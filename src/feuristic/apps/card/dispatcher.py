# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""The virtual multi-application smart card (ISO/IEC 7816-4).

The dispatcher receives command APDUs (bytes) from the CCID layer and
returns response APDUs (data || SW1 SW2). It implements the card-level
parts of ISO/IEC 7816-4 so that the applets only see complete commands:

* **class byte** (§5.4.1): first interindustry values ``0x00–0x1F`` and the
  proprietary range ``0x80–0xFE`` (same bit coding, as used by
  GlobalPlatform) are accepted on the basic logical channel without secure
  messaging. A non-zero logical channel (``b2-b1``, or any further
  interindustry class ``0x40–0x7F``) gives ``6881``; secure messaging
  indication (``b4-b3``) gives ``6882``; ``0x20–0x3F`` (RFU) gives ``6E00``.
* **application selection** (§11.2.2): ``SELECT`` with ``P1=04`` (DF name),
  ``P2=00`` (FCI) / ``04`` (FCP) / ``0C`` (no response data). The first
  registered applet whose :meth:`~feuristic.apps.card.applet.Applet.matches`
  accepts the (possibly partial) AID is selected; the previously selected
  applet is deselected (verified PINs dropped). Re-selecting the current
  applet does **not** deselect it (GnuPG re-selects OpenPGP frequently).
  An unknown AID answers ``6A82`` and keeps the current selection. Other
  selection methods (``P1`` ≠ ``04``: the card has no MF/file system)
  answer ``6A82``.
* **nothing selected**: commands other than SELECT are routed to the optional
  ``fallback`` applet (e.g. the card-level ``GET CHALLENGE`` of the AES/RNG
  profile, spec F06/R11), otherwise ``6D00``.
* **command chaining** (§5.1.1.1, CLA ``b5``): parts are concatenated
  (bounded by :data:`~feuristic.apps.card.apdu.MAX_COMMAND_DATA`, else
  ``6700``); a part whose INS/P1/P2/CLA differ from the chain aborts the
  chain with ``6883``.
* **response chaining**: when the response data exceeds ``Ne``, the first
  ``Ne`` bytes are returned with ``61xx`` (``xx`` = remaining, ``00`` for
  256 or more) and the rest is fetched with ``GET RESPONSE`` (``INS C0``).
  Extended APDUs get up to ``Ne`` = 65536 bytes directly. An absent ``Le``
  is treated as ``Ne`` = 256 (short) / 65536 (extended).
* **card reset** (power on/off): every applet's :meth:`reset` is called and
  the selection, chains and pending response are dropped.

Applets raise :class:`~feuristic.apps.card.apdu.ApduError` to answer a
specific status word. Typed feuristic errors are mapped (``InvalidInput`` →
``6A80``, ``UserCancelled``/``UserTimeout`` → ``6985``, ``StorageFull`` →
``6A84``, ``PinBlocked`` → ``6983``); any other exception gives ``6F00``
(never propagated to the USB loop, logged in debug builds).
"""

from micropython import const

from ...core.errors import (
    InvalidInput,
    PinBlocked,
    StorageFull,
    UserCancelled,
    UserTimeout,
)
from ...platform import log
from . import apdu as _apdu

INS_SELECT = const(0xA4)
INS_GET_RESPONSE = const(0xC0)

#: ISO/IEC 7816-4: an application identifier is 5..16 bytes; we accept
#: partial AIDs down to 1 byte (applets decide via ``matches``)
MAX_AID_LEN = const(16)


def _sw(sw: int) -> bytes:
    return bytes(((sw >> 8) & 0xFF, sw & 0xFF))


class Dispatcher:
    def __init__(self, applets, fallback=None) -> None:
        self.applets = list(applets)
        self.fallback = fallback
        #: re-raise unexpected exceptions instead of answering 6F00 (tests)
        self.raise_unexpected = False
        self.selected = None
        self._chain = None  # (cla, ins, p1, p2, bytearray)
        self._rsp = None  # (remaining bytes, final sw)

    # -- lifecycle -------------------------------------------------------------
    def reset(self) -> None:
        """Card reset: drop all volatile state and reset every applet."""
        self.selected = None
        self._chain = None
        self._rsp = None
        for a in self.applets:
            a.reset()
        if self.fallback is not None and self.fallback not in self.applets:
            self.fallback.reset()

    # -- main entry ------------------------------------------------------------
    async def transmit(self, raw) -> bytes:
        """Process one command APDU; return the response APDU."""
        raw = bytes(raw)
        if len(raw) >= 1 and raw[0] == 0xFF:
            self._chain = None
            self._rsp = None
            return _sw(_apdu.SW_CLA_NOT_SUPPORTED)
        try:
            cmd = _apdu.parse(raw)
        except InvalidInput:
            self._chain = None
            self._rsp = None
            return _sw(_apdu.SW_WRONG_LENGTH)
        sw = self._check_cla(cmd.cla)
        if sw:
            self._chain = None
            self._rsp = None
            return _sw(sw)

        # GET RESPONSE continues a pending response (unless chaining)
        if cmd.ins == INS_GET_RESPONSE and self._chain is None:
            return self._get_response(cmd)
        self._rsp = None

        # command chaining
        if self._chain is not None:
            ccla, cins, cp1, cp2, buf = self._chain
            if (cmd.cla & ~0x10) != ccla or cmd.ins != cins or cmd.p1 != cp1 or cmd.p2 != cp2:
                self._chain = None
                return _sw(_apdu.SW_LAST_COMMAND_OF_CHAIN_EXPECTED)
            if len(buf) + len(cmd.data) > _apdu.MAX_COMMAND_DATA:
                self._chain = None
                return _sw(_apdu.SW_WRONG_LENGTH)
            buf.extend(cmd.data)
            if cmd.chained:
                return _sw(_apdu.SW_OK)
            self._chain = None
            cmd = _apdu.Command(ccla, cins, cp1, cp2, bytes(buf), cmd.ne, cmd.extended)
        elif cmd.chained:
            if len(cmd.data) > _apdu.MAX_COMMAND_DATA:
                return _sw(_apdu.SW_WRONG_LENGTH)
            self._chain = (cmd.cla & ~0x10, cmd.ins, cmd.p1, cmd.p2, bytearray(cmd.data))
            return _sw(_apdu.SW_OK)
        elif len(cmd.data) > _apdu.MAX_COMMAND_DATA:
            return _sw(_apdu.SW_WRONG_LENGTH)

        if cmd.ins == INS_SELECT:
            resp = await self._select(cmd)
        else:
            # Card-level public RNG stays available after a PC/SC client
            # auto-selects OpenPGP or PIV (e.g. opensc-tool before -s).
            target = self.fallback if cmd.ins == 0x84 and self.fallback is not None else self.selected
            if target is None:
                target = self.fallback
            if target is None:
                return _sw(_apdu.SW_INS_NOT_SUPPORTED)
            resp = await self._call(target.process, cmd)
        return self._respond(cmd, resp)

    # -- helpers ---------------------------------------------------------------
    @staticmethod
    def _check_cla(cla: int) -> int:
        if 0x40 <= cla <= 0x7F:
            return _apdu.SW_LOGICAL_CHANNEL_NOT_SUPPORTED  # channels 4..19
        if 0x20 <= cla <= 0x3F:
            return _apdu.SW_CLA_NOT_SUPPORTED
        if cla & 0x03:
            return _apdu.SW_LOGICAL_CHANNEL_NOT_SUPPORTED
        if cla & 0x0C:
            return _apdu.SW_SECURE_MESSAGING_NOT_SUPPORTED
        return 0

    async def _call(self, fn, cmd):
        try:
            resp = await fn(cmd)
        except _apdu.ApduError as e:
            return _apdu.Response(b"", e.sw)
        except (UserCancelled, UserTimeout):
            return _apdu.Response(b"", _apdu.SW_CONDITIONS_NOT_SATISFIED)
        except PinBlocked:
            return _apdu.Response(b"", _apdu.SW_AUTH_METHOD_BLOCKED)
        except StorageFull:
            return _apdu.Response(b"", _apdu.SW_NOT_ENOUGH_MEMORY)
        except InvalidInput:
            return _apdu.Response(b"", _apdu.SW_WRONG_DATA)
        except Exception as e:  # never let an applet bug kill the USB loop
            if self.raise_unexpected:
                raise
            log.warning("card", "applet exception %s", type(e).__name__)
            return _apdu.Response(b"", _apdu.SW_UNKNOWN)
        if resp is None:
            return _apdu.Response(b"", _apdu.SW_OK)
        return resp

    async def _select(self, cmd):
        if cmd.p1 != 0x04:
            return _apdu.Response(b"", _apdu.SW_FILE_NOT_FOUND)
        if cmd.p2 not in (0x00, 0x04, 0x0C):
            return _apdu.Response(b"", _apdu.SW_INCORRECT_P1P2)
        aid = cmd.data
        if not aid or len(aid) > MAX_AID_LEN:
            return _apdu.Response(b"", _apdu.SW_WRONG_LENGTH)
        target = None
        for a in self.applets:
            if a.matches(aid):
                target = a
                break
        if target is None:
            return _apdu.Response(b"", _apdu.SW_FILE_NOT_FOUND)
        previous = self.selected
        if previous is not None and previous is not target:
            previous.deselect()
            self.selected = None
        resp = await self._call(target.select, cmd)
        sw = resp.sw
        # selected unless the SELECT failed (warnings 62xx/63xx keep it,
        # e.g. 6285 = OpenPGP application in termination state)
        if sw == _apdu.SW_OK or (sw >> 8) in (0x61, 0x62, 0x63):
            self.selected = target
        elif previous is target:
            self.selected = None
            target.deselect()
        if cmd.p2 == 0x0C:
            resp = _apdu.Response(b"", sw)
        return resp

    def _respond(self, cmd, resp) -> bytes:
        data = bytes(resp.data)
        sw = resp.sw
        ne = cmd.ne
        if ne == 0:
            ne = _apdu.MAX_EXTENDED_NE if cmd.extended else _apdu.MAX_SHORT_NE
        if len(data) <= ne:
            return data + _sw(sw)
        head = data[:ne]
        rest = data[ne:]
        self._rsp = (rest, sw)
        return head + _sw(_apdu.SW_BYTES_REMAINING | (min(len(rest), 256) & 0xFF))

    def _get_response(self, cmd) -> bytes:
        pending = self._rsp
        self._rsp = None
        if cmd.data:
            return _sw(_apdu.SW_WRONG_LENGTH)
        if cmd.p1 != 0 or cmd.p2 != 0:
            return _sw(_apdu.SW_INCORRECT_P1P2)
        if pending is None:
            return _sw(_apdu.SW_CONDITIONS_NOT_SATISFIED)
        rest, sw = pending
        ne = cmd.ne or (_apdu.MAX_EXTENDED_NE if cmd.extended else _apdu.MAX_SHORT_NE)
        chunk = rest[:ne]
        rest = rest[ne:]
        if rest:
            self._rsp = (rest, sw)
            return chunk + _sw(_apdu.SW_BYTES_REMAINING | (min(len(rest), 256) & 0xFF))
        return chunk + _sw(sw)
