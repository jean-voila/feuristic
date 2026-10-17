# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""CTAPHID transport (CTAP 2.1 §11.2) as a pure state machine + async adapter.

:class:`CtapHid` consumes and produces 64-byte HID reports and never
blocks. It implements:

* framing (§11.2.4): initialization packets (CID, CMD|0x80, BCNT, 57 data
  bytes) and continuation packets (CID, SEQ 0..127, 59 data bytes); messages
  up to :data:`MAX_MESSAGE` = 57 + 128·59 = 7609 bytes assembled into one
  pre-allocated buffer;
* channels (§11.2.3): CTAPHID_INIT on the broadcast CID 0xFFFFFFFF allocates
  a random CID (never 0 or 0xFFFFFFFF); up to :data:`MAX_CHANNELS` channels
  are remembered (least recently used evicted); commands on CID 0, on the
  broadcast CID (other than INIT) or on an unknown CID get
  ERR_INVALID_CHANNEL; INIT on an allocated CID resynchronises it (aborts
  any transaction on it);
* transactions (§11.2.5): one at a time. While a message is being assembled
  or processed, initialization packets of other channels get
  ERR_CHANNEL_BUSY, spurious continuation packets are ignored, a wrong
  sequence number gets ERR_INVALID_SEQ, a gap of more than
  :data:`CONT_TIMEOUT_MS` between packets gets ERR_MSG_TIMEOUT;
* commands (§11.2.9): PING (echo), INIT, WINK (only if a wink hook is
  enabled; advertised in the capability flags only then), MSG and CBOR
  (handed to the application), CANCEL (marks the running CBOR transaction
  cancelled; ignored otherwise, never answered), KEEPALIVE emitted every
  :data:`KEEPALIVE_INTERVAL_MS` while a CBOR request is processed, with the
  status chosen by the application (PROCESSING / UPNEEDED). LOCK is not
  implemented (ERR_INVALID_CMD, not advertised). NMSG is not advertised:
  U2F (CTAPHID_MSG) is supported.

Firmware glue contract (see also :class:`HidServer`)::

    server = HidServer(CtapHid(wink=True), Fido2App(ctx))
    while True:
        pkt = await read_hid_report(timeout_ms=20)     # USB HID or emulator UDP
        now = ticks_ms()
        if pkt is not None:
            server.feed(pkt, now)
        server.poll(now)                               # timeouts + keepalives
        for out in server.packets():
            write_hid_report(out)
        job = server.next_job()                        # request or U2F dialog
        if job is not None:
            spawn(job)                                 # runs concurrently
        if server.take_wink():
            flash_screen()

The interaction object of the FIDO2 context must abort a pending dialog
(return ``False`` or raise ``UserCancelled``) once
``server.cancel_requested()`` becomes true, so that CTAPHID_CANCEL during a
user-presence wait yields CTAP2_ERR_KEEPALIVE_CANCEL.
"""

from micropython import const

from ...platform import crypto, log
from ...platform import time as ptime
from .context import STATUS_PROCESSING
from .status import (
    CTAP1_ERR_CHANNEL_BUSY,
    CTAP1_ERR_INVALID_CHANNEL,
    CTAP1_ERR_INVALID_COMMAND,
    CTAP1_ERR_INVALID_LENGTH,
    CTAP1_ERR_INVALID_SEQ,
    CTAP1_ERR_OTHER,
    CTAP1_ERR_TIMEOUT,
)

PACKET_SIZE = const(64)
INIT_DATA = const(57)
CONT_DATA = const(59)
MAX_MESSAGE = const(7609)
CID_BROADCAST = 0xFFFFFFFF

CMD_PING = const(0x01)
CMD_MSG = const(0x03)
CMD_LOCK = const(0x04)
CMD_INIT = const(0x06)
CMD_WINK = const(0x08)
CMD_CBOR = const(0x10)
CMD_CANCEL = const(0x11)
CMD_KEEPALIVE = const(0x3B)
CMD_ERROR = const(0x3F)

CAP_WINK = const(0x01)
CAP_LOCK = const(0x02)
CAP_CBOR = const(0x04)
CAP_NMSG = const(0x08)

HID_PROTOCOL_VERSION = const(2)
CONT_TIMEOUT_MS = const(500)
KEEPALIVE_INTERVAL_MS = const(100)
MAX_CHANNELS = const(16)
INIT_NONCE_LEN = const(8)


class Transaction:
    """A complete request handed to the application (implements the
    :class:`~.context.Channel` interface)."""

    def __init__(self, cid: int, cmd: int, payload: bytes) -> None:
        self.cid = cid
        self.cmd = cmd
        self.payload = payload
        self.cancelled = False  # CTAPHID_CANCEL received for this request
        self.aborted = False  # channel resynchronised: response is dropped
        self.status = STATUS_PROCESSING

    def set_status(self, status: int) -> None:
        self.status = status


class CtapHid:
    def __init__(self, version=(0, 1, 0), wink: bool = False, max_channels: int = MAX_CHANNELS) -> None:
        self.version = version
        self.wink_enabled = wink
        self.max_channels = max_channels
        self._buf = bytearray(MAX_MESSAGE)
        self._out = []
        self._channels = []
        self._a_cid = None
        self._a_cmd = 0
        self._a_len = 0
        self._a_got = 0
        self._a_seq = 0
        self._a_last = 0
        self._ready = None
        self._txn = None
        self._last_ka = 0
        self.wink_requested = False

    # -- public API ------------------------------------------------------------
    @property
    def capabilities(self) -> int:
        return CAP_CBOR | (CAP_WINK if self.wink_enabled else 0)

    def busy(self) -> bool:
        return self._a_cid is not None or self._ready is not None or self._txn is not None

    def current(self):
        """The transaction being processed (or waiting to be taken)."""
        return self._txn if self._txn is not None else self._ready

    def pop_packets(self) -> list:
        out = self._out
        self._out = []
        return out

    def take_request(self):
        """Return the next complete MSG/CBOR request (now "processing")."""
        txn = self._ready
        if txn is not None:
            self._ready = None
            self._txn = txn
        return txn

    def complete(self, txn: Transaction, cmd: int, payload: bytes) -> None:
        """Send the application's response to ``txn`` (dropped if stale)."""
        if txn is not self._txn:
            return
        self._txn = None
        if txn.aborted:
            return
        if len(payload) > MAX_MESSAGE:
            self._error(txn.cid, CTAP1_ERR_OTHER)
            return
        self._send(txn.cid, cmd, payload)

    def handle_packet(self, packet, now: int) -> None:
        """Process one HID OUT report (shorter reports are zero padded)."""
        n = len(packet)
        if n > PACKET_SIZE or n < 5:
            return
        p = bytes(packet) + bytes(PACKET_SIZE - n)
        self.poll(now)
        cid = int.from_bytes(p[0:4], "big")
        if p[4] & 0x80:
            self._on_init_packet(cid, p[4] & 0x7F, (p[5] << 8) | p[6], p, now)
        else:
            self._on_cont_packet(cid, p[4], p, now)

    def poll(self, now: int) -> None:
        """Handle the continuation timeout and emit keepalives."""
        if self._a_cid is not None and ptime.ticks_diff(now, self._a_last) >= CONT_TIMEOUT_MS:
            cid = self._a_cid
            self._a_cid = None
            self._error(cid, CTAP1_ERR_TIMEOUT)
        txn = self._txn
        if (
            txn is not None
            and txn.cmd == CMD_CBOR
            and not txn.aborted
            and ptime.ticks_diff(now, self._last_ka) >= KEEPALIVE_INTERVAL_MS
        ):
            self._last_ka = now
            self._send(txn.cid, CMD_KEEPALIVE, bytes((txn.status,)))

    # -- packet handling ---------------------------------------------------------
    def _on_init_packet(self, cid: int, cmd: int, bcnt: int, p: bytes, now: int) -> None:
        if cmd == CMD_INIT:
            self._on_init(cid, bcnt, p)
            return
        if cid in (0, CID_BROADCAST) or cid not in self._channels:
            self._error(cid, CTAP1_ERR_INVALID_CHANNEL)
            return
        if self._a_cid is not None:
            if cid == self._a_cid:
                self._a_cid = None
                if cmd != CMD_CANCEL:
                    self._error(cid, CTAP1_ERR_INVALID_SEQ)
            elif cmd != CMD_CANCEL:
                self._error(cid, CTAP1_ERR_CHANNEL_BUSY)
            return
        busy = self.current()
        if busy is not None:
            if cmd == CMD_CANCEL:
                if cid == busy.cid:
                    busy.cancelled = True
            else:
                self._error(cid, CTAP1_ERR_CHANNEL_BUSY)
            return
        if cmd == CMD_CANCEL:
            return  # nothing to cancel: ignored (§11.2.9.1.5)
        if bcnt > MAX_MESSAGE:
            self._error(cid, CTAP1_ERR_INVALID_LENGTH)
            return
        self._touch(cid)
        if bcnt <= INIT_DATA:
            self._dispatch(cid, cmd, p[7 : 7 + bcnt], now)
            return
        self._buf[0:INIT_DATA] = p[7:PACKET_SIZE]
        self._a_cid = cid
        self._a_cmd = cmd
        self._a_len = bcnt
        self._a_got = INIT_DATA
        self._a_seq = 0
        self._a_last = now

    def _on_cont_packet(self, cid: int, seq: int, p: bytes, now: int) -> None:
        if self._a_cid is None or cid != self._a_cid:
            return  # spurious continuation: ignored
        if seq != self._a_seq:
            self._a_cid = None
            self._error(cid, CTAP1_ERR_INVALID_SEQ)
            return
        n = min(CONT_DATA, self._a_len - self._a_got)
        self._buf[self._a_got : self._a_got + n] = p[5 : 5 + n]
        self._a_got += n
        self._a_seq += 1
        self._a_last = now
        if self._a_got >= self._a_len:
            self._a_cid = None
            self._dispatch(cid, self._a_cmd, bytes(self._buf[: self._a_len]), now)

    def _on_init(self, cid: int, bcnt: int, p: bytes) -> None:
        if cid == 0:
            self._error(cid, CTAP1_ERR_INVALID_CHANNEL)
            return
        if bcnt != INIT_NONCE_LEN:
            self._error(cid, CTAP1_ERR_INVALID_LENGTH)
            return
        if cid == CID_BROADCAST:
            new_cid = self._allocate()
        else:
            if cid not in self._channels:
                self._error(cid, CTAP1_ERR_INVALID_CHANNEL)
                return
            new_cid = cid
            self._touch(cid)
            # resynchronise: abort whatever was going on for this channel
            if self._a_cid == cid:
                self._a_cid = None
            cur = self.current()
            if cur is not None and cur.cid == cid:
                cur.aborted = True
                cur.cancelled = True
                if cur is self._ready:
                    self._ready = None
        maj, minor, build = self.version
        self._send(
            cid,
            CMD_INIT,
            p[7:15]
            + new_cid.to_bytes(4, "big")
            + bytes((HID_PROTOCOL_VERSION, maj & 0xFF, minor & 0xFF, build & 0xFF, self.capabilities)),
        )

    def _dispatch(self, cid: int, cmd: int, payload: bytes, now: int) -> None:
        if cmd == CMD_PING:
            self._send(cid, CMD_PING, payload)
        elif cmd == CMD_WINK and self.wink_enabled:
            if payload:
                self._error(cid, CTAP1_ERR_INVALID_LENGTH)
            else:
                self.wink_requested = True
                self._send(cid, CMD_WINK, b"")
        elif cmd in (CMD_MSG, CMD_CBOR):
            if cmd == CMD_CBOR and not payload:
                self._error(cid, CTAP1_ERR_INVALID_LENGTH)
                return
            self._ready = Transaction(cid, cmd, payload)
            self._last_ka = now
        else:
            # LOCK (not implemented), KEEPALIVE/ERROR from the host, vendor
            self._error(cid, CTAP1_ERR_INVALID_COMMAND)

    # -- channels ----------------------------------------------------------------
    def _touch(self, cid: int) -> None:
        if cid in self._channels:
            self._channels.remove(cid)
        self._channels.append(cid)

    def _allocate(self) -> int:
        while True:
            cid = int.from_bytes(crypto.random_bytes(4, False), "big")
            if cid not in (0, CID_BROADCAST) and cid not in self._channels:
                break
        busy = self.current()
        busy_cid = busy.cid if busy is not None else self._a_cid
        while len(self._channels) >= self.max_channels:
            victim = self._channels[0]
            if victim == busy_cid and len(self._channels) > 1:
                victim = self._channels[1]
            self._channels.remove(victim)
        self._channels.append(cid)
        return cid

    # -- output ------------------------------------------------------------------
    def _error(self, cid: int, code: int) -> None:
        log.debug(__name__, "CTAPHID error 0x%02x on cid %08x", code, cid)
        self._send(cid, CMD_ERROR, bytes((code,)))

    def _send(self, cid: int, cmd: int, payload: bytes) -> None:
        n = len(payload)
        head = cid.to_bytes(4, "big")
        first = head + bytes((cmd | 0x80, n >> 8, n & 0xFF)) + payload[:INIT_DATA]
        self._out.append(first + bytes(PACKET_SIZE - len(first)))
        off = INIT_DATA
        seq = 0
        while off < n:
            chunk = head + bytes((seq,)) + payload[off : off + CONT_DATA]
            self._out.append(chunk + bytes(PACKET_SIZE - len(chunk)))
            off += CONT_DATA
            seq += 1


class HidServer:
    """Async adapter binding a :class:`CtapHid` to the application.

    ``app`` provides ``async handle(txn) -> (cmd, payload)`` and
    ``background_job()`` (coroutine or ``None``), see :class:`~.app.Fido2App`.
    """

    def __init__(self, hid: CtapHid, app) -> None:
        self.hid = hid
        self.app = app

    def feed(self, packet, now: int) -> None:
        self.hid.handle_packet(packet, now)

    def poll(self, now: int) -> None:
        self.hid.poll(now)

    def packets(self) -> list:
        return self.hid.pop_packets()

    def cancel_requested(self) -> bool:
        cur = self.hid.current()
        return cur is not None and cur.cancelled

    def take_wink(self) -> bool:
        w = self.hid.wink_requested
        self.hid.wink_requested = False
        return w

    def next_job(self):
        txn = self.hid.take_request()
        if txn is not None:
            return self._process(txn)
        return self.app.background_job()

    async def _process(self, txn: Transaction) -> None:
        try:
            cmd, payload = await self.app.handle(txn)
        except Exception as e:  # pragma: no cover - app.handle never raises
            log.warning(__name__, "request failed: %s", repr(e))
            cmd, payload = CMD_ERROR, bytes((CTAP1_ERR_OTHER,))
        self.hid.complete(txn, cmd, payload)
