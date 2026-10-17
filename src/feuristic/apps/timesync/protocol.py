# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""CDC-ACM time synchronisation protocol, version 1 (spec §3.2, §4; R07).

Normative specification: ``docs/protocols/time-sync-v1.md``. Summary::

    host   -> device : "TIME 1 <unix-seconds>" LF        (set the clock)
    device -> host   : "OK <unix-seconds>" LF  |  "ERR <code>" LF
    host   -> device : "HELLO" LF                         (optional discovery)
    device -> host   : "FEURISTIC TIME 1" LF

* Lines are terminated by LF, CR or CR LF; empty lines are ignored.
* A line holds at most :data:`MAX_LINE` (64) bytes before its terminator;
  a longer line is discarded up to the next terminator and answered with
  ``ERR 6``.
* Tokens are separated by exactly one space; keywords are upper case;
  ``<unix-seconds>`` is 1..20 ASCII digits (no sign); the version is 1..3
  digits and must equal 1.

Error codes (:data:`ERR_SYNTAX` ...):

==== ============================================================
1    syntax error (unknown command, bad token, non-printable byte)
2    unsupported protocol version
3    time out of range (outside 2024-01-01 .. 2100-01-01 UTC)
4    refused on the device (user declined or did not answer)
5    busy (a confirmation is pending) or session already finished
6    line too long
==== ============================================================

Security policy (:meth:`feuristic.core.clock.SessionClock.classify`):
``FIRST_SET`` and ``ACCEPT`` are applied directly; moving the clock back by
more than 60 s (``CONFIRM_BACKWARD``) or forward by more than 300 s
(``CONFIRM_FORWARD``) requires a physical confirmation showing the current
and new UTC times. The time spent on the confirmation screen is added to
the host value before it is applied.

Firmware glue sequence (``Réglages → Heure TOTP → Synchroniser par USB``)::

    usb_set_mode(TIMESYNC)                     # CDC-ACM only (arch. §5.2)
    session = TimeSyncSession(ui)
    loop until session.done or user cancels from the menu or idle timeout:
        data = await read_cdc_packet()         # ≤ 64 bytes
        for resp in await session.feed(data):
            await write_cdc(resp)
    flush, wait ≥ 100 ms                        # let the host read "OK ..."
    usb_set_mode(NORMAL)                        # FIDO HID + CCID again

Reads must continue while a confirmation is displayed so that extra lines
are answered ``ERR 5`` instead of filling the host's buffers.
"""

from micropython import const

from ...core import clock as _clock
from ...core.errors import FeuristicError, InvalidInput
from ...core.i18n import t
from ...core.interaction import SENSITIVE, Prompt
from ...platform import time as _ptime
from . import datetime_fmt
from . import strings as _strings

_strings.register()

VERSION = const(1)
MAX_LINE = const(64)
MAX_SECONDS_DIGITS = const(20)
_MAX_VERSION_DIGITS = const(3)

ERR_SYNTAX = const(1)
ERR_VERSION = const(2)
ERR_RANGE = const(3)
ERR_REFUSED = const(4)
ERR_BUSY = const(5)
ERR_TOO_LONG = const(6)

HELLO = b"HELLO"
HELLO_RESPONSE = b"FEURISTIC TIME 1\n"
_TIME = b"TIME"
_CR = const(0x0D)
_LF = const(0x0A)


def err(code: int) -> bytes:
    """Wire form of an error response."""
    return b"ERR " + str(code).encode() + b"\n"


def ok(unix: int) -> bytes:
    """Wire form of a success response."""
    return b"OK " + str(unix).encode() + b"\n"


class LineAssembler:
    """Turns an arbitrarily chunked byte stream into bounded lines.

    :meth:`feed` returns a list whose items are either a complete,
    non-empty line (``bytes``, terminator removed) or ``None`` for a line
    that exceeded ``max_line`` bytes (to be answered ``ERR 6``). Memory use
    is bounded by ``max_line`` regardless of the input.
    """

    def __init__(self, max_line: int = MAX_LINE) -> None:
        if max_line < 1:
            raise ValueError("max_line")
        self.max_line = max_line
        self._buf = bytearray()
        self._overflow = False

    def reset(self) -> None:
        self._buf = bytearray()
        self._overflow = False

    def pending(self) -> int:
        """Number of buffered bytes of the current (unterminated) line."""
        return len(self._buf)

    def feed(self, data) -> list:
        out = []
        for c in bytes(data):
            if c in (_CR, _LF):
                if self._overflow:
                    out.append(None)
                elif self._buf:
                    out.append(bytes(self._buf))
                self._buf = bytearray()
                self._overflow = False
            elif self._overflow:
                continue
            elif len(self._buf) >= self.max_line:
                self._overflow = True
                self._buf = bytearray()
            else:
                self._buf.append(c)
        return out


def _digits(tok: bytes, max_digits: int) -> bool:
    if not 1 <= len(tok) <= max_digits:
        return False
    return all(48 <= c <= 57 for c in tok)


def _to_int(tok: bytes) -> int:
    v = 0
    for c in tok:
        v = v * 10 + (c - 0x30)
    return v


def parse_line(line):
    """Parse one line. Returns ``("hello", None)``, ``("time", unix)`` or
    ``("err", code)``. Pure function (no clock access)."""
    if line is None:
        return "err", ERR_TOO_LONG
    if len(line) > MAX_LINE:
        return "err", ERR_TOO_LONG
    for c in line:
        if not 0x20 <= c <= 0x7E:
            return "err", ERR_SYNTAX
    if line == HELLO:
        return "hello", None
    toks = bytes(line).split(b" ")
    if toks[0] != _TIME or len(toks) < 2:
        return "err", ERR_SYNTAX
    if not _digits(toks[1], _MAX_VERSION_DIGITS):
        return "err", ERR_SYNTAX
    if _to_int(toks[1]) != VERSION:
        return "err", ERR_VERSION
    if len(toks) != 3:
        return "err", ERR_SYNTAX
    secs = toks[2]
    if len(secs) > MAX_SECONDS_DIGITS:
        for c in secs:
            if not 0x30 <= c <= 0x39:
                return "err", ERR_SYNTAX
        return "err", ERR_RANGE
    if not _digits(secs, MAX_SECONDS_DIGITS):
        return "err", ERR_SYNTAX
    return "time", _to_int(secs)


class TimeSyncSession:
    """One time-sync USB session (a ``TIMESYNC`` mode activation).

    ``ui`` is the injected interaction object; ``clock`` defaults to
    :data:`feuristic.core.clock.CLOCK`. With ``confirm_first=True`` even the
    first setting of the power session is confirmed (default: applied
    directly, as allowed by spec §4).

    After a successful ``TIME`` command :attr:`done` is True and
    :attr:`applied` holds the applied UNIX time; the glue must then return
    USB to the normal mode.
    """

    def __init__(self, ui, clock=None, confirm_first: bool = False) -> None:
        self.ui = ui
        self.clock = _clock.CLOCK if clock is None else clock
        self.confirm_first = confirm_first
        self.assembler = LineAssembler()
        self.busy = False
        self.done = False
        self.applied = None

    async def feed(self, data) -> list:
        """Process a chunk of received bytes; return the responses to send."""
        out = []
        for line in self.assembler.feed(data):
            out.append(await self.handle_line(line))
        return out

    async def handle_line(self, line) -> bytes:
        """Handle one assembled line (``None`` = overflowed line)."""
        kind, value = parse_line(line)
        if kind == "err":
            return err(value)
        if kind == "hello":
            return HELLO_RESPONSE
        if self.busy or self.done:
            return err(ERR_BUSY)
        return await self._set_time(value)

    def _prompt(self, cls: int, current, new: int) -> Prompt:
        if cls == _clock.CONFIRM_BACKWARD:
            title = "timesync.confirm_backward.title"
        elif cls == _clock.CONFIRM_FORWARD:
            title = "timesync.confirm_forward.title"
        else:
            title = "timesync.confirm_first.title"
        if current is None:
            fields = [
                ("timesync.field.current", t("timesync.not_set")),
                ("timesync.field.new", datetime_fmt.format_utc(new)),
            ]
        else:
            fields = [
                ("timesync.field.current", datetime_fmt.format_utc(current)),
                ("timesync.field.new", datetime_fmt.format_utc(new)),
                ("timesync.field.delta", datetime_fmt.format_delta(new - current)),
            ]
        return Prompt("timesync.confirm", title, fields, SENSITIVE)

    async def _set_time(self, unix: int) -> bytes:
        try:
            cls = self.clock.classify(unix)
        except InvalidInput:
            return err(ERR_RANGE)
        needs_confirm = cls in (_clock.CONFIRM_BACKWARD, _clock.CONFIRM_FORWARD) or (
            cls == _clock.FIRST_SET and self.confirm_first
        )
        if needs_confirm:
            received = _ptime.ticks_ms()
            prompt = self._prompt(cls, self.clock.now(), unix)
            self.busy = True
            try:
                confirmed = await self.ui.confirm(prompt)
            except FeuristicError:  # timeout / cancellation reported as an error
                confirmed = False
            finally:
                self.busy = False
            if not confirmed:
                return err(ERR_REFUSED)
            if self.done:  # pragma: no cover - only reachable through re-entrancy
                return err(ERR_BUSY)
            # account for the time spent on the confirmation screen
            elapsed = _ptime.ticks_diff(_ptime.ticks_ms(), received)
            if elapsed > 0:
                unix += elapsed // 1000
        try:
            self.clock.set(unix)
        except InvalidInput:
            return err(ERR_RANGE)
        self.done = True
        self.applied = unix
        return ok(unix)
