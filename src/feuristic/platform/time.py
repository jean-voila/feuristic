# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Unwrapped monotonic milliseconds, sampled at least once per minute.

MicroPython's 32-bit target ticks wrap every 2**30 milliseconds and its
ticks_diff is only valid over half that period. Extending at each sample
keeps old timestamps (PIN token expiry, TOTP base, power-up) meaningful for
the whole power session. The firmware's independent heartbeat samples this
facade even while locked or in an exclusive USB mode.
"""

from . import _backend


class MonotonicError(RuntimeError):
    """The native sampling interval became ambiguous; reboot is required."""


class _ExtendedTicks:
    def __init__(self, read, difference):
        self._read = read
        self._difference = difference
        self._last = None
        self._elapsed = 0
        self._failed = False

    def now(self):
        if self._failed:
            raise MonotonicError("monotonic clock unavailable")
        current = self._read()
        if self._last is None:
            self._elapsed = current
        else:
            delta = self._difference(current, self._last)
            if delta < 0:
                # Never let an expired PIN token or presence latch become
                # young again, nor silently display a code for the wrong time.
                self._failed = True
                raise MonotonicError("monotonic clock sampling interval missed")
            self._elapsed += delta
        self._last = current
        return self._elapsed


if _backend.FIRMWARE:
    import utime as _utime

    _ticks = _ExtendedTicks(_utime.ticks_ms, _utime.ticks_diff)

    def ticks_ms() -> int:
        return _ticks.now()

    def ticks_diff(a: int, b: int) -> int:
        return a - b

else:
    from . import testing as _testing

    def ticks_ms() -> int:
        return _testing.CLOCK.now_ms()

    def ticks_diff(a: int, b: int) -> int:
        return a - b
