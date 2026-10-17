# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Monotonic time facade (milliseconds since power-up)."""

from . import _backend

if _backend.FIRMWARE:
    import utime as _utime

    def ticks_ms() -> int:
        return _utime.ticks_ms()

    def ticks_diff(a: int, b: int) -> int:
        return _utime.ticks_diff(a, b)

else:
    from . import testing as _testing

    def ticks_ms() -> int:
        return _testing.CLOCK.now_ms()

    def ticks_diff(a: int, b: int) -> int:
        return a - b
