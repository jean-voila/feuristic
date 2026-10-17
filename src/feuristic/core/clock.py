# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Session wall clock for TOTP (spec §4).

The Safe 3 has no battery-backed RTC. The host provides UNIX time through
the CDC-ACM time-sync mode; the clock then runs from the monotonic tick
counter for as long as the device stays powered. After power loss the clock
is unset and TOTP shows "time to synchronise" instead of a wrong code.

Rules implemented here (pure logic; UI confirmation is the caller's job):

* setting a time more than :data:`BACKWARD_TOLERANCE_S` *earlier* than the
  current session time requires a physical confirmation;
* a jump forward of more than :data:`FORWARD_WARN_S` is reported so that the
  UI shows it before accepting;
* values outside ``[MIN_UNIX, MAX_UNIX]`` are rejected.
"""

from micropython import const

from ..platform import time as ptime
from .errors import InvalidInput

MIN_UNIX = const(1_704_067_200)  # 2024-01-01T00:00:00Z
MAX_UNIX = 4_102_444_800  # 2100-01-01T00:00:00Z
BACKWARD_TOLERANCE_S = const(60)
FORWARD_WARN_S = const(300)

# classification returned by SessionClock.classify()
ACCEPT = const(0)  # can be applied directly
CONFIRM_BACKWARD = const(1)  # moves back by more than 60 s: confirmation required
CONFIRM_FORWARD = const(2)  # large forward jump: show before accepting
FIRST_SET = const(3)  # clock not set yet in this power session


class SessionClock:
    def __init__(self) -> None:
        self._base_unix = None  # UNIX seconds at _base_ticks
        self._base_ticks = 0

    def is_set(self) -> bool:
        return self._base_unix is not None

    def now(self):
        """Current UNIX time in seconds, or ``None`` if not synchronised."""
        if self._base_unix is None:
            return None
        elapsed_ms = ptime.ticks_diff(ptime.ticks_ms(), self._base_ticks)
        return self._base_unix + elapsed_ms // 1000

    @staticmethod
    def validate(unix: int) -> None:
        if not isinstance(unix, int) or unix < MIN_UNIX or unix > MAX_UNIX:
            raise InvalidInput("time out of range")

    def classify(self, unix: int) -> int:
        self.validate(unix)
        current = self.now()
        if current is None:
            return FIRST_SET
        if unix < current - BACKWARD_TOLERANCE_S:
            return CONFIRM_BACKWARD
        if unix > current + FORWARD_WARN_S:
            return CONFIRM_FORWARD
        return ACCEPT

    def set(self, unix: int) -> None:  # noqa: A003
        """Apply ``unix`` (caller must have obtained any required confirmation)."""
        self.validate(unix)
        self._base_unix = unix
        self._base_ticks = ptime.ticks_ms()

    def clear(self) -> None:
        self._base_unix = None


# the single session clock of the running firmware
CLOCK = SessionClock()
