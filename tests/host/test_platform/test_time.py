# SPDX-License-Identifier: GPL-3.0-only
"""32-bit tick periods must not shorten a powered wall-clock session."""

import pytest

from feuristic.core.clock import ACCEPT, CONFIRM_BACKWARD, SessionClock
from feuristic.platform import time as ptime

PERIOD = 1 << 30


class Native32:
    def __init__(self, elapsed=0):
        self.elapsed = elapsed

    def read(self):
        return self.elapsed % PERIOD

    @staticmethod
    def diff(end, start):
        return ((end - start + PERIOD // 2) % PERIOD) - PERIOD // 2


def test_wrapping_ticks_keep_totp_and_backward_policy_for_many_powered_days(monkeypatch):
    raw = Native32(PERIOD - 1234)
    extended = ptime._ExtendedTicks(raw.read, raw.diff)
    monkeypatch.setattr(ptime, "ticks_ms", extended.now)
    clock = SessionClock()
    clock.set(1_800_000_000)
    # Heartbeat sampling, without a wall-clock read for 40 days. This crosses
    # both the first half-period (old bug) and multiple complete MCU wraps.
    for _ in range(40 * 24 * 60):
        raw.elapsed += 60_000
        ptime.ticks_ms()
    assert clock.now() == 1_800_000_000 + 40 * 86400
    current = clock.now()
    assert clock.classify(current - 60) == ACCEPT
    assert clock.classify(current - 61) == CONFIRM_BACKWARD
    clock.set(current - 61)
    raw.elapsed += 1234
    assert clock.now() == current - 60
    raw.elapsed += 766
    assert clock.now() == current - 59


def test_missed_sampling_latches_failure_and_invalidates_wall_time(monkeypatch):
    raw = Native32()
    extended = ptime._ExtendedTicks(raw.read, raw.diff)
    monkeypatch.setattr(ptime, "ticks_ms", extended.now)
    clock = SessionClock()
    clock.set(1_800_000_000)
    raw.elapsed += PERIOD // 2
    assert clock.now() is None and not clock.is_set()
    raw.elapsed += PERIOD
    with pytest.raises(ptime.MonotonicError):
        ptime.ticks_ms()
    with pytest.raises(ptime.MonotonicError):
        clock.set(1_800_000_000)
