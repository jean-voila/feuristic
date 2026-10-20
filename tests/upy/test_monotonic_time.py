# SPDX-License-Identifier: GPL-3.0-only
"""Native app/crypto expiry after simulated 40-day, multi-wrap MCU uptime."""

from upytest import raises, run, storage_setup, test

from feuristic.apps.fido2 import ctap1
from feuristic.apps.fido2.context import NULL_CHANNEL, Context
from feuristic.apps.fido2.ctap2 import Authenticator
from feuristic.apps.fido2.status import CTAP2_ERR_NOT_ALLOWED, CtapError
from feuristic.apps.otp import totp
from feuristic.core.clock import ACCEPT, CONFIRM_BACKWARD, SessionClock
from feuristic.core.interaction import Prompt, ScriptedInteraction
from feuristic.platform import time as ptime

PERIOD = 1 << 30


class Native32:
    def __init__(self):
        self.elapsed = PERIOD - 1234

    def read(self):
        return self.elapsed % PERIOD

    @staticmethod
    def diff(end, start):
        return ((end - start + PERIOD // 2) % PERIOD) - PERIOD // 2


def drive(coro):
    try:
        while True:
            coro.send(None)
    except StopIteration as exc:
        return exc.value


def not_allowed(fn, *args):
    try:
        fn(*args)
    except CtapError as exc:
        assert exc.code == CTAP2_ERR_NOT_ALLOWED
    else:
        raise AssertionError("expired operation accepted")


@test
def wall_clock_and_security_expiry_survive_long_idle_and_repeated_wraps():
    raw = Native32()
    extended = ptime._ExtendedTicks(raw.read, raw.diff)
    original = ptime.ticks_ms
    ptime.ticks_ms = extended.now
    try:
        start = ptime.ticks_ms()
        clock = SessionClock()
        clock.set(1_800_000_000)
        ctx = Context(b"m" * 32, ScriptedInteraction())
        auth = Authenticator(ctx)
        auth.pin._begin_using(1, True)
        auth._ga = {"t": start, "uids": []}
        u2f = ctap1.U2f(auth)
        prompt = Prompt("presence", "presence")
        u2f._presence(b"request", prompt)
        drive(u2f.dialog_job())
        for _ in range(40 * 24):
            # Coarsen the simulation to hourly samples (still far below the
            # MCU half-period); the actual heartbeat samples every minute.
            raw.elapsed += 3_600_000
            ptime.ticks_ms()
        elapsed = 40 * 86400
        assert clock.now() == 1_800_000_000 + elapsed
        secret = b"12345678901234567890"
        assert totp.totp_now(secret, clock=clock) == totp.totp_at(secret, 1_800_000_000 + elapsed)
        assert ctx.ms_since_power_up() == elapsed * 1000
        assert not auth.pin.token_in_use()
        not_allowed(auth.get_next_assertion)
        assert auth._ga is None
        not_allowed(drive, auth.reset(NULL_CHANNEL))
        u2f._presence(b"request", prompt)
        assert u2f.dialog_pending()
        assert clock.classify(clock.now() - 60) == ACCEPT
        assert clock.classify(clock.now() - 61) == CONFIRM_BACKWARD
        clock.set(clock.now() - 61)
        raw.elapsed += 1500
        assert clock.now() == 1_800_000_000 + elapsed - 60
    finally:
        ptime.ticks_ms = original


@test
def ambiguous_native_elapsed_never_silently_recovers_or_shows_totp():
    raw = Native32()
    extended = ptime._ExtendedTicks(raw.read, raw.diff)
    original = ptime.ticks_ms
    ptime.ticks_ms = extended.now
    try:
        clock = SessionClock()
        clock.set(1_800_000_000)
        raw.elapsed += PERIOD // 2
        assert clock.now() is None
        raises(totp.TimeNotSynchronised, totp.totp_now, b"12345678901234567890", 30, 6, "SHA1", clock)
        raw.elapsed += PERIOD
        raises(ptime.MonotonicError, ptime.ticks_ms)
    finally:
        ptime.ticks_ms = original


storage_setup()
run()
