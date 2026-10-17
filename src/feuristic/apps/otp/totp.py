# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""TOTP — time-based one-time password (RFC 6238).

* RFC 6238 §4.2: ``T = floor((unix - T0) / X)`` with ``T0 = 0`` and the time
  step ``X`` (``period``) restricted by feuristic to 15..300 s (default 30);
* ``TOTP = HOTP(K, T)`` (RFC 6238 §4.2, RFC 4226 §5.3) with HMAC-SHA-1,
  HMAC-SHA-256 or HMAC-SHA-512.

The device has no battery-backed clock (spec §4): the wall time comes from
the session clock (:data:`feuristic.core.clock.CLOCK`, set over CDC-ACM).
When the clock is not synchronised :func:`totp_now` raises
:class:`TimeNotSynchronised`; the UI must then show ``otp.time_not_set``
("Heure à synchroniser") instead of a code — never a code computed from an
unknown time.
"""

from micropython import const

from ...core import clock as _clock
from ...core.errors import InvalidInput, PolicyDenied
from . import hotp as _hotp

DEFAULT_PERIOD = const(30)
MIN_PERIOD = const(15)
MAX_PERIOD = const(300)
T0 = const(0)
MAX_UNIX = 0x7FFFFFFFFFFFFFFF


class TimeNotSynchronised(PolicyDenied):
    """The session clock is not set: show "Heure à synchroniser" (spec §4)."""


def check_period(period: int) -> None:
    if isinstance(period, bool) or not isinstance(period, int) or not MIN_PERIOD <= period <= MAX_PERIOD:
        raise InvalidInput("period")


def time_step(unix: int, period: int = DEFAULT_PERIOD) -> int:
    """RFC 6238 §4.2 time-step counter ``T`` for ``unix`` seconds."""
    check_period(period)
    if isinstance(unix, bool) or not isinstance(unix, int) or not T0 <= unix <= MAX_UNIX:
        raise InvalidInput("time")
    return (unix - T0) // period


def totp_at(secret, unix: int, period: int = DEFAULT_PERIOD, digits: int = 6, algorithm: str = _hotp.SHA1):
    """Return ``(code, seconds_remaining)`` for the time ``unix`` (pure function).

    ``seconds_remaining`` is in ``1..period``: the number of seconds during
    which ``code`` stays valid.
    """
    t = time_step(unix, period)
    code = _hotp.hotp(secret, t, digits, algorithm)
    remaining = period - ((unix - T0) % period)
    return code, remaining


def totp_now(secret, period: int = DEFAULT_PERIOD, digits: int = 6, algorithm: str = _hotp.SHA1, clock=None):
    """Return ``(code, seconds_remaining)`` for the current session time.

    ``clock`` defaults to :data:`feuristic.core.clock.CLOCK` (any object with
    a ``now()`` method returning UNIX seconds or ``None``).

    Raises :class:`TimeNotSynchronised` if the clock is not set.
    """
    clk = _clock.CLOCK if clock is None else clock
    now = clk.now()
    if now is None:
        raise TimeNotSynchronised("time not synchronised")
    return totp_at(secret, now, period, digits, algorithm)
