# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Hardware RNG service: ISO/IEC 7816-4 GET CHALLENGE (spec F06, §7; R11).

* :class:`HealthMonitor` runs continuous health tests on the bytes delivered
  by :func:`feuristic.platform.crypto.random_bytes` (TRNG ⊕ secure-element
  RNG through the firmware DRBG), adapted from NIST SP 800-90B §4.4:

  - samples are output **bytes** (8-bit samples) and the assessed entropy
    used to derive the cutoffs is H = 8 bits/sample (DRBG output must be
    indistinguishable from uniform; the tests detect catastrophic failures
    such as a stuck or repeating source, not subtle biases);
  - false-positive probability α = 2⁻⁴⁰ per test (SP 800-90B recommends
    2⁻²⁰ ≤ α ≤ 2⁻⁴⁰);
  - Repetition Count Test (§4.4.1): cutoff ``C = 1 + ⌈−log2 α / H⌉ = 6``
    identical consecutive bytes;
  - Adaptive Proportion Test (§4.4.2): window ``W = 512`` (non-binary
    samples), cutoff ``C = 1 + CRITBINOM(512, 2⁻⁸, 1 − 2⁻⁴⁰) = 19``
    occurrences of the window's first byte;
  - start-up test (§4.3): 1024 consecutive bytes are drawn and tested (and
    discarded) before the first output of the power session;
  - a failure is **latched** for the rest of the power session: every
    request is refused until :meth:`HealthMonitor.retest` (menu "Aléa →
    état → relancer le test") passes a new start-up test.

* :class:`TokenBucket` / :class:`RngService` implement the public GET
  CHALLENGE function: no PIN (spec §7 "fonction publique"), at most
  :data:`MAX_CHALLENGE` = 32 bytes per request, anti-abuse rate limiting
  (≤ 20 requests/s and ≤ 4096 bytes/s, burst of one second), and refusal
  when the RNG health status is not satisfactory.

Status words (docs/protocols/aes-gcm-iso7816-v1.md §7):
``9000`` ok · ``6700`` no Le / data present · ``6C20`` Le > 32 (incl.
``Le=00`` = 256) · ``6A86`` P1-P2 ≠ 0000 · ``6985`` rate limit exceeded ·
``6400`` RNG health failure.

When no application is selected, the dispatcher's ``fallback`` should be a
:class:`RngApplet` (GET CHALLENGE only); :func:`get_challenge` is the same
logic as a plain function. Neither touches applet security state, so GET
CHALLENGE cannot disturb sensitive operations in progress. The AES profile
answers GET CHALLENGE when selected; PIV does not define it (``6D00``).
"""

from micropython import const

from ....core.errors import FeuristicError
from ....platform import crypto
from ....platform import time as ptime
from .. import apdu
from ..apdu import Response
from ..applet import Applet

MAX_CHALLENGE = const(32)
RCT_CUTOFF = const(6)
APT_WINDOW = const(512)
APT_CUTOFF = const(19)
STARTUP_SAMPLES = const(1024)

REQUESTS_PER_S = const(20)
BYTES_PER_S = const(4096)

STATE_UNTESTED = const(0)
STATE_OK = const(1)
STATE_FAILED = const(2)

FAIL_RCT = "rct"
FAIL_APT = "apt"


class RngHealthError(FeuristicError):
    """The RNG health tests failed; no random output is released."""


class HealthMonitor:
    """Continuous SP 800-90B-style health tests on delivered random bytes."""

    def __init__(self, source=None) -> None:
        self._source = source
        self.state = STATE_UNTESTED
        self.bytes_tested = 0
        self.bytes_delivered = 0
        self.requests = 0
        self.rct_failures = 0
        self.apt_failures = 0
        self.last_failure = None  # FAIL_RCT / FAIL_APT
        self.last_failure_ms = None
        self._reset_tests()

    def _reset_tests(self) -> None:
        self._rct_value = -1
        self._rct_count = 0
        self._apt_value = -1
        self._apt_count = 0
        self._apt_seen = 0

    def _draw(self, n: int) -> bytes:
        if self._source is not None:
            return self._source(n)
        return crypto.random_bytes(n)

    def _fail(self, kind: str) -> None:
        self.state = STATE_FAILED
        self.last_failure = kind
        self.last_failure_ms = ptime.ticks_ms()
        if kind == FAIL_RCT:
            self.rct_failures += 1
        else:
            self.apt_failures += 1
        self._reset_tests()

    def _feed(self, data) -> bool:
        """Run RCT and APT over ``data``; False (and latched failure) on alarm."""
        rv, rc = self._rct_value, self._rct_count
        av, ac, seen = self._apt_value, self._apt_count, self._apt_seen
        for b in data:
            # Repetition Count Test (SP 800-90B §4.4.1)
            if b == rv:
                rc += 1
                if rc >= RCT_CUTOFF:
                    self._fail(FAIL_RCT)
                    return False
            else:
                rv, rc = b, 1
            # Adaptive Proportion Test (SP 800-90B §4.4.2)
            if seen == 0:
                av, ac, seen = b, 1, 1
            else:
                if b == av:
                    ac += 1
                    if ac >= APT_CUTOFF:
                        self._fail(FAIL_APT)
                        return False
                seen += 1
                if seen >= APT_WINDOW:
                    seen = 0
        self._rct_value, self._rct_count = rv, rc
        self._apt_value, self._apt_count, self._apt_seen = av, ac, seen
        self.bytes_tested += len(data)
        return True

    def startup(self) -> bool:
        """Start-up test over :data:`STARTUP_SAMPLES` bytes (discarded)."""
        self._reset_tests()
        remaining = STARTUP_SAMPLES
        while remaining:
            n = remaining if remaining < 256 else 256
            if not self._feed(self._draw(n)):
                return False
            remaining -= n
        self.state = STATE_OK
        return True

    def retest(self) -> bool:
        """Clear a latched failure by passing a new start-up test (menu action)."""
        self.state = STATE_UNTESTED
        return self.startup()

    def random_bytes(self, n: int) -> bytes:
        """Health-checked random bytes. Raises :class:`RngHealthError`."""
        if self.state == STATE_UNTESTED:
            self.startup()
        if self.state != STATE_OK:
            raise RngHealthError("rng health")
        data = self._draw(n)
        if len(data) != n or not self._feed(data):
            raise RngHealthError("rng health")
        self.requests += 1
        self.bytes_delivered += n
        return data

    def status(self) -> dict:
        """Data of the "Aléa (RNG : état / informations)" screen."""
        return {
            "state": self.state,
            "bytes_tested": self.bytes_tested,
            "bytes_delivered": self.bytes_delivered,
            "requests": self.requests,
            "rct_failures": self.rct_failures,
            "apt_failures": self.apt_failures,
            "last_failure": self.last_failure,
            "last_failure_ms": self.last_failure_ms,
            "rct_cutoff": RCT_CUTOFF,
            "apt_window": APT_WINDOW,
            "apt_cutoff": APT_CUTOFF,
        }


class TokenBucket:
    """Token bucket in milli-tokens driven by the monotonic clock."""

    def __init__(self, rate_per_s: int, burst: int) -> None:
        self.rate = rate_per_s  # milli-tokens per millisecond
        self.capacity = burst * 1000
        self.level = self.capacity
        self._t = ptime.ticks_ms()

    def refill(self) -> None:
        now = ptime.ticks_ms()
        elapsed = ptime.ticks_diff(now, self._t)
        self._t = now
        if elapsed > 0:
            self.level = min(self.capacity, self.level + elapsed * self.rate)

    def available(self, n: int) -> bool:
        return self.level >= n * 1000

    def take(self, n: int) -> None:
        self.level -= n * 1000


class RngService:
    """GET CHALLENGE handler shared by the AES applet and the dispatcher."""

    def __init__(
        self, health=None, requests_per_s: int = REQUESTS_PER_S, bytes_per_s: int = BYTES_PER_S
    ) -> None:
        self.health = HealthMonitor() if health is None else health
        self.req_bucket = TokenBucket(requests_per_s, requests_per_s)
        self.byte_bucket = TokenBucket(bytes_per_s, bytes_per_s)
        self.rate_limited = 0
        self.refused_health = 0

    def get_challenge(self, cmd) -> Response:
        """Answer ``00 84 00 00 Le`` (ISO/IEC 7816-4 §11.6.3)."""
        if cmd.p1p2 != 0x0000:
            return Response(b"", apdu.SW_INCORRECT_P1P2)
        if cmd.data or cmd.ne == 0:
            return Response(b"", apdu.SW_WRONG_LENGTH)
        n = cmd.ne
        if n > MAX_CHALLENGE:
            return Response(b"", apdu.SW_WRONG_LE | MAX_CHALLENGE)
        self.req_bucket.refill()
        self.byte_bucket.refill()
        if not (self.req_bucket.available(1) and self.byte_bucket.available(n)):
            self.rate_limited += 1
            return Response(b"", apdu.SW_CONDITIONS_NOT_SATISFIED)
        self.req_bucket.take(1)
        self.byte_bucket.take(n)
        try:
            return Response(self.health.random_bytes(n))
        except RngHealthError:
            self.refused_health += 1
            return Response(b"", apdu.SW_EXEC_ERROR)

    def status(self) -> dict:
        st = self.health.status()
        st["rate_limited"] = self.rate_limited
        st["refused_health"] = self.refused_health
        st["max_challenge"] = MAX_CHALLENGE
        st["requests_per_s"] = self.req_bucket.rate
        st["bytes_per_s"] = self.byte_bucket.rate
        return st


_default = None


def default() -> RngService:
    """The firmware-wide RNG service (one health state per power session)."""
    global _default
    if _default is None:
        _default = RngService()
    return _default


def _reset_default() -> None:  # tests
    global _default
    _default = None


def get_challenge(cmd) -> Response:
    """Dispatcher entry point: GET CHALLENGE through the firmware-wide service."""
    return default().get_challenge(cmd)


class RngApplet(Applet):
    """Card-level GET CHALLENGE for the dispatcher's ``fallback`` slot.

    Never selectable (no AID); answers only ``GET CHALLENGE`` (CLA ``00``)
    when no application is selected and ``6D00`` to anything else, so that
    no AES operation is reachable without selecting the AES profile::

        Card([openpgp, piv, aes], fallback=RngApplet(ui))
    """

    NAME = "rng"

    def __init__(self, ui=None, service=None) -> None:
        super().__init__(ui)
        self._service = service

    def matches(self, aid_prefix: bytes) -> bool:
        return False

    async def select(self, cmd) -> Response:  # pragma: no cover - never selected
        return Response(b"", apdu.SW_FILE_NOT_FOUND)

    async def process(self, cmd) -> Response:
        if cmd.ins != 0x84:
            return Response(b"", apdu.SW_INS_NOT_SUPPORTED)
        if cmd.cla & 0xEF:
            return Response(b"", apdu.SW_CLA_NOT_SUPPORTED)
        svc = default() if self._service is None else self._service
        return svc.get_challenge(cmd)
