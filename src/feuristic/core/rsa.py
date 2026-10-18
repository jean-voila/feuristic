# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""RSA key generation and PKCS#1 v1.5 encoding helpers (shared code).

Key generation follows FIPS 186-5 Appendix A.1.3 ("generation of random
primes that are probably prime") and is driven from Python so that the
firmware stays responsive: every native call (one sieve, one Miller-Rabin
round, ...) is bounded (<= ~160 ms on a Cortex-M4) and ``yield_fn`` is
awaited between calls. See docs/developer/rsa.md for the parameters, the
deviations from the letter of FIPS 186-5 and the timing estimates.

The raw RSA primitives live in :mod:`feuristic.platform.crypto`
(``rsa_complete``, ``rsa_private``, ``rsa_public``, ``rsa_sieve``,
``rsa_mr_round``).
"""

from micropython import const

from feuristic.core.errors import InvalidInput
from feuristic.platform import crypto

from .secure import wipe

DEFAULT_E = const(65537)

# Miller-Rabin rounds for one prime of the given size (random candidates,
# no Lucas test). FIPS 186-5 Table B.1: 5 rounds for the 1024-bit primes of
# RSA-2048. The 512-bit row (RSA-1024, host tests only - RSA-1024 is not an
# approved FIPS 186-5 size) uses 7 rounds as in FIPS 186-4 Table C.3.
_MR_ROUNDS = {512: 7, 1024: 5}

# Expected number of candidates before a prime is found: ln(2^bits) / 2 for
# odd candidates. Only used to shape the progress indicator.
_EXPECTED_CANDIDATES = {512: 177, 1024: 355}

# FIPS 186-5 A.1.3 5.4: |p - q| > 2^(nlen/2 - 100).
_PQ_DISTANCE_BITS = const(100)

# DigestInfo prefixes, RFC 8017 section 9.2, note 1.
_DIGEST_INFO_PREFIX = {
    "sha256": (
        b"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20",
        32,
    ),
    "sha384": (
        b"\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30",
        48,
    ),
    "sha512": (
        b"\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40",
        64,
    ),
}


# ---------------------------------------------------------------------------
# key generation
# ---------------------------------------------------------------------------


class _Progress:
    """Maps the (unbounded) prime search onto a monotonic [0, 1] fraction."""

    def __init__(self, fn, expected: int) -> None:
        self.fn = fn
        self.expected = expected
        self.start = 0.0
        self.width = 0.0
        self.last = 0.0

    def phase(self, start: float, width: float) -> None:
        self.start = start
        self.width = width
        self.report(start)

    def tries(self, n: int) -> None:
        # n / (n + expected): 0 at start, 1/2 after the expected number of
        # candidates, tends to 1; never decreases.
        self.report(self.start + self.width * n / (n + self.expected))

    def report(self, value: float) -> None:
        value = max(value, self.last)
        value = min(value, 1.0)
        self.last = value
        if self.fn is not None:
            self.fn(value)


def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def _from_bytes(b) -> int:
    return int.from_bytes(bytes(b), "big")


async def _yield(yield_fn) -> None:
    if yield_fn is not None:
        await yield_fn()


async def _random_prime(nbytes: int, e: int, prog: _Progress, yield_fn) -> bytearray:
    """FIPS 186-5 A.1.3 steps 4.2-4.7 (resp. 5.2-5.8) for one prime."""
    rounds = _MR_ROUNDS[nbytes * 8]
    tries = 0
    while True:
        tries += 1
        prog.tries(tries)
        # 4.2: random candidate from the strong RBG. The two top bits are set
        # so that p >= sqrt(2) * 2^(nlen/2 - 1) (4.4) holds by construction,
        # and p = 3 mod 4 so that the Miller-Rabin round runs in time
        # independent of the candidate (v2(p - 1) = 1, see frsa_mr_round).
        cand = bytearray(crypto.random_bytes(nbytes, True))
        cand[0] |= 0xC0
        cand[-1] |= 0x03
        # Cheap rejection first: trial division (constant time in C).
        ok = crypto.rsa_sieve(cand)
        await _yield(yield_fn)
        if not ok:
            continue
        # 4.5: gcd(p - 1, e) = 1.
        if _gcd(_from_bytes(cand) - 1, e) != 1:
            continue
        # 4.6: Miller-Rabin with random bases (B.3.1).
        w = _from_bytes(cand)
        for _ in range(rounds):
            while True:
                b = crypto.random_bytes(nbytes, False)
                bi = _from_bytes(b)
                if 1 < bi < w - 1:
                    break
            ok = crypto.rsa_mr_round(cand, b)
            await _yield(yield_fn)
            if not ok:
                break
        if ok:
            return cand


def _d_too_small(p: int, q: int, dp: int, dq: int, half_bits: int) -> bool:
    """True iff d = e^-1 mod lcm(p-1, q-1) <= 2^(nlen/2) (FIPS 186-5 A.1.1).

    d is not materialised: if d <= 2^(nlen/2) < 2(p - 1) then d is dp or
    dp + (p - 1), and it is the one that is also congruent to dq modulo q - 1
    (any such value <= 2^(nlen/2) < lcm(p-1, q-1) equals d).
    """
    bound = 1 << half_bits
    return any(c <= bound and c % (q - 1) == dq for c in (dp, dp + p - 1))


async def generate(
    bits: int = 2048,
    e: int = DEFAULT_E,
    progress=None,
    yield_fn=None,
) -> crypto.RsaKey:
    """Generate an RSA key pair (FIPS 186-5 A.1.3, probable primes).

    ``bits`` is 2048 (or 1024 for tests); ``e`` is an odd public exponent
    with 2^16 < e < 2^32. ``progress(fraction)`` is called with a monotonic
    value in [0, 1]; ``await yield_fn()`` runs between native calls so the
    caller can service USB and the UI. Returns a completed :class:`RsaKey`
    (p > q) that passed a pairwise consistency test.
    """
    if bits not in (1024, 2048):
        raise InvalidInput("RSA size")
    if not isinstance(e, int) or e & 1 == 0 or not (1 << 16) < e < (1 << 32):
        raise InvalidInput("RSA public exponent")
    half_bits = bits // 2
    nbytes = half_bits // 8
    prog = _Progress(progress, _EXPECTED_CANDIDATES[half_bits])
    min_distance = 1 << (half_bits - _PQ_DISTANCE_BITS)

    while True:
        prog.phase(0.0, 0.45)  # never goes backwards on a (rare) restart
        p = await _random_prime(nbytes, e, prog, yield_fn)
        pi = _from_bytes(p)
        prog.phase(0.45, 0.45)
        while True:
            q = await _random_prime(nbytes, e, prog, yield_fn)
            qi = _from_bytes(q)
            # 5.4: |p - q| > 2^(nlen/2 - 100), otherwise pick another q.
            if abs(pi - qi) > min_distance:
                break
            wipe(q)
        if pi < qi:
            p, q = q, p
            pi, qi = qi, pi
        key = crypto.RsaKey(bytes(p), bytes(q), e)
        wipe(p)
        wipe(q)
        prog.report(0.9)
        crypto.rsa_complete(key)
        await _yield(yield_fn)
        # n must have exactly `bits` bits: guaranteed by the two top bits of
        # each prime (product >= 2.25 * 2^(nlen-2)).
        if len(key.n) != bits // 8 or key.n[0] < 0x80:
            continue
        if _d_too_small(pi, qi, _from_bytes(key.dp), _from_bytes(key.dq), half_bits):
            continue  # negligible probability; regenerate both primes
        prog.report(0.95)
        if not await _pairwise_test(key, yield_fn):
            raise crypto.CryptoError("RSA pairwise consistency test failed")
        prog.report(1.0)
        return key


async def _pairwise_test(key: crypto.RsaKey, yield_fn) -> bool:
    """Sign/verify a random block (SP 800-56B rev. 2, 6.4.1.1 style PCT)."""
    k = len(key.n)
    m = bytearray(crypto.random_bytes(k, False))
    m[0] = 0  # m < n
    m[-1] |= 2  # m not in {0, 1}
    s = crypto.rsa_private(key, bytes(m))
    await _yield(yield_fn)
    ok = crypto.ct_equal(crypto.rsa_public(key.n, key.e, s), bytes(m))
    await _yield(yield_fn)
    return ok


# ---------------------------------------------------------------------------
# PKCS#1 v1.5 (RFC 8017)
# ---------------------------------------------------------------------------


def digest_info(hash_name: str, digest: bytes) -> bytes:
    """DER DigestInfo for ``hash_name`` in ("sha256", "sha384", "sha512")."""
    entry = _DIGEST_INFO_PREFIX.get(hash_name)
    if entry is None:
        raise InvalidInput("unsupported hash")
    prefix, size = entry
    if len(digest) != size:
        raise InvalidInput("digest size")
    return prefix + bytes(digest)


def pkcs1v15_sign_pad(t: bytes, k: int) -> bytes:
    """EMSA-PKCS1-v1_5 encoding (RFC 8017 9.2 steps 3-5) of DigestInfo ``t``
    for a ``k``-byte modulus: ``00 01 FF..FF 00 || t`` (at least 8 x FF)."""
    if k < len(t) + 11:
        raise InvalidInput("intended encoded message length too short")
    return b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + bytes(t)


def pkcs1v15_decrypt_unpad(em: bytes, k=None):
    """RSAES-PKCS1-v1_5 decoding (RFC 8017 7.2.2 step 3).

    ``k`` is the modulus length in bytes (defaults to ``len(em)``; pass it
    explicitly to also reject a block of the wrong size). Returns the
    message, or ``None`` if ``em`` is not ``00 02 PS 00 M`` with
    at least 8 non-zero PS bytes. All bytes are always examined with
    branch-free mask arithmetic and a single final decision is taken, so the
    caller learns only "valid" or "invalid", never which check failed.
    Callers implementing a decryption oracle (OpenPGP/PIV decipher) must map
    ``None`` to one generic error, ideally after the same amount of work.
    """
    if k is None:
        k = len(em)
    if k < 11 or len(em) != k:
        return None
    good = 1 if (em[0] | (em[1] ^ 0x02)) == 0 else 0
    looking = 1
    sep = 0
    for i in range(2, k):
        is_zero = ((em[i] - 1) >> 8) & 1  # 1 iff em[i] == 0
        first = looking & is_zero
        sep |= (-first) & i
        looking &= is_zero ^ 1
    # separator found, and PS (indices 2 .. sep-1) is at least 8 bytes long
    long_ps = ((9 - sep) >> 31) & 1  # 1 iff sep >= 10
    valid = good & (looking ^ 1) & long_ps
    if valid != 1:
        return None
    return bytes(em[sep + 1 :])


def public_numbers(key: crypto.RsaKey) -> tuple:
    """Return ``(n, e)``: the big-endian modulus and the public exponent."""
    if not key.n:
        crypto.rsa_complete(key)
    return key.n, key.e
