# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Tests for feuristic.core.rsa.generate (FIPS 186-5 A.1.3 key generation)."""

import random

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from feuristic.core import rsa as frsa
from feuristic.core.errors import InvalidInput
from feuristic.platform import crypto, testing

from ..aio import run


def _is_probable_prime(n: int, rounds: int = 32) -> bool:
    if n < 2 or n % 2 == 0:
        return n == 2
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    rng = random.Random(n)
    for _ in range(rounds):
        x = pow(rng.randrange(2, n - 1), d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


class Recorder:
    def __init__(self):
        self.yields = 0
        self.progress = []

    async def yield_fn(self):
        self.yields += 1

    def on_progress(self, fraction):
        self.progress.append(fraction)


def _gen(bits=1024, e=65537, rec=None):
    rec = rec or Recorder()
    key = run(frsa.generate(bits, e, progress=rec.on_progress, yield_fn=rec.yield_fn))
    return key, rec


def _validate(key, bits, e=65537):
    p, q = int.from_bytes(key.p, "big"), int.from_bytes(key.q, "big")
    n = int.from_bytes(key.n, "big")
    half = bits // 2
    assert len(key.p) == len(key.q) == half // 8
    assert p > q
    assert p.bit_length() == q.bit_length() == half
    # two top bits set, p = q = 3 mod 4 (see core/rsa.py)
    assert p >> (half - 2) == 3 and q >> (half - 2) == 3
    assert p % 4 == 3 and q % 4 == 3
    assert _is_probable_prime(p) and _is_probable_prime(q)
    assert n == p * q and n.bit_length() == bits and len(key.n) == bits // 8
    assert abs(p - q) > 1 << (half - 100)
    lam = (p - 1) * (q - 1) // _gcd(p - 1, q - 1)
    d = pow(e, -1, lam)
    assert d > 1 << half
    assert key.e == e
    assert int.from_bytes(key.dp, "big") == d % (p - 1)
    assert int.from_bytes(key.dq, "big") == d % (q - 1)
    assert int.from_bytes(key.qinv, "big") == pow(q, -1, p)
    # the cryptography package accepts the key and it works end to end
    priv = rsa.RSAPrivateNumbers(
        p,
        q,
        d,
        rsa.rsa_crt_dmp1(d, p),
        rsa.rsa_crt_dmq1(d, q),
        rsa.rsa_crt_iqmp(p, q),
        rsa.RSAPublicNumbers(e, n),
    ).private_key()
    sig = priv.sign(b"feuristic", padding.PKCS1v15(), hashes.SHA256())
    priv.public_key().verify(sig, b"feuristic", padding.PKCS1v15(), hashes.SHA256())


def _gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def test_generate_1024_deterministic(det_rng):
    key, rec = _gen(1024)
    _validate(key, 1024)
    # yield_fn between native calls, progress monotonic and complete
    assert rec.yields > 20
    assert rec.progress == sorted(rec.progress)
    assert rec.progress[0] >= 0.0 and rec.progress[-1] == 1.0
    assert any(0.0 < f < 0.45 for f in rec.progress)
    assert any(0.45 <= f < 0.9 for f in rec.progress)

    # same RNG seed -> same key
    testing.set_rng(testing.deterministic_rng())
    key2, _ = _gen(1024)
    assert (key2.p, key2.q, key2.n) == (key.p, key.q, key.n)

    # different seed -> different key
    testing.set_rng(testing.deterministic_rng(b"another seed"))
    key3, _ = _gen(1024)
    _validate(key3, 1024)
    assert key3.n != key.n


@pytest.mark.parametrize("seed", [b"s1", b"s2", b"s3"])
def test_generate_1024_seeds(seed):
    testing.set_rng(testing.deterministic_rng(seed))
    key, _ = _gen(1024)
    _validate(key, 1024)


def test_generate_other_exponent(det_rng):
    e = (1 << 31) - 1  # prime, single 31-bit limb in frsa
    key, _ = _gen(1024, e)
    _validate(key, 1024, e)
    e = 0xFFFFFFFF - 2  # odd, needs two limbs in frsa
    key, _ = _gen(1024, e)
    _validate(key, 1024, e)


def test_generate_without_callbacks(det_rng):
    key = run(frsa.generate(1024))
    _validate(key, 1024)


def test_generate_real_rng():
    key, _ = _gen(1024)
    _validate(key, 1024)


@pytest.mark.slow
def test_generate_2048(det_rng):
    key, rec = _gen(2048)
    _validate(key, 2048)
    assert rec.progress[-1] == 1.0
    # usable through the facade
    block = b"\x00" + bytes(range(1, 256))
    sig = crypto.rsa_private(key, block)
    assert crypto.rsa_public(key.n, key.e, sig) == block


@pytest.mark.parametrize("bits", [512, 1023, 1536, 3072, 4096, 0])
def test_generate_rejects_sizes(bits):
    with pytest.raises(InvalidInput):
        run(frsa.generate(bits))


@pytest.mark.parametrize("e", [3, 17, 65536, 65535 + 1, 1 << 16, 1 << 32, (1 << 32) + 1, -65537, 65538])
def test_generate_rejects_exponents(e):
    with pytest.raises(InvalidInput):
        run(frsa.generate(1024, e))


def test_p_q_distance_rule(monkeypatch, det_rng):
    """A q too close to p (FIPS 186-5 A.1.3 5.4) is discarded."""
    calls = []
    real = frsa._random_prime

    async def fake(nbytes, e, prog, yield_fn):
        calls.append(nbytes)
        if len(calls) == 2:
            # return p + 4 (prime or not, it must be rejected by the distance rule)
            p = int.from_bytes(first[0], "big")
            return bytearray((p + 4).to_bytes(nbytes, "big"))
        out = await real(nbytes, e, prog, yield_fn)
        if len(calls) == 1:
            first.append(bytes(out))
        return out

    first = []
    monkeypatch.setattr(frsa, "_random_prime", fake)
    key, _ = _gen(1024)
    assert len(calls) == 3
    _validate(key, 1024)


def test_d_too_small_detection():
    # Construct values where d is small: choose p, q, then e = d^-1 for a small d.
    rng = random.Random(7)

    def prime(bits):
        while True:
            c = rng.getrandbits(bits) | (3 << (bits - 2)) | 3
            if _is_probable_prime(c):
                return c

    p, q = prime(512), prime(512)
    lam = (p - 1) * (q - 1) // _gcd(p - 1, q - 1)
    d = (1 << 400) + 1
    while _gcd(d, lam) != 1:
        d += 2
    e = pow(d, -1, lam)
    assert frsa._d_too_small(p, q, d % (p - 1), d % (q - 1), 512)
    d_big = pow(65537, -1, lam)
    assert not frsa._d_too_small(p, q, d_big % (p - 1), d_big % (q - 1), 512)
    # d slightly above p - 1 (second candidate dp + p - 1) is also caught
    d2 = (p - 1) + 12345
    while _gcd(d2, lam) != 1:
        d2 += 2
    if d2 <= 1 << 512:
        assert frsa._d_too_small(p, q, d2 % (p - 1), d2 % (q - 1), 512)
    assert e > 0


def test_restart_when_d_too_small(monkeypatch, det_rng):
    hits = []

    def fake(p, q, dp, dq, half_bits):
        hits.append(1)
        return len(hits) == 1  # first key rejected

    monkeypatch.setattr(frsa, "_d_too_small", fake)
    key, rec = _gen(1024)
    assert len(hits) == 2
    _validate(key, 1024)
    assert rec.progress == sorted(rec.progress)


def test_pairwise_failure_raises(monkeypatch, det_rng):
    monkeypatch.setattr(crypto, "rsa_public", lambda n, e, b: b"\x00" * len(n))
    with pytest.raises(crypto.CryptoError):
        _gen(1024)
