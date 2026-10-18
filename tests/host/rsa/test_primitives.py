# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Facade-level RSA helpers: rsa_sieve / rsa_mr_round (host backend) and the
firmware dispatch contract with the `feuristic_native` C module."""

import os
import re
import sys
import types

import pytest

from feuristic.platform import _backend, _host_crypto, crypto

ROOT = os.path.join(os.path.dirname(__file__), "..", "..", "..")


def _b(x: int) -> bytes:
    return x.to_bytes(max(1, (x.bit_length() + 7) // 8), "big")


# --- sieve -----------------------------------------------------------------


def test_sieve_table_matches_c_header():
    """The host product must equal lib/frsa/frsa_sieve_table.h bit for bit."""
    with open(os.path.join(ROOT, "lib", "frsa", "frsa_sieve_table.h")) as f:
        text = f.read()
    body = text.split("FRSA_SIEVE_PRODUCT", 1)[1]
    data = bytes(int(h, 16) for h in re.findall(r"0x([0-9A-F]{2})", body))
    assert int.from_bytes(data, "big") == _host_crypto._sieve_product()


@pytest.mark.parametrize(
    ("c", "expected"),
    [
        (3, False),
        (17881, False),  # largest table prime
        (17891, True),  # next prime
        (17891 * 17903, True),
        (17881 * 17891, False),
        (1, False),
        (0, False),
        (2, False),
        (4, False),
        (2**127 - 1, True),
        (3 * (2**127 - 1), False),
        (2**521 - 1, True),
    ],
)
def test_sieve_values(c, expected):
    assert crypto.rsa_sieve(_b(c)) is expected


def test_sieve_leading_zeros_and_limits():
    assert crypto.rsa_sieve(b"\x00\x00" + _b(2**127 - 1)) is True
    assert crypto.rsa_sieve(b"\x00") is False
    with pytest.raises(ValueError):
        crypto.rsa_sieve(b"")
    with pytest.raises(ValueError):
        crypto.rsa_sieve(b"\x01" * 257)


# --- Miller-Rabin ----------------------------------------------------------

SPSP2 = [2047, 3277, 4033, 4681, 8321, 15841, 29341]
CARMICHAEL = [561, 1105, 1729, 2465, 2821, 6601, 8911]


def test_mr_strong_pseudoprimes_base2():
    for n in SPSP2:
        assert crypto.rsa_mr_round(_b(n), _b(2)) is True
        assert any(crypto.rsa_mr_round(_b(n), _b(b)) is False for b in (3, 5, 7, 11))


def test_mr_carmichael_numbers():
    for n in CARMICHAEL:
        assert any(crypto.rsa_mr_round(_b(n), _b(b)) is False for b in (2, 3, 5, 7, 11, 13))


def test_mr_jaeschke_psi():
    # strong pseudoprime to all prime bases up to 37
    n = 318665857834031151167461
    for b in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        assert crypto.rsa_mr_round(_b(n), _b(b)) is True
    assert crypto.rsa_mr_round(_b(n), _b(41)) is False


@pytest.mark.parametrize("p", [5, 7, 563, 2**61 - 1, 2**127 - 1, 2**521 - 1, 2**1279 - 1])
def test_mr_primes(p):
    for b in {2, 3, p - 2}:
        if 1 < b < p - 1:
            assert crypto.rsa_mr_round(_b(p), _b(b)) is True


@pytest.mark.parametrize(
    ("w", "b"),
    [(563, 1), (563, 0), (563, 562), (563, 563), (564, 2), (3, 2), (1, 2), (563, 10**6)],
)
def test_mr_rejects(w, b):
    with pytest.raises(ValueError):
        crypto.rsa_mr_round(_b(w), _b(b))


def test_mr_rejects_sizes():
    with pytest.raises(ValueError):
        crypto.rsa_mr_round(b"", b"\x02")
    with pytest.raises(ValueError):
        crypto.rsa_mr_round(b"\x01" * 257, b"\x02")


# --- firmware dispatch contract -------------------------------------------


class FakeNative(types.ModuleType):
    def __init__(self):
        super().__init__("feuristic_native")
        self.calls = []

    def rsa_complete(self, p, q, e):
        self.calls.append(("rsa_complete", p, q, e))
        return _host_crypto.rsa_complete(p, q, e)

    def rsa_private(self, *args):
        self.calls.append(("rsa_private", *args))
        p, q, dp, dq, qinv, e, n, block = args
        key = crypto.RsaKey(p, q, e)
        key.n, key.dp, key.dq, key.qinv = n, dp, dq, qinv
        return None if block == b"\x00" * len(n) else _host_crypto.rsa_private(key, block)

    def rsa_sieve(self, c):
        self.calls.append(("rsa_sieve", c))
        return True

    def rsa_mr_round(self, c, b):
        self.calls.append(("rsa_mr_round", c, b))
        return False


@pytest.fixture
def firmware(monkeypatch):
    fake = FakeNative()
    monkeypatch.setitem(sys.modules, "feuristic_native", fake)
    monkeypatch.setattr(_backend, "FIRMWARE", True)
    return fake


def test_firmware_rsa_private_passes_e_and_n(firmware):
    from cryptography.hazmat.primitives.asymmetric import rsa

    nums = rsa.generate_private_key(65537, 1024).private_numbers()
    key = crypto.RsaKey(nums.p.to_bytes(64, "big"), nums.q.to_bytes(64, "big"))
    block = b"\x00" + b"\x42" * 127
    out = crypto.rsa_private(key, block)
    names = [c[0] for c in firmware.calls]
    assert names == ["rsa_complete", "rsa_private"]
    call = firmware.calls[1]
    assert call[1:] == ("rsa_private", key.p, key.q, key.dp, key.dq, key.qinv, 65537, key.n, block)[1:]
    assert len(call) == 9  # 8 positional arguments
    assert pow(int.from_bytes(out, "big"), 65537, nums.public_numbers.n) == int.from_bytes(block, "big")
    # native failure (None) -> CryptoError
    with pytest.raises(crypto.CryptoError):
        crypto.rsa_private(key, bytes(128))


def test_firmware_sieve_and_mr_dispatch(firmware):
    assert crypto.rsa_sieve(b"\x07") is True
    assert crypto.rsa_mr_round(b"\x07", b"\x02") is False
    assert firmware.calls == [("rsa_sieve", b"\x07"), ("rsa_mr_round", b"\x07", b"\x02")]
