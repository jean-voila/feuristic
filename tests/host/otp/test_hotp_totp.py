# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
import hashlib
import hmac as py_hmac

import pytest
from hypothesis import given
from hypothesis import strategies as st

from feuristic.apps.otp import hotp, totp
from feuristic.core import clock as clock_mod
from feuristic.core.errors import InvalidInput, PolicyDenied
from feuristic.platform import crypto

RFC4226_SECRET = b"12345678901234567890"

# RFC 4226 Appendix D: (count, HMAC-SHA-1 hex, truncated decimal, HOTP)
RFC4226_D = [
    (0, "cc93cf18508d94934c64b65d8ba7667fb7cde4b0", 1284755224, "755224"),
    (1, "75a48a19d4cbe100644e8ac1397eea747a2d33ab", 1094287082, "287082"),
    (2, "0bacb7fa082fef30782211938bc1c5e70416ff44", 137359152, "359152"),
    (3, "66c28227d03a2d5529262ff016a1e6ef76557ece", 1726969429, "969429"),
    (4, "a904c900a64b35909874b33e61c5938a8e15ed1c", 1640338314, "338314"),
    (5, "a37e783d7b7233c083d4f62926c7a25f238d0316", 868254676, "254676"),
    (6, "bc9cd28561042c83f219324d3c607256c03272ae", 1918287922, "287922"),
    (7, "a4fb960c0bc06e1eabb804e5b397cdc4b45596fa", 82162583, "162583"),
    (8, "1b3c89f65e6c9e883012052823443f048b4332db", 673399871, "399871"),
    (9, "1637409809a679dc698207310c8c7fc07290d9e5", 645520489, "520489"),
]


@pytest.mark.parametrize(("count", "mac_hex", "trunc", "code"), RFC4226_D)
def test_rfc4226_appendix_d(count, mac_hex, trunc, code):
    mac = crypto.hmac("sha1", RFC4226_SECRET, count.to_bytes(8, "big"))
    assert mac.hex() == mac_hex
    assert hotp.dynamic_truncate(mac) == trunc
    assert hotp.hotp(RFC4226_SECRET, count) == code
    assert hotp.hotp(bytearray(RFC4226_SECRET), count) == code


def test_rfc4226_section_5_4_example():
    mac = bytes.fromhex("1f8698690e02ca16618550ef7f19da8e945b555a")
    assert hotp.dynamic_truncate(mac) == 0x50EF7F19
    assert hotp.format_code(0x50EF7F19, 6) == "872921"


SEEDS = {
    "SHA1": b"12345678901234567890",
    "SHA256": b"12345678901234567890123456789012",
    "SHA512": b"1234567890123456789012345678901234567890123456789012345678901234",
}

# RFC 6238 Appendix B (8 digits, T0 = 0, X = 30)
RFC6238_B = [
    (59, "94287082", "46119246", "90693936"),
    (1111111109, "07081804", "68084774", "25091201"),
    (1111111111, "14050471", "67062674", "99943326"),
    (1234567890, "89005924", "91819424", "93441116"),
    (2000000000, "69279037", "90698825", "38618901"),
    (20000000000, "65353130", "77737706", "47863826"),
]


@pytest.mark.parametrize(("unix", "c1", "c256", "c512"), RFC6238_B)
def test_rfc6238_appendix_b(unix, c1, c256, c512):
    for alg, expected in (("SHA1", c1), ("SHA256", c256), ("SHA512", c512)):
        code, remaining = totp.totp_at(SEEDS[alg], unix, 30, 8, alg)
        assert code == expected
        assert remaining == 30 - unix % 30


def test_time_step_matches_rfc_table():
    assert totp.time_step(59) == 1
    assert totp.time_step(1111111109) == 0x23523EC
    assert totp.time_step(1111111111) == 0x23523ED
    assert totp.time_step(1234567890) == 0x273EF07
    assert totp.time_step(2000000000) == 0x3F940AA
    assert totp.time_step(20000000000) == 0x27BC86AA


def test_remaining_bounds_and_boundaries():
    s = SEEDS["SHA1"]
    assert totp.totp_at(s, 0)[1] == 30
    assert totp.totp_at(s, 29)[1] == 1
    assert totp.totp_at(s, 30)[1] == 30
    assert totp.totp_at(s, 29)[0] == hotp.hotp(s, 0)
    assert totp.totp_at(s, 30)[0] == hotp.hotp(s, 1)
    assert totp.totp_at(s, 100, period=15)[0] == hotp.hotp(s, 6)
    assert totp.totp_at(s, 599, period=300) == (hotp.hotp(s, 1), 1)


@pytest.mark.parametrize("digits", [6, 7, 8])
def test_digits_zero_padding(digits):
    assert hotp.format_code(42, digits) == "0" * (digits - 2) + "42"
    assert hotp.format_code(123456789, digits) == "123456789"[-digits:]
    for c in range(10):
        assert len(hotp.hotp(RFC4226_SECRET, c, digits)) == digits


@pytest.mark.parametrize(
    "kwargs",
    [
        {"secret": b""},
        {"secret": bytes(65)},
        {"secret": "12345678901234567890"},
        {"digits": 5},
        {"digits": 9},
        {"digits": 10},
        {"digits": True},
        {"algorithm": "sha1"},
        {"algorithm": "MD5"},
        {"counter": -1},
        {"counter": 2**64},
        {"counter": True},
        {"counter": "1"},
    ],
)
def test_hotp_invalid_params(kwargs):
    args = {"secret": RFC4226_SECRET, "counter": 0, "digits": 6, "algorithm": "SHA1"}
    args.update(kwargs)
    with pytest.raises(InvalidInput):
        hotp.hotp(args["secret"], args["counter"], args["digits"], args["algorithm"])


def test_hotp_counter_extremes():
    assert len(hotp.hotp(RFC4226_SECRET, 2**64 - 1)) == 6
    with pytest.raises(InvalidInput):
        hotp.dynamic_truncate(bytes(19))


@pytest.mark.parametrize("period", [0, -30, 14, 301, 3600, True, "30"])
def test_invalid_period(period):
    with pytest.raises(InvalidInput):
        totp.totp_at(SEEDS["SHA1"], 1000, period)


@pytest.mark.parametrize("unix", [-1, True, "59", 2**63])
def test_invalid_time(unix):
    with pytest.raises(InvalidInput):
        totp.totp_at(SEEDS["SHA1"], unix)


def test_totp_now_not_synchronised_and_synchronised(clock):
    sc = clock_mod.SessionClock()
    with pytest.raises(totp.TimeNotSynchronised) as ei:
        totp.totp_now(SEEDS["SHA1"], clock=sc)
    assert isinstance(ei.value, PolicyDenied)
    sc.set(1_800_000_000)
    clock.advance(12_000)
    assert totp.totp_now(SEEDS["SHA1"], clock=sc) == totp.totp_at(SEEDS["SHA1"], 1_800_000_012)


def test_totp_now_uses_global_clock_by_default(clock):
    try:
        clock_mod.CLOCK.clear()
        with pytest.raises(totp.TimeNotSynchronised):
            totp.totp_now(SEEDS["SHA1"])
        clock_mod.CLOCK.set(1_800_000_000)
        assert totp.totp_now(SEEDS["SHA1"], 60, 7, "SHA256") == totp.totp_at(
            SEEDS["SHA1"], 1_800_000_000, 60, 7, "SHA256"
        )
    finally:
        clock_mod.CLOCK.clear()


def _ref_hotp(key, counter, digits, alg):
    mac = py_hmac.new(key, counter.to_bytes(8, "big"), getattr(hashlib, alg.lower())).digest()
    off = mac[-1] & 0x0F
    v = int.from_bytes(mac[off : off + 4], "big") & 0x7FFFFFFF
    return str(v % 10**digits).zfill(digits)


@given(
    st.binary(min_size=1, max_size=64),
    st.integers(min_value=0, max_value=2**64 - 1),
    st.sampled_from([6, 7, 8]),
    st.sampled_from(["SHA1", "SHA256", "SHA512"]),
)
def test_hotp_matches_reference(key, counter, digits, alg):
    assert hotp.hotp(key, counter, digits, alg) == _ref_hotp(key, counter, digits, alg)


@given(
    st.binary(min_size=1, max_size=64),
    st.integers(min_value=0, max_value=2**40),
    st.integers(min_value=15, max_value=300),
)
def test_totp_matches_reference(key, unix, period):
    code, remaining = totp.totp_at(key, unix, period)
    assert code == _ref_hotp(key, unix // period, 6, "SHA1")
    assert 1 <= remaining <= period
    assert (unix + remaining) % period == 0
