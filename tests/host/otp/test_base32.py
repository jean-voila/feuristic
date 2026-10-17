# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
import base64
import contextlib

import pytest
from hypothesis import given
from hypothesis import strategies as st

from feuristic.core import base32
from feuristic.core.errors import InvalidInput

# RFC 4648 §10 test vectors
RFC4648 = [
    (b"f", "MY======"),
    (b"fo", "MZXQ===="),
    (b"foo", "MZXW6==="),
    (b"foob", "MZXW6YQ="),
    (b"fooba", "MZXW6YTB"),
    (b"foobar", "MZXW6YTBOI======"),
]


@pytest.mark.parametrize(("raw", "enc"), RFC4648)
def test_rfc4648_vectors(raw, enc):
    assert base32.encode(raw) == enc
    assert base32.encode(raw, pad=False) == enc.rstrip("=")
    assert base32.decode(enc) == raw
    assert base32.decode(enc.rstrip("=")) == raw
    assert base32.decode(enc.lower()) == raw
    assert base32.decode(enc.encode()) == raw
    assert base32.decode(bytearray(enc.encode())) == raw
    assert base32.decode(enc, strict=False) == raw


def test_encode_empty():
    assert base32.encode(b"") == ""
    assert base32.encoded_len(0) == 0


def test_encoded_len():
    for n in range(70):
        assert base32.encoded_len(n) == len(base32.encode(bytes(n), pad=False))
        assert base32.encoded_len(n, pad=True) == len(base32.encode(bytes(n)))
    with pytest.raises(InvalidInput):
        base32.encoded_len(-1)


def test_short_padded_forms():
    assert base32.decode("MY======") == b"f"
    assert base32.decode("MY") == b"f"
    assert base32.decode("MZ======", strict=False) == b"f"


def test_separators_tolerated():
    assert base32.decode("JBSW Y3DP EHPK 3PXP") == b"Hello!\xde\xad\xbe\xef"
    assert base32.decode("jbsw-y3dp-ehpk-3pxp") == b"Hello!\xde\xad\xbe\xef"
    assert base32.decode(" MZXW6YTBOI====== ") == b"foobar"
    assert base32.decode("MZXW6YTBOI = = = = = =") == b"foobar"


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "   ",
        "----",
        "MZXW6YT0",  # '0' not in alphabet
        "MZXW6YT1",
        "MZXW6YT8",
        "MZXW6YT9",
        "MZXW+YTB",
        "MZXW/YTB",
        "MZ=XW6YTB",  # padding in the middle
        "MZXW6YTBOI=======",  # 7 pads
        "MZXW6YQ==",  # inconsistent padding count
        "MZXQ==",  # incomplete padding
        "M",  # invalid length (1 char)
        "MZX",  # invalid length (3)
        "MZXW6Y",  # invalid length (6)
        "MZ======",  # non-zero trailing bits
        "MZXW6YR=",  # non-zero trailing bits
        "MZé",
        "MZXW6YTB\n",
        "=",
    ],
)
def test_strict_rejects(bad):
    with pytest.raises(InvalidInput):
        base32.decode(bad)


def test_nonzero_trailing_bits_lenient():
    # 'MB' encodes 0x60 + 2 leftover bits '01'... lenient ignores them
    with pytest.raises(InvalidInput):
        base32.decode("MB")
    assert base32.decode("MB", strict=False) == b"\x60"


def test_lenient_arbitrary_lengths_match_google_decoder():
    # Google Authenticator's decoder: 5 bits per char, drop incomplete byte
    def ref(s):
        bits = "".join(format(base32.ALPHABET.index(c), "05b") for c in s)
        return bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits) - 7, 8))

    for s in ["MZXW6YTBO", "ABCDEFGHIJK", "JBSWY3DPEHPK3PXPA", "AB2"]:
        assert base32.decode(s, strict=False) == ref(s)
    with pytest.raises(InvalidInput):
        base32.decode("M", strict=False)  # 5 bits: no byte
    with pytest.raises(InvalidInput):
        base32.decode("MZXW6Y==", strict=False)  # inconsistent padding still refused


def test_bounds():
    with pytest.raises(InvalidInput):
        base32.decode("A" * 2000)
    with pytest.raises(InvalidInput):
        base32.decode(b"A" * 2000)
    with pytest.raises(InvalidInput):
        base32.decode(base32.encode(bytes(65)), max_len=64)
    assert len(base32.decode(base32.encode(bytes(64)), max_len=64)) == 64
    with pytest.raises(InvalidInput):
        base32.decode("MZXW6YTB", max_input=4)
    with pytest.raises(InvalidInput):
        base32.decode(12345)


def test_error_message_does_not_echo_input():
    try:
        base32.decode("SECRET0SECRET")
    except InvalidInput as e:
        assert "SECRET" not in str(e)


@given(st.binary(min_size=1, max_size=64))
def test_roundtrip_matches_stdlib(data):
    enc = base32.encode(data)
    assert enc == base64.b32encode(data).decode()
    assert base32.decode(enc) == data
    assert base32.decode(enc.rstrip("=").lower()) == data
    assert base32.decode(enc, strict=False) == data


@given(st.text(max_size=80))
def test_decode_never_crashes(s):
    for strict in (True, False):
        try:
            out = base32.decode(s, strict=strict)
        except InvalidInput:
            continue
        assert 1 <= len(out) <= 64


@given(st.binary(max_size=120))
def test_decode_bytes_never_crashes(s):
    with contextlib.suppress(InvalidInput):
        base32.decode(s, max_len=128)
