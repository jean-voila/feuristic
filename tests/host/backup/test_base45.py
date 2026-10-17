# SPDX-License-Identifier: GPL-3.0-only
import contextlib

import pytest
from hypothesis import given
from hypothesis import strategies as st

from feuristic.core import base45
from feuristic.core.errors import InvalidInput

# RFC 9285 §4.3 / §4.4 examples
RFC_VECTORS = [
    (b"AB", "BB8"),
    (b"Hello!!", "%69 VD92EX0"),
    (b"base-45", "UJCLQE7W581"),
    (b"ietf!", "QED8WEX0"),
]


@pytest.mark.parametrize(("raw", "text"), RFC_VECTORS)
def test_rfc_vectors(raw, text):
    assert base45.encode(raw) == text
    assert base45.decode(text) == raw
    assert base45.decode(text.encode()) == raw
    assert base45.decode(bytearray(text.encode())) == raw


def test_edge_values():
    assert base45.encode(b"") == ""
    assert base45.decode("") == b""
    assert base45.encode(b"\x00") == "00"
    assert base45.encode(b"\x00\x00") == "000"
    assert base45.encode(b"\xff") == "U5"
    assert base45.encode(b"\xff\xff") == "FGW"
    assert base45.decode("FGW") == b"\xff\xff"
    assert base45.decode("U5") == b"\xff"


@pytest.mark.parametrize(
    "bad",
    [
        "GGW",  # 65536: RFC 9285 §4.4 example of an invalid triplet
        ":::",  # 44 + 44*45 + 44*2025 > 65535
        "GG",  # trailing pair 736 > 255
        "::",
        "A",  # dangling single character
        "BB8A",  # dangling after a valid group
        "bb8",  # lower case is not in the alphabet
        "BB#",
        "BB\x00",
        "BB8\n",
        "AB_",
        "ÀB8",  # non-ASCII
        "BBé",
    ],
)
def test_strict_rejection(bad):
    with pytest.raises(base45.Base45Error):
        base45.decode(bad)


def test_error_is_invalid_input():
    assert issubclass(base45.Base45Error, InvalidInput)


def test_bad_type():
    with pytest.raises(base45.Base45Error):
        base45.decode(12345)


def test_bounds():
    with pytest.raises(base45.Base45Error):
        base45.encode(b"\x00" * 11, max_bytes=10)
    with pytest.raises(base45.Base45Error):
        base45.decode("000" * 6, max_bytes=11)  # 12 bytes
    assert base45.decode("000" * 6, max_bytes=12) == bytes(12)
    with pytest.raises(base45.Base45Error):
        base45.encoded_length(-1)
    with pytest.raises(base45.Base45Error):
        base45.max_decoded_length(-1)


def test_lengths():
    for n in range(50):
        enc = base45.encode(bytes(n))
        assert len(enc) == base45.encoded_length(n)
        assert base45.max_decoded_length(len(enc)) == n
    assert base45.max_decoded_length(258) == 172
    assert base45.max_decoded_length(57) == 38
    assert base45.max_decoded_length(56) == 37  # 18 groups + one pair


def test_alphabet_is_qr_alphanumeric():
    assert len(base45.ALPHABET) == 45
    assert base45.ALPHABET == b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
    assert base45.is_alphabet("FB1 $%*+-./:")
    assert not base45.is_alphabet("fb1")
    assert not base45.is_alphabet("é")
    assert base45.is_alphabet(b"")


@given(st.binary(max_size=600))
def test_roundtrip(data):
    text = base45.encode(data)
    assert base45.is_alphabet(text)
    assert base45.decode(text) == data


@given(st.text(alphabet=st.sampled_from(list(base45.ALPHABET.decode())), max_size=60))
def test_decode_is_bijective_or_rejects(text):
    try:
        raw = base45.decode(text)
    except base45.Base45Error:
        return
    assert base45.encode(raw) == text


@given(st.binary(max_size=200))
def test_decode_arbitrary_bytes_never_crashes(data):
    with contextlib.suppress(base45.Base45Error):
        base45.decode(data)
