# SPDX-License-Identifier: GPL-3.0-only
import contextlib

import pytest
from hypothesis import given
from hypothesis import strategies as st

from feuristic.core import tlv


def test_build_and_parse_simple():
    data = tlv.build(0x4F, b"\xa0\x00") + tlv.build(0x5F50, b"https://x") + tlv.build(0x7F49, b"")
    assert tlv.parse(data) == [(0x4F, b"\xa0\x00"), (0x5F50, b"https://x"), (0x7F49, b"")]
    assert tlv.find(data, 0x5F50) == b"https://x"
    assert tlv.find(data, 0x99) is None


@pytest.mark.parametrize(
    "n,enc", [(0, "00"), (0x7F, "7f"), (0x80, "8180"), (0xFF, "81ff"), (0x100, "820100")]
)
def test_length_forms(n, enc):
    assert tlv.encode_len(n).hex() == enc
    parsed = tlv.parse(bytes.fromhex("53") + bytes.fromhex(enc) + bytes(n))
    assert parsed == [(0x53, bytes(n))]


def test_three_byte_tag():
    data = bytes.fromhex("5fc10203") + b"abc"
    assert tlv.parse(data) == [(0x5FC102, b"abc")]
    assert tlv.build(0x5FC102, b"abc") == data


@pytest.mark.parametrize(
    "hexenc",
    ["5f", "5fc1", "5fc1c1c101", "53", "5383", "538101", "5302aa", "5f50820001", "5380"],
)
def test_rejects_malformed(hexenc):
    with pytest.raises(tlv.TlvError):
        tlv.parse(bytes.fromhex(hexenc))


def test_constructed_bit():
    assert tlv.is_constructed(0x7F49)
    assert tlv.is_constructed(0x6E)
    assert not tlv.is_constructed(0x5F50)
    assert not tlv.is_constructed(0x4F)


def test_too_large():
    with pytest.raises(tlv.TlvError):
        tlv.encode_len(0x10000)
    with pytest.raises(tlv.TlvError):
        tlv.encode_tag(0x1000000)


@given(
    st.lists(
        st.tuples(st.sampled_from([0x4F, 0x53, 0x5F50, 0x7F49, 0x5FC105]), st.binary(max_size=300)),
        max_size=6,
    )
)
def test_roundtrip(items):
    assert tlv.parse(tlv.build_many(items)) == items


@given(st.binary(max_size=100))
def test_parser_never_crashes(data):
    with contextlib.suppress(tlv.TlvError):
        tlv.parse(data)
