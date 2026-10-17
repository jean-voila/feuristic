# SPDX-License-Identifier: GPL-3.0-only
import zlib

from hypothesis import given
from hypothesis import strategies as st

from feuristic.apps.backup import crc32


def test_check_value():
    assert crc32.crc32(b"123456789") == 0xCBF43926
    assert crc32.crc32_bytes(b"123456789") == bytes.fromhex("CBF43926")


def test_known_vectors():
    assert crc32.crc32(b"") == 0
    assert crc32.crc32(b"a") == 0xE8B7BE43
    assert crc32.crc32(b"The quick brown fox jumps over the lazy dog") == 0x414FA339
    assert crc32.crc32(bytes(32)) == 0x190A55AD
    assert crc32.crc32(b"\xff" * 32) == 0xFF6CAB0B


def test_incremental():
    assert crc32.update(crc32.crc32(b"12345"), b"6789") == 0xCBF43926


@given(st.binary(max_size=2048))
def test_matches_zlib(data):
    assert crc32.crc32(data) == zlib.crc32(data)


@given(st.binary(min_size=1, max_size=256), st.integers(min_value=0), st.integers(min_value=0, max_value=7))
def test_detects_single_bit_flip(data, pos, bit):
    pos %= len(data)
    flipped = bytearray(data)
    flipped[pos] ^= 1 << bit
    assert crc32.crc32(bytes(flipped)) != crc32.crc32(data)
