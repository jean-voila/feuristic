# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""DES / TDEA known-answer tests (FIPS 46-3, NIST SP 800-17, SP 800-67)."""

import os

import pytest
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from hypothesis import given, settings
from hypothesis import strategies as st

from feuristic.apps.card.piv import des
from feuristic.core.errors import InvalidInput

H = bytes.fromhex


@pytest.mark.parametrize(
    ("key", "pt", "ct"),
    [
        # classic FIPS 46 worked example
        ("133457799BBCDFF1", "0123456789ABCDEF", "85E813540F0AB405"),
        # NIST SP 800-17 Table B.1 (variable plaintext, key 0101..01)
        ("0101010101010101", "8000000000000000", "95F8A5E5DD31D900"),
        ("0101010101010101", "4000000000000000", "DD7F121CA5015619"),
        ("0101010101010101", "0000000000000001", "166B40B44ABA4BD6"),
        # SP 800-17 Table B.2 (variable key, plaintext 0)
        ("8001010101010101", "0000000000000000", "95A8D72813DAA94D"),
        ("0101010101010102", "0000000000000000", "869EFD7F9F265A09"),
        # SP 800-17 Table B.3 (permutation operation)
        ("1046913489980131", "0000000000000000", "88D55E54F54C97B4"),
        # SP 800-17 Table B.4 (substitution table)
        ("7CA110454A1A6E57", "01A1D6D039776742", "690F5B0D9A26939B"),
    ],
)
def test_des_kat(key, pt, ct):
    d = des.Des(H(key))
    assert d.encrypt_block(H(pt)) == H(ct)
    assert d.decrypt_block(H(ct)) == H(pt)


def test_parity_bits_ignored():
    a = des.Des(H("133457799BBCDFF1"))
    b = des.Des(H("123456789ABCDEF0"))  # same key, LSBs flipped
    assert a.encrypt_block(b"\x00" * 8) == b.encrypt_block(b"\x00" * 8)


def test_tdes_sp800_67_example():
    """SP 800-67 Rev. 1 Appendix B: "The qufck brown fox jump"."""
    t = des.TripleDes(H("0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123"))
    pt = b"The qufck brown fox jump"
    ct = b"".join(t.encrypt_block(pt[i : i + 8]) for i in range(0, 24, 8))
    assert ct == H("A826FD8CE53B855FCCE21C8112256FE668D5C05DD9B6B900")
    assert b"".join(t.decrypt_block(ct[i : i + 8]) for i in range(0, 24, 8)) == pt


def test_tdes_with_equal_keys_is_single_des():
    k = H("0102030405060708")
    assert des.TripleDes(k * 3).encrypt_block(b"ABCDEFGH") == des.Des(k).encrypt_block(b"ABCDEFGH")


@settings(max_examples=40, deadline=None)
@given(st.binary(min_size=24, max_size=24), st.binary(min_size=8, max_size=8))
def test_tdes_matches_reference(key, block):
    ref = Cipher(TripleDES(key), modes.ECB()).encryptor()
    expected = ref.update(block) + ref.finalize()
    t = des.TripleDes(key)
    assert t.encrypt_block(block) == expected
    assert t.decrypt_block(expected) == block


def test_random_roundtrip():
    for _ in range(10):
        t = des.TripleDes(os.urandom(24))
        b = os.urandom(8)
        assert t.decrypt_block(t.encrypt_block(b)) == b


@pytest.mark.parametrize("n", [0, 7, 9, 16])
def test_bad_sizes(n):
    with pytest.raises(InvalidInput):
        des.Des(bytes(n))
    with pytest.raises(InvalidInput):
        des.Des(bytes(8)).encrypt_block(bytes(n))
    with pytest.raises(InvalidInput):
        des.TripleDes(bytes(n))
