# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""DES and Triple-DES (TDEA) block ciphers in pure Python.

Only used for the PIV *card application administration key* (slot ``9B``,
algorithm ``0x03``, NIST SP 800-78-4 Table 5) authentication, i.e. one or two
single-block operations per GENERAL AUTHENTICATE. Bulk encryption with
(T)DES is not offered anywhere in feuristic.

* DES: FIPS 46-3 (withdrawn, kept as the TDEA building block).
* TDEA: NIST SP 800-67 Rev. 2, keying option 1 (three independent 8-byte
  keys, 24-byte key bundle), encryption ``E_K3(D_K2(E_K1(P)))``. The PIV
  default key ``0102..08`` × 3 degenerates to single DES (K1 = K2 = K3); it is
  only acceptable as a factory default that the user replaces.
* DES parity bits (LSB of each key byte) are ignored, as in FIPS 46-3.

Side channels: the S-box lookups index small tables; the target MCUs have
no data cache in the coreapp memory path, and the key is a non-exportable
administration secret used at most a few times per session.
"""

from micropython import const

from ....core.errors import InvalidInput

BLOCK_SIZE = const(8)
TDES_KEY_SIZE = const(24)

# fmt: off
_IP = bytes((
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
))
_FP = bytes((
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
))
_E = bytes((
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11,
    12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
    22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
))
_P = bytes((
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
))
_PC1 = bytes((
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
))
_PC2 = bytes((
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
))
_SHIFTS = bytes((1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1))
# S-boxes S1..S8, each 4 rows x 16 columns
_S = bytes((
    14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
    0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
    4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
    15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,

    15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
    3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
    0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
    13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,

    10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
    13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
    13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
    1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,

    7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
    13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
    10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
    3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,

    2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
    14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
    4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
    11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,

    12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
    10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
    9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
    4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,

    4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
    13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
    1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
    6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,

    13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
    1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
    7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
    2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
))
# fmt: on

_MASK28 = const(0x0FFFFFFF)
_MASK32 = 0xFFFFFFFF


def _permute(value: int, table: bytes, in_bits: int) -> int:
    """Bit permutation; ``table`` lists 1-based input positions, MSB first."""
    out = 0
    for pos in table:
        out = (out << 1) | ((value >> (in_bits - pos)) & 1)
    return out


def _subkeys(key8: bytes) -> list:
    """The 16 round keys (48 bits each) of FIPS 46-3 §"Key schedule"."""
    cd = _permute(int.from_bytes(key8, "big"), _PC1, 64)
    c = cd >> 28
    d = cd & _MASK28
    keys = []
    for s in _SHIFTS:
        c = ((c << s) | (c >> (28 - s))) & _MASK28
        d = ((d << s) | (d >> (28 - s))) & _MASK28
        keys.append(_permute((c << 28) | d, _PC2, 56))
    return keys


def _feistel(r: int, k: int) -> int:
    x = _permute(r, _E, 32) ^ k
    out = 0
    for i in range(8):
        six = (x >> (42 - 6 * i)) & 0x3F
        row = ((six >> 4) & 0x02) | (six & 0x01)
        col = (six >> 1) & 0x0F
        out = (out << 4) | _S[(i << 6) | (row << 4) | col]
    return _permute(out, _P, 32)


def _crypt(block: bytes, keys) -> bytes:
    v = _permute(int.from_bytes(block, "big"), _IP, 64)
    left = v >> 32
    right = v & _MASK32
    for k in keys:
        left, right = right, left ^ _feistel(right, k)
    return _permute((right << 32) | left, _FP, 64).to_bytes(8, "big")


class Des:
    """Single DES (FIPS 46-3) on one 8-byte block."""

    def __init__(self, key: bytes) -> None:
        if len(key) != 8:
            raise InvalidInput("DES key must be 8 bytes")
        self._enc = _subkeys(bytes(key))
        self._dec = list(reversed(self._enc))

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != BLOCK_SIZE:
            raise InvalidInput("DES block must be 8 bytes")
        return _crypt(bytes(block), self._enc)

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != BLOCK_SIZE:
            raise InvalidInput("DES block must be 8 bytes")
        return _crypt(bytes(block), self._dec)


class TripleDes:
    """TDEA keying option 1 (SP 800-67 Rev. 2 §3.2): ``E_K3 ∘ D_K2 ∘ E_K1``."""

    def __init__(self, key: bytes) -> None:
        if len(key) != TDES_KEY_SIZE:
            raise InvalidInput("TDES key must be 24 bytes")
        key = bytes(key)
        self._k1 = Des(key[0:8])
        self._k2 = Des(key[8:16])
        self._k3 = Des(key[16:24])

    def encrypt_block(self, block: bytes) -> bytes:
        return self._k3.encrypt_block(self._k2.decrypt_block(self._k1.encrypt_block(block)))

    def decrypt_block(self, block: bytes) -> bytes:
        return self._k1.decrypt_block(self._k2.encrypt_block(self._k3.decrypt_block(block)))
