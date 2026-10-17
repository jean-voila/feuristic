# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Pure-Python SHA-1 (FIPS 180-4).

SHA-1 is not exposed by trezor-crypto's MicroPython bindings. It is only used
where a standard mandates it (HOTP/TOTP HMAC-SHA1, OpenPGP v4 fingerprints)
and only on small inputs, so a portable implementation is sufficient.
"""

_MASK = 0xFFFFFFFF


def _rol(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & _MASK


def sha1(data: bytes) -> bytes:
    data = bytes(data)
    h0, h1, h2, h3, h4 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
    ml = len(data) * 8
    data += b"\x80" + bytes((55 - len(data)) % 64) + ml.to_bytes(8, "big")
    w = [0] * 80
    for off in range(0, len(data), 64):
        for i in range(16):
            w[i] = int.from_bytes(data[off + 4 * i : off + 4 * i + 4], "big")
        for i in range(16, 80):
            w[i] = _rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)
        a, b, c, d, e = h0, h1, h2, h3, h4
        for i in range(80):
            if i < 20:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif i < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif i < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6
            t = (_rol(a, 5) + (f & _MASK) + e + k + w[i]) & _MASK
            e = d
            d = c
            c = _rol(b, 30)
            b = a
            a = t
        h0 = (h0 + a) & _MASK
        h1 = (h1 + b) & _MASK
        h2 = (h2 + c) & _MASK
        h3 = (h3 + d) & _MASK
        h4 = (h4 + e) & _MASK
    return b"".join(x.to_bytes(4, "big") for x in (h0, h1, h2, h3, h4))
