# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""RFC 4648 §6 base32 codec (standard alphabet ``A-Z2-7``).

Used for OTP secrets (Google Key URI Format, ``secret=`` parameter) and the
manual display of secrets.

Encoding (:func:`encode`) is canonical: upper case, padding optional
(``pad=False`` is what the Key URI Format recommends).

Decoding (:func:`decode`) accepts what authenticator applications accept:

* case-insensitive letters;
* ``" "`` and ``"-"`` separators anywhere (secrets are often shown in groups
  of four characters); they are removed before decoding;
* optional trailing ``"="`` padding (at most 6 characters, only at the end).

Two strictness levels:

* ``strict=True`` (default, RFC 4648 §3.5 "canonical encoding"): the number
  of significant characters must be a valid base32 length
  (``n % 8 in {0, 2, 4, 5, 7}``), the leftover bits of the final character
  must be zero, and padding, when present, must be complete.
* ``strict=False`` (OTP secrets): behaves like the reference Google
  Authenticator decoder — characters are consumed 5 bits at a time, complete
  bytes are emitted and incomplete trailing bits are discarded. This accepts
  secrets made of *random base32 characters* (any length) which many services
  generate; the resulting key bytes are exactly what other authenticators
  use, so the codes agree.

Input is bounded **before** any allocation (``max_input`` characters) and the
output is bounded by ``max_len`` bytes. Errors raise
:class:`feuristic.core.errors.InvalidInput` without echoing the input (it may
be a secret).
"""

from micropython import const

from .errors import InvalidInput

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
DEFAULT_MAX_INPUT = const(1024)

# valid number of significant characters modulo 8 -> number of '=' pads
_PADS = {0: 0, 2: 6, 4: 4, 5: 3, 7: 1}


def encode(data, pad: bool = True) -> str:
    """Encode ``data`` (bytes-like) as upper-case base32."""
    data = bytes(data)
    out = []
    acc = 0
    bits = 0
    for b in data:
        acc = ((acc << 8) | b) & 0xFFF  # keep at most 12 bits
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append(ALPHABET[(acc >> bits) & 0x1F])
    if bits:
        out.append(ALPHABET[(acc << (5 - bits)) & 0x1F])
    s = "".join(out)
    if pad:
        s += "=" * _PADS[len(s) % 8]
    return s


def encoded_len(n: int, pad: bool = False) -> int:
    """Length of the base32 encoding of ``n`` bytes."""
    if n < 0:
        raise InvalidInput("length")
    if pad:
        return (n + 4) // 5 * 8
    return (n * 8 + 4) // 5


def _value(c: int) -> int:
    """Alphabet value of the character code ``c`` (case-insensitive), or -1."""
    if 0x41 <= c <= 0x5A:  # A-Z
        return c - 0x41
    if 0x61 <= c <= 0x7A:  # a-z
        return c - 0x61
    if 0x32 <= c <= 0x37:  # 2-7
        return c - 0x32 + 26
    return -1


def decode(text, max_len: int = 64, strict: bool = True, max_input: int = DEFAULT_MAX_INPUT) -> bytes:
    """Decode base32 ``text`` (``str`` or bytes-like) into at most ``max_len`` bytes.

    Raises :class:`InvalidInput` on oversized input, characters outside the
    alphabet, misplaced or inconsistent padding, a non-canonical length or
    non-zero trailing bits (strict mode), an empty result or a result longer
    than ``max_len``.
    """
    if isinstance(text, str):
        if len(text) > max_input:  # a str has at least as many bytes as chars
            raise InvalidInput("base32 input too long")
        raw = text.encode()
    elif isinstance(text, (bytes, bytearray, memoryview)):
        raw = bytes(text)
    else:
        raise InvalidInput("base32 input type")
    if len(raw) > max_input:
        raise InvalidInput("base32 input too long")

    values = bytearray()
    pads = 0
    for c in raw:
        if c in (0x20, 0x2D):  # ' ' and '-' separators
            continue
        if c == 0x3D:  # '='
            pads += 1
            continue
        if pads:
            raise InvalidInput("base32 padding not at the end")
        v = _value(c)
        if v < 0:
            raise InvalidInput("invalid base32 character")
        values.append(v)

    n = len(values)
    if n == 0:
        raise InvalidInput("empty base32 input")
    if pads > 6:
        raise InvalidInput("base32 padding too long")
    rem = n % 8
    if strict:
        if rem not in _PADS:
            raise InvalidInput("invalid base32 length")
        if pads and pads != _PADS[rem]:
            raise InvalidInput("inconsistent base32 padding")
    elif pads and (rem not in _PADS or pads != _PADS[rem]):
        raise InvalidInput("inconsistent base32 padding")

    out_len = n * 5 // 8
    if out_len == 0:
        raise InvalidInput("base32 input too short")
    if out_len > max_len:
        raise InvalidInput("base32 value too long")

    out = bytearray(out_len)
    acc = 0
    bits = 0
    pos = 0
    for v in values:
        acc = ((acc << 5) | v) & 0xFFF
        bits += 5
        if bits >= 8:
            bits -= 8
            out[pos] = (acc >> bits) & 0xFF
            pos += 1
    if strict and (acc & ((1 << bits) - 1)):
        raise InvalidInput("non-zero base32 trailing bits")
    return bytes(out)
