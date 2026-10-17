# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Base45 (RFC 9285) encoder and strict decoder.

Base45 maps every 2 input bytes ``a, b`` to 3 characters of the QR code
alphanumeric alphabet (``n = a*256 + b = c + d*45 + e*45**2`` is emitted
``c d e``) and a trailing odd byte to 2 characters. Because the alphabet is
exactly the QR alphanumeric set, a Base45 string is stored by a QR encoder in
alphanumeric mode (5.5 bits per character), which is how feuristic backup
frames are displayed (spec §8.2, docs/protocols/backup-format-v1.md §5).

The decoder is **strict** (RFC 9285 §4 "decoding"):

* only the 45 alphabet characters are accepted (lower-case letters, other
  punctuation, NUL, non-ASCII, ... are rejected);
* a dangling single character (length ``≡ 1 (mod 3)``) is rejected;
* a 3-character group whose value exceeds 65535, or a final 2-character group
  whose value exceeds 255, is rejected.

These rules make the encoding bijective: each byte string has exactly one
valid Base45 representation. Both directions are bounded by ``max_len``
before any allocation.
"""

from micropython import const

from .errors import InvalidInput

ALPHABET = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

#: default bound on the decoded size (64 KiB) — callers pass tighter bounds
DEFAULT_MAX_BYTES = const(65536)

_INVALID = const(0xFF)


def _build_table() -> bytes:
    table = bytearray(b"\xff" * 256)
    for i in range(len(ALPHABET)):
        table[ALPHABET[i]] = i
    return bytes(table)


_DECODE = _build_table()


class Base45Error(InvalidInput):
    """Invalid Base45 input (bad character, dangling character, overflow, too long)."""


def encoded_length(n: int) -> int:
    """Number of Base45 characters needed for ``n`` bytes."""
    if n < 0:
        raise Base45Error("negative length")
    return 3 * (n // 2) + 2 * (n % 2)


def max_decoded_length(nchars: int) -> int:
    """Largest byte count whose encoding fits in ``nchars`` characters."""
    if nchars < 0:
        raise Base45Error("negative length")
    pairs = nchars // 3
    rem = nchars - 3 * pairs
    return 2 * pairs + (1 if rem >= 2 else 0)


def encode(data, max_bytes: int = DEFAULT_MAX_BYTES) -> str:
    """Encode ``data`` (bytes-like) and return an ASCII ``str``."""
    data = bytes(data)
    n = len(data)
    if n > max_bytes:
        raise Base45Error("input too long")
    out = bytearray(encoded_length(n))
    o = 0
    i = 0
    while i + 1 < n:
        v = (data[i] << 8) | data[i + 1]
        e = v // 2025
        v -= e * 2025
        d = v // 45
        c = v - d * 45
        out[o] = ALPHABET[c]
        out[o + 1] = ALPHABET[d]
        out[o + 2] = ALPHABET[e]
        o += 3
        i += 2
    if i < n:
        v = data[i]
        d = v // 45
        c = v - d * 45
        out[o] = ALPHABET[c]
        out[o + 1] = ALPHABET[d]
    return bytes(out).decode()


def decode(text, max_bytes: int = DEFAULT_MAX_BYTES) -> bytes:
    """Strictly decode ``text`` (``str`` or bytes-like ASCII) into bytes.

    Raises :class:`Base45Error` on any deviation from RFC 9285 or if the
    decoded data would exceed ``max_bytes``.
    """
    if isinstance(text, str):
        # reject non-ASCII before encoding so the length bound is meaningful
        raw = text.encode()
        if len(raw) != len(text):
            raise Base45Error("non-ASCII character")
    elif isinstance(text, (bytes, bytearray, memoryview)):
        raw = bytes(text)
    else:
        raise Base45Error("unsupported input type")
    nchars = len(raw)
    if nchars % 3 == 1:
        raise Base45Error("dangling character")
    if max_decoded_length(nchars) > max_bytes:
        raise Base45Error("input too long")
    out = bytearray(max_decoded_length(nchars))
    o = 0
    i = 0
    table = _DECODE
    while i + 2 < nchars:
        c = table[raw[i]]
        d = table[raw[i + 1]]
        e = table[raw[i + 2]]
        if _INVALID in (c, d, e):
            raise Base45Error("invalid character")
        v = c + d * 45 + e * 2025
        if v > 0xFFFF:
            raise Base45Error("group value out of range")
        out[o] = v >> 8
        out[o + 1] = v & 0xFF
        o += 2
        i += 3
    if i < nchars:  # exactly two characters left (one was rejected above)
        c = table[raw[i]]
        d = table[raw[i + 1]]
        if _INVALID in (c, d):
            raise Base45Error("invalid character")
        v = c + d * 45
        if v > 0xFF:
            raise Base45Error("group value out of range")
        out[o] = v
    return bytes(out)


def is_alphabet(text) -> bool:
    """True if every character of ``text`` (str or bytes) is in the alphabet."""
    raw = text.encode() if isinstance(text, str) else bytes(text)
    if isinstance(text, str) and len(raw) != len(text):
        return False
    table = _DECODE
    return all(table[ch] != _INVALID for ch in raw)
