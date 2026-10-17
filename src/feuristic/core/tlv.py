# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""BER-TLV as used by ISO/IEC 7816-4 smart-card applications (OpenPGP, PIV).

Tags are returned as integers of their full encoding (e.g. ``0x5F50``,
``0x7F49``, ``0x9F7F``). Supported: tag numbers up to 3 bytes, definite
lengths up to ``0x82 xx xx`` (65535). Indefinite lengths are rejected.
"""

from micropython import const

from .errors import InvalidInput

MAX_LEN = const(0xFFFF)


class TlvError(InvalidInput):
    """Malformed BER-TLV."""


def encode_tag(tag: int) -> bytes:
    if tag <= 0xFF:
        return bytes((tag,))
    if tag <= 0xFFFF:
        return tag.to_bytes(2, "big")
    if tag <= 0xFFFFFF:
        return tag.to_bytes(3, "big")
    raise TlvError("tag too large")


def encode_len(n: int) -> bytes:
    if n < 0x80:
        return bytes((n,))
    if n <= 0xFF:
        return bytes((0x81, n))
    if n <= MAX_LEN:
        return bytes((0x82,)) + n.to_bytes(2, "big")
    raise TlvError("length too large")


def build(tag: int, value: bytes) -> bytes:
    """Encode a single TLV."""
    return encode_tag(tag) + encode_len(len(value)) + bytes(value)


def build_many(items) -> bytes:
    """Encode an iterable of ``(tag, value)`` pairs, concatenated."""
    return b"".join(build(t, v) for t, v in items)


def _read_tag(data, pos: int):
    end = len(data)
    if pos >= end:
        raise TlvError("truncated tag")
    first = data[pos]
    pos += 1
    tag = first
    if first & 0x1F == 0x1F:
        # multi-byte tag number: continuation bit 0x80 on subsequent bytes
        for i in range(2):
            if pos >= end:
                raise TlvError("truncated tag")
            b = data[pos]
            pos += 1
            tag = (tag << 8) | b
            if not b & 0x80:
                break
            if i == 1:
                raise TlvError("tag too long")
    return tag, pos


def _read_len(data, pos: int):
    end = len(data)
    if pos >= end:
        raise TlvError("truncated length")
    b = data[pos]
    pos += 1
    if b < 0x80:
        return b, pos
    if b == 0x81:
        if pos + 1 > end:
            raise TlvError("truncated length")
        return data[pos], pos + 1
    if b == 0x82:
        if pos + 2 > end:
            raise TlvError("truncated length")
        return (data[pos] << 8) | data[pos + 1], pos + 2
    raise TlvError("unsupported length form")


def iterate(data):
    """Yield ``(tag, value)`` for each top-level TLV in ``data`` (strict)."""
    data = memoryview(bytes(data))
    pos = 0
    end = len(data)
    while pos < end:
        # ISO 7816 allows 0x00/0xFF padding between TLVs only in some
        # contexts; feuristic is strict and treats them as tags (rejected
        # by callers that do not expect them).
        tag, pos = _read_tag(data, pos)
        length, pos = _read_len(data, pos)
        if pos + length > end:
            raise TlvError("value overruns buffer")
        yield tag, bytes(data[pos : pos + length])
        pos += length


def parse(data) -> list:
    """Return the list of top-level ``(tag, value)`` pairs."""
    return list(iterate(data))


def find(data, tag: int):
    """Return the value of the first top-level TLV with ``tag``, or ``None``."""
    for t, v in iterate(data):
        if t == tag:
            return v
    return None


def is_constructed(tag: int) -> bool:
    """True if the first tag byte has the 'constructed' bit (0x20) set."""
    first = tag
    while first > 0xFF:
        first >>= 8
    return bool(first & 0x20)
