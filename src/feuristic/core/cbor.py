# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Bounded CBOR (RFC 8949) encoder/decoder.

* :func:`encode` always produces **deterministic (canonical) encoding**
  (RFC 8949 §4.2.1 "core deterministic encoding"): shortest-form integers and
  lengths, definite lengths only, map keys sorted by the bytewise
  lexicographic order of their encodings. This is also the CTAP2 canonical
  form (CTAP 2.1 §8) because CTAP keys are small ints and short text strings.
* :func:`decode` accepts the subset needed by CTAP2 and feuristic backups:
  unsigned/negative ints (≤ 64 bit), byte/text strings, arrays, maps,
  ``false``/``true``/``null``, and tag 24 is rejected. Floats and indefinite
  lengths are rejected. Depth, item count and total size are bounded.
  ``canonical=True`` additionally rejects any non-deterministic encoding,
  which feuristic uses for backup envelopes (malleability resistance).

Python mapping: ``int``, ``bytes``, ``str``, ``list``/``tuple`` (encode),
``list`` (decode), ``dict``, ``bool``, ``None``.
"""

from micropython import const

from .errors import InvalidInput

_MT_UINT = const(0)
_MT_NINT = const(1)
_MT_BYTES = const(2)
_MT_TEXT = const(3)
_MT_ARRAY = const(4)
_MT_MAP = const(5)
_MT_TAG = const(6)
_MT_SIMPLE = const(7)

DEFAULT_MAX_DEPTH = const(8)
DEFAULT_MAX_ITEMS = const(2048)

_UINT64_MAX = 0xFFFFFFFFFFFFFFFF


class CborError(InvalidInput):
    """Malformed, unsupported or non-canonical CBOR."""


# ---------------------------------------------------------------------------
# encoding
# ---------------------------------------------------------------------------


def _head(major: int, value: int) -> bytes:
    if value < 24:
        return bytes(((major << 5) | value,))
    if value < 0x100:
        return bytes(((major << 5) | 24, value))
    if value < 0x10000:
        return bytes(((major << 5) | 25,)) + value.to_bytes(2, "big")
    if value < 0x100000000:
        return bytes(((major << 5) | 26,)) + value.to_bytes(4, "big")
    if value <= _UINT64_MAX:
        return bytes(((major << 5) | 27,)) + value.to_bytes(8, "big")
    raise CborError("integer too large")


def _encode_into(out: list, obj) -> None:
    # bool must be tested before int (bool is a subclass of int on CPython)
    if obj is False:
        out.append(b"\xf4")
    elif obj is True:
        out.append(b"\xf5")
    elif obj is None:
        out.append(b"\xf6")
    elif isinstance(obj, int):
        if obj >= 0:
            out.append(_head(_MT_UINT, obj))
        else:
            out.append(_head(_MT_NINT, -1 - obj))
    elif isinstance(obj, (bytes, bytearray, memoryview)):
        b = bytes(obj)
        out.append(_head(_MT_BYTES, len(b)))
        out.append(b)
    elif isinstance(obj, str):
        b = obj.encode()
        out.append(_head(_MT_TEXT, len(b)))
        out.append(b)
    elif isinstance(obj, (list, tuple)):
        out.append(_head(_MT_ARRAY, len(obj)))
        for item in obj:
            _encode_into(out, item)
    elif isinstance(obj, dict):
        items = []
        for k, v in obj.items():
            if k is None or k is True or k is False or not isinstance(k, (int, str, bytes)):
                raise CborError("unsupported map key type")
            ek = encode(k)
            items.append((ek, v))
        items.sort(key=lambda kv: kv[0])
        for i in range(1, len(items)):
            if items[i][0] == items[i - 1][0]:
                raise CborError("duplicate map key")
        out.append(_head(_MT_MAP, len(items)))
        for ek, v in items:
            out.append(ek)
            _encode_into(out, v)
    else:
        raise CborError("unsupported type")


def encode_parts(obj) -> list:
    """Return deterministic CBOR chunks without joining a second full copy.

    Bytes-like input is snapshotted by the encoder, as with :func:`encode`.
    The returned list can be hashed or copied directly into a bounded buffer.
    """
    out = []
    _encode_into(out, obj)
    return out


def encode(obj) -> bytes:
    """Encode ``obj`` in deterministic CBOR."""
    return b"".join(encode_parts(obj))


# ---------------------------------------------------------------------------
# decoding
# ---------------------------------------------------------------------------


class _Reader:
    def __init__(self, data, max_depth: int, max_items: int, canonical: bool) -> None:
        self.data = data
        self.pos = 0
        self.max_depth = max_depth
        self.items_left = max_items
        self.canonical = canonical

    def take(self, n: int):
        end = self.pos + n
        if n < 0 or end > len(self.data):
            raise CborError("truncated")
        chunk = self.data[self.pos : end]
        self.pos = end
        return chunk

    def head(self):
        ib = self.take(1)[0]
        major = ib >> 5
        info = ib & 0x1F
        if info < 24:
            return major, info, ib
        if info == 24:
            v = self.take(1)[0]
            if self.canonical and v < 24:
                raise CborError("non-canonical integer")
        elif info == 25:
            v = int.from_bytes(self.take(2), "big")
            if self.canonical and v < 0x100:
                raise CborError("non-canonical integer")
        elif info == 26:
            v = int.from_bytes(self.take(4), "big")
            if self.canonical and v < 0x10000:
                raise CborError("non-canonical integer")
        elif info == 27:
            v = int.from_bytes(self.take(8), "big")
            if self.canonical and v < 0x100000000:
                raise CborError("non-canonical integer")
        else:
            # 28..30 reserved, 31 indefinite length: both unsupported
            raise CborError("unsupported additional info")
        return major, v, ib

    def item(self, depth: int):
        self.items_left -= 1
        if self.items_left < 0:
            raise CborError("too many items")
        if depth > self.max_depth:
            raise CborError("nesting too deep")
        major, val, ib = self.head()
        if major == _MT_UINT:
            return val
        if major == _MT_NINT:
            return -1 - val
        if major == _MT_BYTES:
            return bytes(self.take(val))
        if major == _MT_TEXT:
            raw = bytes(self.take(val))
            try:
                return raw.decode()
            except UnicodeError:
                raise CborError("invalid UTF-8")
        if major == _MT_ARRAY:
            if val > self.items_left:
                raise CborError("too many items")
            return [self.item(depth + 1) for _ in range(val)]
        if major == _MT_MAP:
            if 2 * val > self.items_left:
                raise CborError("too many items")
            result = {}
            prev_key_enc = None
            for _ in range(val):
                kstart = self.pos
                k = self.item(depth + 1)
                kenc = self.data[kstart : self.pos]
                if isinstance(k, (list, dict)):
                    raise CborError("unsupported map key type")
                if self.canonical and prev_key_enc is not None and bytes(kenc) <= bytes(prev_key_enc):
                    raise CborError("map keys not in canonical order")
                prev_key_enc = kenc
                if k in result:
                    raise CborError("duplicate map key")
                result[k] = self.item(depth + 1)
            return result
        if major == _MT_TAG:
            raise CborError("tags not supported")
        # major 7: simple values / floats
        if ib == 0xF4:
            return False
        if ib == 0xF5:
            return True
        if ib == 0xF6:
            return None
        raise CborError("unsupported simple value")


def decode(
    data,
    *,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_items: int = DEFAULT_MAX_ITEMS,
    canonical: bool = False,
    allow_trailing: bool = False,
):
    """Decode one CBOR item from ``data``.

    Raises :class:`CborError` on any malformed/unsupported/non-canonical input
    and (unless ``allow_trailing``) when bytes remain after the item.
    With ``allow_trailing=True`` returns ``(item, consumed_length)``.
    """
    r = _Reader(memoryview(data), max_depth, max_items, canonical)
    obj = r.item(0)
    if allow_trailing:
        return obj, r.pos
    if r.pos != len(data):
        raise CborError("trailing bytes")
    return obj
