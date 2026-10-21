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


def _encode_into(out: list, obj, borrow_bytes=False) -> None:
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
        b = obj if borrow_bytes else bytes(obj)
        out.append(_head(_MT_BYTES, len(b)))
        out.append(b)
    elif isinstance(obj, str):
        b = obj.encode()
        out.append(_head(_MT_TEXT, len(b)))
        out.append(b)
    elif isinstance(obj, (list, tuple)):
        out.append(_head(_MT_ARRAY, len(obj)))
        for item in obj:
            _encode_into(out, item, borrow_bytes)
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
            _encode_into(out, v, borrow_bytes)
    else:
        raise CborError("unsupported type")


def encode_parts(obj, borrow_bytes=False) -> list:
    """Return deterministic CBOR chunks without joining a second full copy.

    Bytes-like input is snapshotted by the encoder, as with :func:`encode`.
    The returned list can be hashed or copied directly into a bounded buffer.
    ``borrow_bytes=True`` avoids copies for immediate synchronous consumption;
    the caller must keep those buffers alive and unchanged until consumed.
    """
    out = []
    _encode_into(out, obj, borrow_bytes)
    return out


def iter_encode(obj, borrow_bytes=False):
    """Yield canonical chunks without retaining a list for a large array."""
    if obj is False or obj is True or obj is None or isinstance(obj, int):
        parts = []
        _encode_into(parts, obj)
        yield from parts
    elif isinstance(obj, (bytes, bytearray, memoryview)):
        data = obj if borrow_bytes else bytes(obj)
        yield _head(_MT_BYTES, len(data))
        yield data
    elif isinstance(obj, str):
        data = obj.encode()
        yield _head(_MT_TEXT, len(data))
        yield data
    elif isinstance(obj, (list, tuple)):
        yield _head(_MT_ARRAY, len(obj))
        for item in obj:
            yield from iter_encode(item, borrow_bytes)
    elif isinstance(obj, dict):
        items = []
        for key, value in obj.items():
            if key is None or key is True or key is False or not isinstance(key, (int, str, bytes)):
                raise CborError("unsupported map key type")
            items.append((encode(key), value))
        items.sort(key=lambda item: item[0])
        for index in range(1, len(items)):
            if items[index][0] == items[index - 1][0]:
                raise CborError("duplicate map key")
        yield _head(_MT_MAP, len(items))
        for key, value in items:
            yield key
            yield from iter_encode(value, borrow_bytes)
    else:
        raise CborError("unsupported type")


def encode(obj) -> bytes:
    """Encode ``obj`` in deterministic CBOR."""
    return b"".join(encode_parts(obj))


def encode_into(obj, buffer, offset=0):
    """Encode into an owned buffer; input must not alias the destination.

    Validate and check capacity before mutation, then stream canonical chunks.
    """
    size = sum(len(part) for part in iter_encode(obj, borrow_bytes=True))
    if offset < 0 or offset + size > len(buffer):
        raise CborError("encoding buffer too small")
    position = offset
    for part in iter_encode(obj, borrow_bytes=True):
        buffer[position : position + len(part)] = part
        position += len(part)
    return memoryview(buffer)[offset:position]


# ---------------------------------------------------------------------------
# decoding
# ---------------------------------------------------------------------------


class _Reader:
    def __init__(self, data, max_depth: int, max_items: int, canonical: bool, bytes_view=False) -> None:
        self.data = data
        self.pos = 0
        self.max_depth = max_depth
        self.items_left = max_items
        self.canonical = canonical
        self.bytes_view = bytes_view

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
            value = self.take(val)
            return value if self.bytes_view else bytes(value)
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
                if isinstance(k, memoryview):
                    k = bytes(k)  # Map keys remain hashable in view mode.
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
    bytes_view: bool = False,
):
    """Decode one CBOR item from ``data``.

    Raises :class:`CborError` on any malformed/unsupported/non-canonical input
    and (unless ``allow_trailing``) when bytes remain after the item.
    With ``allow_trailing=True`` returns ``(item, consumed_length)``.
    """
    r = _Reader(memoryview(data), max_depth, max_items, canonical, bytes_view)
    obj = r.item(0)
    if allow_trailing:
        return obj, r.pos
    if r.pos != len(data):
        raise CborError("trailing bytes")
    return obj


def array_items(data, *, max_depth=DEFAULT_MAX_DEPTH, max_items=DEFAULT_MAX_ITEMS):
    """Yield (decoded item, encoded view) without retaining the whole array."""
    if max_depth < 0 or max_items < 1:
        raise CborError("expected bounded array")
    reader = _Reader(memoryview(data), max_depth, max_items, False, True)
    major, count, _ = reader.head()
    reader.items_left -= 1
    if major != _MT_ARRAY or count > reader.items_left:
        raise CborError("expected bounded array")
    for _ in range(count):
        start = reader.pos
        value = reader.item(1)
        yield value, reader.data[start : reader.pos]
    if reader.pos != len(data):
        raise CborError("trailing bytes")
