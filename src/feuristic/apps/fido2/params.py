# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Strict CTAP2 request parameter validation helpers.

CTAP 2.1 §8 (message encoding) requires authenticators to reject members of
the wrong CBOR type with ``CTAP2_ERR_CBOR_UNEXPECTED_TYPE`` and missing
required members with ``CTAP2_ERR_MISSING_PARAMETER``, while unknown map
keys are ignored. All helpers raise :class:`~.status.CtapError` accordingly.

Also contains UTF-8 helpers (truncation on code point boundaries, CTAP 2.1
§6.1.2 step "truncate to 64 bytes") that do not depend on the MicroPython
``str`` implementation details.
"""

from micropython import const

from ...core import cbor
from .status import (
    CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
    CTAP2_ERR_INVALID_CBOR,
    CTAP2_ERR_MISSING_PARAMETER,
    CtapError,
)

# CTAP 2.1 §8: requests nest at most 4 levels below the top-level map
# (makeCredential -> extensions -> hmac-secret -> keyAgreement -> value).
MAX_DEPTH = const(5)
MAX_ITEMS = const(1024)


def decode_request(data) -> dict:
    """Decode the CBOR parameter map of a CTAP2 command (bytes after the
    command byte). An empty input is an empty map."""
    if len(data) == 0:
        return {}
    try:
        obj = cbor.decode(data, max_depth=MAX_DEPTH, max_items=MAX_ITEMS)
    except cbor.CborError:
        raise CtapError(CTAP2_ERR_INVALID_CBOR)
    if not isinstance(obj, dict):
        raise CtapError(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
    return obj


def _check(value, kind):
    if kind == "int":
        ok = isinstance(value, int) and not isinstance(value, bool)
    elif kind == "uint":
        ok = isinstance(value, int) and not isinstance(value, bool) and value >= 0
    elif kind == "bytes":
        ok = isinstance(value, bytes)
    elif kind == "text":
        ok = isinstance(value, str)
    elif kind == "map":
        ok = isinstance(value, dict)
    elif kind == "list":
        ok = isinstance(value, list)
    elif kind == "bool":
        ok = isinstance(value, bool)
    else:  # pragma: no cover - programming error
        raise ValueError(kind)
    if not ok:
        raise CtapError(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
    return value


def get(params: dict, key, kind: str, required: bool = False):
    """Return ``params[key]`` checked against ``kind`` or ``None`` if absent."""
    if key not in params:
        if required:
            raise CtapError(CTAP2_ERR_MISSING_PARAMETER)
        return None
    return _check(params[key], kind)


def utf8_valid(raw: bytes) -> bool:
    """Strict UTF-8 validation (RFC 3629: no overlongs, no surrogates)."""
    i = 0
    n = len(raw)
    while i < n:
        b = raw[i]
        if b < 0x80:
            i += 1
            continue
        if 0xC2 <= b <= 0xDF:
            need, lo, hi = 1, 0x80, 0xBF
        elif b == 0xE0:
            need, lo, hi = 2, 0xA0, 0xBF
        elif 0xE1 <= b <= 0xEC or 0xEE <= b <= 0xEF:
            need, lo, hi = 2, 0x80, 0xBF
        elif b == 0xED:
            need, lo, hi = 2, 0x80, 0x9F
        elif b == 0xF0:
            need, lo, hi = 3, 0x90, 0xBF
        elif 0xF1 <= b <= 0xF3:
            need, lo, hi = 3, 0x80, 0xBF
        elif b == 0xF4:
            need, lo, hi = 3, 0x80, 0x8F
        else:
            return False
        if i + need >= n:
            return False
        if not lo <= raw[i + 1] <= hi:
            return False
        for j in range(2, need + 1):
            if not 0x80 <= raw[i + j] <= 0xBF:
                return False
        i += need + 1
    return True


def utf8_code_points(raw: bytes) -> int:
    """Number of code points of *valid* UTF-8 ``raw``."""
    count = 0
    for b in raw:
        if b & 0xC0 != 0x80:
            count += 1
    return count


def truncate_utf8(text: str, max_bytes: int) -> str:
    """Truncate ``text`` to at most ``max_bytes`` UTF-8 bytes without
    splitting a code point (CTAP 2.1 §6.1.2: authenticators MAY truncate
    rp.name, user.name and user.displayName to 64 bytes)."""
    raw = text.encode()
    if len(raw) <= max_bytes:
        return text
    cut = max_bytes
    while cut > 0 and raw[cut] & 0xC0 == 0x80:
        cut -= 1
    return raw[:cut].decode()


def raw_map_values(data) -> dict:
    """Map each top-level *integer* key of the CBOR map ``data`` to the exact
    encoded bytes of its value.

    Used where CTAP computes a MAC over the platform's encoding of a nested
    parameter (credentialManagement ``subCommandParams``, CTAP 2.1 §6.8.1)
    so that verification does not depend on re-encoding.
    """
    data = bytes(data)
    if not data or data[0] >> 5 != 5:
        raise CtapError(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
    info = data[0] & 0x1F
    pos = 1
    if info < 24:
        count = info
    elif info == 24 and len(data) > 1:
        count = data[1]
        pos = 2
    elif info == 25 and len(data) > 2:
        count = (data[1] << 8) | data[2]
        pos = 3
    else:
        raise CtapError(CTAP2_ERR_INVALID_CBOR)
    if count > MAX_ITEMS:
        raise CtapError(CTAP2_ERR_INVALID_CBOR)
    out = {}
    try:
        for _ in range(count):
            key, used = cbor.decode(data[pos:], max_depth=MAX_DEPTH, max_items=MAX_ITEMS, allow_trailing=True)
            pos += used
            _, used = cbor.decode(data[pos:], max_depth=MAX_DEPTH, max_items=MAX_ITEMS, allow_trailing=True)
            if isinstance(key, int) and not isinstance(key, bool):
                out[key] = data[pos : pos + used]
            pos += used
    except cbor.CborError:
        raise CtapError(CTAP2_ERR_INVALID_CBOR)
    return out
