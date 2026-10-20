# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""authenticatorLargeBlobs (CTAP 2.1 §6.10).

The serialized large-blob array (CBOR array || LEFT(SHA-256(array), 16)) is
stored as one :class:`~feuristic.core.store.Blob` in ``FIDO_STATE``
(keys ``FIDO_STATE_LARGEBLOB`` A/B), so a new array becomes visible
atomically and only after its integrity check succeeded (§6.10.2 step
"if the hash matches, commit"). Its size is capped at
:data:`MAX_SERIALIZED` = 4096 bytes (product spec §5), the value of
``maxSerializedLargeBlobArray`` in authenticatorGetInfo. The pending write
buffer is bounded by the same cap.
"""

from micropython import const

from ...core import cbor, namespaces
from ...core.errors import StorageFull
from ...core.store import Blob
from ...platform import crypto
from . import params as prm
from .clientpin import PERM_LBW
from .status import (
    CTAP1_ERR_INVALID_LENGTH,
    CTAP1_ERR_INVALID_PARAMETER,
    CTAP1_ERR_INVALID_SEQ,
    CTAP2_ERR_INTEGRITY_FAILURE,
    CTAP2_ERR_LARGE_BLOB_STORAGE_FULL,
    CTAP2_ERR_MISSING_PARAMETER,
    CTAP2_ERR_PIN_AUTH_INVALID,
    CTAP2_ERR_PUAT_REQUIRED,
    CtapError,
)

MAX_SERIALIZED = const(4096)
MIN_SERIALIZED = const(17)

_P_GET = const(0x01)
_P_SET = const(0x02)
_P_OFFSET = const(0x03)
_P_LENGTH = const(0x04)
_P_PIN_UV_AUTH_PARAM = const(0x05)
_P_PIN_UV_AUTH_PROTOCOL = const(0x06)
R_CONFIG = const(0x01)


def _serialized_parts(entries):
    parts = cbor.encode_parts(entries)
    digest = crypto.Sha256()
    for part in parts:
        digest.update(part)
    parts.append(digest.digest()[:16])
    return parts


def serialize(entries: list) -> bytes:
    return b"".join(_serialized_parts(entries))


# h'80' || LEFT(SHA-256(h'80'), 16): the initial (empty) serialized array
EMPTY_ARRAY = b"\x80\x76\xbe\x8b\x52\x8d\x00\x75\xf7\xaa\xe9\x8d\x6f\xa5\x7a\x6d\x3c"


def check_integrity(serialized: bytes) -> bool:
    if len(serialized) < MIN_SERIALIZED:
        return False
    view = memoryview(serialized)
    return crypto.ct_equal(crypto.sha256(view[:-16])[:16], view[-16:])


def entry_belongs_to(entry, key: bytes) -> bool:
    """True if the large-blob array item ``entry`` decrypts under the
    credential's ``largeBlobKey`` (WebAuthn L3 §10.1.5: AES-256-GCM,
    AAD = "blob" || uint64LE(origSize))."""
    if not isinstance(entry, dict):
        return False
    ct = entry.get(1)
    nonce = entry.get(2)
    size = entry.get(3)
    if (
        not isinstance(ct, bytes)
        or not isinstance(nonce, bytes)
        or not isinstance(size, int)
        or isinstance(size, bool)
        or len(nonce) != 12
        or len(ct) < 16
        or not 0 <= size < 1 << 64
    ):
        return False
    try:
        crypto.aes256_gcm_decrypt(key, nonce, ct[:-16], ct[-16:], b"blob" + size.to_bytes(8, "little"))
    except MemoryError:
        # A failed ownership check must never silently omit backup data or
        # allow credential deletion while leaving its blobs behind.
        raise
    except Exception:
        return False
    return True


class LargeBlobs:
    def __init__(self, pin, max_fragment: int) -> None:
        self.pin = pin
        self.max_fragment = max_fragment
        self.blob = Blob(
            namespaces.FIDO_STATE,
            namespaces.FIDO_STATE_LARGEBLOB,
            namespaces.FIDO_STATE_LARGEBLOB + 1,
            MAX_SERIALIZED,
        )
        self._abort_write()

    def _abort_write(self) -> None:
        self._pending = None
        self._write_head = None
        self._expected_len = 0
        self._next_offset = 0

    def _read_view(self):
        data = self.blob.get_view()
        if data is None or not check_integrity(data):
            return memoryview(EMPTY_ARRAY)
        return data

    def read(self) -> bytes:
        """The current serialized array (initial empty array if none)."""
        return bytes(self._read_view())

    def entries(self) -> list:
        """Decoded array items (list of maps) — used by the backup provider."""
        data = self._read_view()
        try:
            items = cbor.decode(data[:-16], max_depth=3, max_items=1024)
        except cbor.CborError:
            return []
        return items if isinstance(items, list) else []

    def write_entries(self, entries: list) -> None:
        """Atomically replace the array (local use: backup restore).
        Raises ``StorageFull`` if the serialized array exceeds the cap."""
        # This operation is synchronous: read metadata before allocating the
        # new full array, rather than keeping both A/B payloads beside it.
        generation, key = self.blob._head()
        parts = _serialized_parts(entries)
        length = sum(len(part) for part in parts)
        if length > MAX_SERIALIZED:
            raise StorageFull("largeBlob array full")
        data = bytearray(4 + length)
        offset = 4
        for part in parts:
            data[offset : offset + len(part)] = part
            offset += len(part)
        parts = None
        self.blob._commit(data, generation, key)
        self._abort_write()

    def reset(self) -> None:
        self.blob.clear()
        self._abort_write()

    def handle(self, req: dict) -> dict:
        get = prm.get(req, _P_GET, "uint")
        data = prm.get(req, _P_SET, "bytes")
        offset = prm.get(req, _P_OFFSET, "uint")
        length = prm.get(req, _P_LENGTH, "uint")
        param = prm.get(req, _P_PIN_UV_AUTH_PARAM, "bytes")
        proto = prm.get(req, _P_PIN_UV_AUTH_PROTOCOL, "uint")
        if offset is None:
            raise CtapError(CTAP2_ERR_MISSING_PARAMETER)
        if (get is None) == (data is None):
            raise CtapError(CTAP1_ERR_INVALID_PARAMETER)
        if get is not None:
            if length is not None:
                raise CtapError(CTAP1_ERR_INVALID_PARAMETER)
            if get > self.max_fragment:
                raise CtapError(CTAP1_ERR_INVALID_LENGTH)
            current = self._read_view()
            if offset > len(current):
                raise CtapError(CTAP1_ERR_INVALID_PARAMETER)
            return {R_CONFIG: bytes(current[offset : offset + get])}
        return self._set(data, offset, length, param, proto)

    def _set(self, data: bytes, offset: int, length, param, proto) -> dict:
        if len(data) > self.max_fragment:
            raise CtapError(CTAP1_ERR_INVALID_LENGTH)
        if offset == 0:
            if length is None:
                raise CtapError(CTAP1_ERR_INVALID_PARAMETER)
            if length > MAX_SERIALIZED:
                raise CtapError(CTAP2_ERR_LARGE_BLOB_STORAGE_FULL)
            if length < MIN_SERIALIZED:
                raise CtapError(CTAP1_ERR_INVALID_PARAMETER)
            self._abort_write()
            self._expected_len = length
        else:
            if length is not None:
                raise CtapError(CTAP1_ERR_INVALID_PARAMETER)
            if self._pending is None or offset != self._next_offset:
                raise CtapError(CTAP1_ERR_INVALID_SEQ)
        if self.pin.state.pin_is_set() or param is not None:
            if param is None:
                raise CtapError(CTAP2_ERR_PUAT_REQUIRED)
            if proto is None:
                raise CtapError(CTAP2_ERR_MISSING_PARAMETER)
            self.pin.protocol(proto)
            msg = b"\xff" * 32 + b"\x0c\x00" + offset.to_bytes(4, "little") + crypto.sha256(data)
            if not self.pin.verify_token(proto, msg, param) or not self.pin.has_permission(PERM_LBW):
                raise CtapError(CTAP2_ERR_PIN_AUTH_INVALID)
        if offset + len(data) > self._expected_len:
            raise CtapError(CTAP1_ERR_INVALID_PARAMETER)
        if offset == 0:
            # All local array replacements/reset invalidate this pending
            # write. Capture its A/B head before allocating the receive buffer;
            # no other writer to these keys exists in a live NORMAL session.
            self._write_head = self.blob._head()
            self._pending = bytearray(4 + self._expected_len)
        self._pending[4 + offset : 4 + offset + len(data)] = data
        self._next_offset = offset + len(data)
        if self._next_offset == self._expected_len:
            buf = self._pending
            generation, key = self._write_head
            self._abort_write()
            if not check_integrity(memoryview(buf)[4:]):
                raise CtapError(CTAP2_ERR_INTEGRITY_FAILURE)
            try:
                self.blob._commit(buf, generation, key)
            except StorageFull:
                raise CtapError(CTAP2_ERR_LARGE_BLOB_STORAGE_FULL)
        return {}
