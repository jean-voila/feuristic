# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Backup provider for AES-256-GCM keys (spec §8.2, §8.3; R12).

One identity per key. Normative schema: ``docs/protocols/backup-aes.md``::

    aes-identity = {
      "type": "aes", "v": 1,
      "id": 1..16,                  ; key identifier used in MSE (83/84)
      "name": tstr .size (1..16),   ; printable ASCII
      "key": bstr .size 32,
      "enabled": bool,
      "policy": 0 / 1,              ; 0 confirm every operation, 1 once per session
      "nonce_floor": uint,          ; source device nonce counter at export
    }

``nonce_floor`` lets the restoring device move its global nonce counter past
every value the source device had reserved when the backup was made, so a
restored key never reuses a counter value of its past on either device's
counter range; the 64-bit device/key/epoch namespace separates the two devices
(see backup-aes for the residual 2⁻⁶⁴ per-pair namespace collision bound).
"""

from micropython import const

from ....core.errors import InvalidInput, NotFound, PolicyDenied
from ...backup.provider import BackupProvider
from . import keys as _keys
from . import strings

strings.register()

SCHEMA_VERSION = const(1)
_FIELDS = ("type", "v", "id", "name", "key", "enabled", "policy", "nonce_floor")


def _check(obj) -> None:
    if not isinstance(obj, dict) or obj.get("type") != "aes":
        raise InvalidInput("aes backup type")
    v = obj.get("v")
    if isinstance(v, bool) or v != SCHEMA_VERSION:
        raise InvalidInput("aes backup version")
    if len(obj) != len(_FIELDS) or any(k not in obj for k in _FIELDS):
        raise InvalidInput("aes backup fields")
    _keys.check_kid(obj["id"])
    _keys.check_name(obj["name"])
    _keys.check_policy(obj["policy"])
    key = obj["key"]
    if not isinstance(key, (bytes, bytearray)) or len(key) != _keys.KEY_LEN:
        raise InvalidInput("aes backup key")
    if not isinstance(obj["enabled"], bool):
        raise InvalidInput("aes backup enabled")
    floor = obj["nonce_floor"]
    if isinstance(floor, bool) or not isinstance(floor, int) or not 0 <= floor <= 0xFFFFFFFFFFFFFFFF:
        raise InvalidInput("aes backup nonce floor")


def _uid(kid: int) -> bytes:
    return b"AESkey" + bytes((0, kid))


class AesBackupProvider(BackupProvider):
    TYPE = "aes"
    LABEL_KEY = "aes.title"

    def __init__(self, store=None) -> None:
        self._store = store

    @property
    def store(self):
        return _keys.default() if self._store is None else self._store

    def list_identities(self) -> list:
        return [(_uid(k.kid), f"AES #{k.kid} {k.name}") for k in self.store.entries()]

    def _kid(self, uid) -> int:
        uid = bytes(uid)
        if len(uid) != 8 or uid[:7] != b"AESkey\x00" or not 1 <= uid[7] <= _keys.MAX_KEYS:
            raise NotFound
        return uid[7]

    def export_identity(self, uid) -> dict:
        k = self.store.get(self._kid(uid))
        if k is None:
            raise NotFound
        return {
            "type": self.TYPE,
            "v": SCHEMA_VERSION,
            "id": k.kid,
            "name": k.name,
            "key": k.key,
            "enabled": k.enabled,
            "policy": k.policy,
            "nonce_floor": self.store.nonce_floor(),
        }

    def validate(self, obj) -> None:
        super().validate(obj)
        _check(obj)

    def exists(self, obj) -> bool:
        _check(obj)
        return self.store.get(obj["id"]) is not None

    def describe(self, obj) -> tuple:
        _check(obj)
        return f"AES #{obj['id']} {obj['name']}", _keys.key_check_value(obj["key"])

    def restore_identity(self, obj, overwrite: bool) -> bytes:
        _check(obj)
        if self.exists(obj) and not overwrite:
            raise PolicyDenied("AES key id in use")
        # counter first: if power is lost afterwards the key is simply absent
        self.store.raise_nonce_floor(obj["nonce_floor"])
        k = self.store.put_restored(obj["id"], obj["key"], obj["name"], obj["enabled"], obj["policy"])
        return _uid(k.kid)

    def on_exported(self, uid) -> None:
        return
