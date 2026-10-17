# SPDX-License-Identifier: GPL-3.0-only
"""Fake backup providers and helpers shared by the backup/importer tests."""

from feuristic.apps.backup import envelope, provider
from feuristic.core.errors import InvalidInput, NotFound, PolicyDenied, StorageFull
from feuristic.platform import crypto

PASSPHRASE = b"correct horse battery staple"


class FakeProvider(provider.BackupProvider):
    """In-memory provider. Identities are keyed by ``name``.

    ``fail_on``: names whose restore raises StorageFull *before* writing
    (models an atomic provider refusing the write)."""

    def __init__(self, type_="fake", label_key="") -> None:
        self.TYPE = type_
        self.LABEL_KEY = label_key
        self.data = {}  # uid -> obj
        self.exported = []
        self.restored = []
        self.fail_on = set()
        self.fail_on_exported = False

    def add(self, name, secret=None):
        uid = crypto.sha256(name.encode())[:8]
        self.data[uid] = {
            "type": self.TYPE,
            "v": 1,
            "name": name,
            "secret": secret if secret is not None else crypto.sha256(b"s" + name.encode()),
        }
        return uid

    def _uid(self, obj):
        return crypto.sha256(obj["name"].encode())[:8]

    def snapshot(self):
        return {k: dict(v) for k, v in self.data.items()}

    # --- interface ---
    def list_identities(self):
        return [(uid, obj["name"]) for uid, obj in self.data.items()]

    def export_identity(self, uid):
        if uid not in self.data:
            raise NotFound("uid")
        return dict(self.data[uid])

    def validate(self, obj):
        super().validate(obj)
        if set(obj) != {"type", "v", "name", "secret"}:
            raise InvalidInput("fields")
        if not isinstance(obj["name"], str) or not 1 <= len(obj["name"]) <= 64:
            raise InvalidInput("name")
        if not isinstance(obj["secret"], bytes) or len(obj["secret"]) != 32:
            raise InvalidInput("secret")

    def exists(self, obj):
        return self._uid(obj) in self.data

    def describe(self, obj):
        return obj["name"], crypto.sha256(obj["secret"])[:8].hex()

    def restore_identity(self, obj, overwrite):
        uid = self._uid(obj)
        if uid in self.data and not overwrite:
            raise PolicyDenied("exists")
        if obj["name"] in self.fail_on:
            raise StorageFull("full")
        self.data[uid] = dict(obj)
        self.restored.append(obj["name"])
        return uid

    def on_exported(self, uid):
        if self.fail_on_exported:
            raise StorageFull("cannot record BS flag")
        self.exported.append(uid)


class DuckProvider:
    """Duck-typed provider without validate() (like apps/otp/provider.py)."""

    TYPE = "duck"
    LABEL_KEY = ""

    def __init__(self) -> None:
        self.data = {}

    def list_identities(self):
        return [(k, v["n"]) for k, v in self.data.items()]

    def export_identity(self, uid):
        return dict(self.data[uid])

    def exists(self, obj):
        return obj["n"].encode() in self.data

    def describe(self, obj):
        return obj["n"], ""

    def restore_identity(self, obj, overwrite):
        self.data[obj["n"].encode()] = dict(obj)
        return obj["n"].encode()

    def on_exported(self, uid):
        pass


def passphrases(*values):
    """Async get_passphrase callback replaying ``values``; records requests."""
    queue = list(values)
    calls = []

    async def get(req):
        calls.append(req)
        if not queue:
            raise AssertionError("unexpected passphrase request")
        v = queue.pop(0)
        return bytearray(v) if isinstance(v, bytes) else v

    get.calls = calls
    return get


def make_raw_envelope(key, salt, plaintext: bytes, kind=1, backup_id=b"\x01" * 8, nonce=b"\x02" * 12):
    """Encrypt arbitrary plaintext bytes under a valid header (for schema tests)."""
    aad = envelope.encode_header(kind, backup_id, salt, nonce)
    ct, tag = crypto.aes256_gcm_encrypt(bytes(key), nonce, plaintext, aad)
    return aad + ct + tag
