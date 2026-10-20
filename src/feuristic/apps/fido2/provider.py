# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Backup provider for discoverable FIDO2 credentials (spec §8.2, §8.3;
interface: ``feuristic.apps.backup.provider.BackupProvider``).

One identity = one discoverable credential (record uid). Item schema
(CDDL, RFC 8610), version 1::

    fido2-identity = {
      "type": "fido2", "v": 1,
      "cred_id": bstr .size 13,          ; 0x01 | uid(8) | seq(4): kept on restore
      "rp_id": tstr .size (1..128),
      "user_id": bstr .size (0..64),
      ? "user_name": tstr .size (1..64),
      ? "display_name": tstr .size (1..64),
      "alg": -7 / -8,
      "key": bstr .size 32,              ; P-256 scalar or Ed25519 seed
      "cred_protect": 1..3,
      "hmac_secret": bool,
      "large_blob": bool,
      "sign_count": uint,                ; global counter at export time
      "large_blobs": [* bstr],           ; canonical CBOR of each largeBlob
                                         ; array item encrypted for this
                                         ; credential (≤ 4096 B in total)
    }

Design notes:

* hmac-secret ``CredRandom`` values and the ``largeBlobKey`` derive from the
  private key (see :mod:`.credentials`), so they survive a restore.
* largeBlob data: the shared array is opaque, but each item is encrypted
  under one credential's largeBlobKey, so the provider exports, *per
  identity*, the items that decrypt under that credential's key ("données
  largeBlobs associées"). Restoring merges them into the array (duplicates
  skipped). Items belonging to no stored credential are not exported.
* The signature counter is global: restoring raises it to at least the
  exported value so relying parties never see it go backwards.
* Restored credentials carry BE = 1 and BS = 1; :meth:`on_exported` sets
  BS = 1 on the exported credential (WebAuthn L3 backup state).
* Order of writes on restore: counter, largeBlob array, credential record.
  Each write is atomic; a power cut can at worst leave harmless extra
  largeBlob items, never a partial credential.
"""

from micropython import const

from ...core import cbor
from ...core.errors import InvalidInput, NotFound, PolicyDenied, StorageFull
from ...platform import crypto
from ..backup import provider as bp
from . import credentials as cr
from .largeblobs import MAX_SERIALIZED, entry_belongs_to, serialize

SCHEMA_VERSION = const(1)
MAX_LARGE_BLOB_ITEMS = const(64)

_REQUIRED = (
    "type",
    "v",
    "cred_id",
    "rp_id",
    "user_id",
    "alg",
    "key",
    "cred_protect",
    "hmac_secret",
    "large_blob",
    "sign_count",
    "large_blobs",
)
_OPTIONAL = ("user_name", "display_name")


def _label(rp_id: str, account: str) -> str:
    text = rp_id + " — " + account
    raw = text.encode()
    if len(raw) <= bp.LABEL_MAX_BYTES:
        return text
    cut = bp.LABEL_MAX_BYTES
    while cut > 0 and raw[cut] & 0xC0 == 0x80:
        cut -= 1
    return raw[:cut].decode()


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


class Fido2BackupProvider(bp.BackupProvider):
    TYPE = "fido2"
    LABEL_KEY = "fido2.app"

    def __init__(self, auth) -> None:
        self.auth = auth

    # -- export ----------------------------------------------------------------
    def iter_uids(self):
        return iter(self.auth.store.uids())

    def identity_label(self, uid):
        credential = self.auth.store.get(uid)
        if credential is None:
            raise NotFound("credential")
        return _label(credential.rp_id, credential.label())

    def list_identities(self) -> list:
        out = []
        for rp_id, h, _n in self.auth.store.rps():
            for c in self.auth.store.for_rp(h):
                out.append((c.uid, _label(rp_id, c.label())))
        return out

    def export_identity(self, uid: bytes) -> dict:
        cred = self.auth.store.get(uid)
        if cred is None:
            raise NotFound("credential")
        obj = {
            "type": self.TYPE,
            "v": SCHEMA_VERSION,
            "cred_id": cred.cred_id,
            "rp_id": cred.rp_id,
            "user_id": cred.user_id,
            "alg": cred.alg,
            "key": cred.key,
            "cred_protect": cred.cred_protect,
            "hmac_secret": cred.hmac_secret,
            "large_blob": cred.large_blob,
            "sign_count": self.auth.state.signature_counter(),
            "large_blobs": [],
        }
        if cred.user_name:
            obj["user_name"] = cred.user_name
        if cred.display_name:
            obj["display_name"] = cred.display_name
        key = cred.large_blob_key()
        if key is not None:
            obj["large_blobs"] = [
                cbor.encode(e) for e in self.auth.large_blobs.entries() if entry_belongs_to(e, key)
            ]
        return obj

    def on_exported(self, uid: bytes) -> None:
        self.auth.store.set_backup_state(uid)

    # -- validation ------------------------------------------------------------
    def validate(self, obj: dict) -> None:
        super().validate(obj)
        if obj.get("v") != SCHEMA_VERSION:
            raise InvalidInput("fido2 item version")
        for k in _REQUIRED:
            if k not in obj:
                raise InvalidInput("fido2 item field missing")
        for k in obj:
            if k not in _REQUIRED and k not in _OPTIONAL:
                raise InvalidInput("fido2 item unknown field")
        cid = obj["cred_id"]
        if not isinstance(cid, bytes) or len(cid) != cr.RESIDENT_ID_LEN or cid[0] != cr.ID_RESIDENT:
            raise InvalidInput("fido2 cred_id")
        rp_id = obj["rp_id"]
        if not isinstance(rp_id, str) or not 0 < len(rp_id.encode()) <= cr.MAX_RP_ID_LEN:
            raise InvalidInput("fido2 rp_id")
        uid = obj["user_id"]
        if not isinstance(uid, bytes) or len(uid) > cr.MAX_USER_ID_LEN:
            raise InvalidInput("fido2 user_id")
        for k in _OPTIONAL:
            v = obj.get(k)
            if v is not None and (not isinstance(v, str) or not 0 < len(v.encode()) <= cr.MAX_NAME_LEN):
                raise InvalidInput("fido2 name")
        alg = obj["alg"]
        if not _is_int(alg) or alg not in cr.SUPPORTED_ALGS:
            raise InvalidInput("fido2 alg")
        key = obj["key"]
        if not isinstance(key, bytes) or len(key) != 32:
            raise InvalidInput("fido2 key")
        if alg == cr.ALG_ES256 and not 0 < int.from_bytes(key, "big") < crypto.P256_ORDER:
            raise InvalidInput("fido2 key range")
        prot = obj["cred_protect"]
        if not _is_int(prot) or not 1 <= prot <= 3:
            raise InvalidInput("fido2 cred_protect")
        for k in ("hmac_secret", "large_blob"):
            if not isinstance(obj[k], bool):
                raise InvalidInput("fido2 flag")
        sc = obj["sign_count"]
        if not _is_int(sc) or not 0 <= sc <= 0xFFFFFFFF:
            raise InvalidInput("fido2 sign_count")
        blobs = obj["large_blobs"]
        if not isinstance(blobs, list) or len(blobs) > MAX_LARGE_BLOB_ITEMS:
            raise InvalidInput("fido2 large_blobs")
        total = 0
        for b in blobs:
            if not isinstance(b, bytes):
                raise InvalidInput("fido2 large_blobs item")
            total += len(b)
            try:
                e = cbor.decode(b, max_depth=1, max_items=16)
            except cbor.CborError:
                raise InvalidInput("fido2 large_blobs item")
            if not isinstance(e, dict) or 1 not in e or 2 not in e or 3 not in e:
                raise InvalidInput("fido2 large_blobs item")
        if total > MAX_SERIALIZED:
            raise InvalidInput("fido2 large_blobs size")
        if blobs and not obj["large_blob"]:
            raise InvalidInput("fido2 large_blobs without largeBlobKey")

    # -- restore ---------------------------------------------------------------
    def _existing(self, obj: dict):
        """``(same_uid_cred, same_owner_cred)`` currently stored."""
        store = self.auth.store
        by_uid = store.get(obj["cred_id"][1:9])
        by_owner = store.find_user(crypto.sha256(obj["rp_id"].encode()), obj["user_id"])
        return by_uid, by_owner

    def exists(self, obj: dict) -> bool:
        self.validate(obj)
        by_uid, by_owner = self._existing(obj)
        return by_uid is not None or by_owner is not None

    def _credential(self, obj: dict):
        cid = obj["cred_id"]
        rp_id = obj["rp_id"]
        return cr.Credential(
            cr.KIND_RESIDENT,
            cid,
            crypto.sha256(rp_id.encode()),
            obj["key"],
            obj["alg"],
            obj["cred_protect"],
            obj["hmac_secret"],
            obj["large_blob"],
            rp_id,
            obj["user_id"],
            obj.get("user_name"),
            obj.get("display_name"),
            int.from_bytes(cid[9:13], "big"),
            cid[1:9],
            True,
        )

    def describe(self, obj: dict) -> tuple:
        self.validate(obj)
        cred = self._credential(obj)
        return _label(cred.rp_id, cred.label()), cred.fingerprint()

    def restore_identity(self, obj: dict, overwrite: bool) -> bytes:
        self.validate(obj)
        store = self.auth.store
        by_uid, by_owner = self._existing(obj)
        if (by_uid is not None or by_owner is not None) and not overwrite:
            raise PolicyDenied("identity exists")
        cred = self._credential(obj)
        replace_uid = None
        if by_owner is not None and by_owner.uid != cred.uid:
            replace_uid = by_owner.uid
        if by_uid is None and replace_uid is None and store.is_full():
            raise StorageFull("key store full")
        # merged largeBlob array, checked before anything is written
        merged = None
        if obj["large_blobs"]:
            current = self.auth.large_blobs.entries()
            encoded = [cbor.encode(e) for e in current]
            changed = False
            for b in obj["large_blobs"]:
                if b not in encoded:
                    current.append(cbor.decode(b))
                    encoded.append(b)
                    changed = True
            if changed:
                if len(serialize(current)) > MAX_SERIALIZED:
                    raise StorageFull("largeBlob array full")
                merged = current
        self.auth.state.raise_signature_counter(obj["sign_count"])
        if merged is not None:
            self.auth.large_blobs.write_entries(merged)
        store.restore(cred, replace_uid)
        return cred.uid
