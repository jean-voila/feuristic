# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Backup provider for PIV slot identities (spec §8.2, §8.3).

One identity per key slot (9A, 9C, 9D, 9E) holding a private key, including
its certificate. The normative schema is ``docs/protocols/backup-piv.md``::

    piv-identity = {
      "type": "piv", "v": 1,
      "slot": 0x9A / 0x9C / 0x9D / 0x9E,
      "alg": 0x11 / 0x07,                  ; SP 800-78-4: ECC P-256 / RSA 2048
      ? "sk": bstr .size 32,               ; alg 0x11: secret scalar, big-endian
      ? "p": bstr .size 128,               ; alg 0x07: prime factors, big-endian
      ? "q": bstr .size 128,
      ? "e": 65537,                        ; alg 0x07
      "pin_policy": 1..3,                  ; never stricter-than-default violation
      ? "cert": bstr .size (1..2048),      ; X.509 certificate (PIV tag 70)
      ? "certinfo": 0 / 1,                 ; PIV CertInfo (tag 71)
    }

Not exported: PIN, PUK, administration key and the data objects (CHUID,
CCC, ...); the restoring device keeps its own (spec §8.3: backups are
independent of the device). Slots holding only a certificate have no
secret and are not listed.
"""

from micropython import const

from ....core.errors import InvalidInput, NotFound, PolicyDenied
from ....core.i18n import t
from ....platform import crypto
from ...backup.provider import BackupProvider
from . import consts as pc
from . import storage, strings

strings.register()

SCHEMA_VERSION = const(1)

_EC_KEYS = ("type", "v", "slot", "alg", "sk", "pin_policy")
_RSA_KEYS = ("type", "v", "slot", "alg", "p", "q", "e", "pin_policy")


def _uint(obj: dict, k: str) -> int:
    v = obj.get(k)
    if isinstance(v, bool) or not isinstance(v, int):
        raise InvalidInput("piv backup integer")
    return v


def _bstr(obj: dict, k: str, size: int) -> bytes:
    v = obj.get(k)
    if not isinstance(v, (bytes, bytearray)) or len(v) != size:
        raise InvalidInput("piv backup bytes")
    return bytes(v)


def slot_from_object(obj) -> storage.SlotData:
    """Strictly validate a backup item and return the :class:`SlotData` it describes."""
    if not isinstance(obj, dict) or obj.get("type") != "piv":
        raise InvalidInput("piv backup type")
    if _uint(obj, "v") != SCHEMA_VERSION:
        raise InvalidInput("piv backup version")
    slot = _uint(obj, "slot")
    if slot not in pc.KEY_SLOTS:
        raise InvalidInput("piv backup slot")
    alg = _uint(obj, "alg")
    expected = _EC_KEYS if alg == pc.ALG_P256 else _RSA_KEYS if alg == pc.ALG_RSA2048 else None
    if expected is None:
        raise InvalidInput("piv backup alg")
    optional = ("cert", "certinfo")
    for k in obj:
        if k not in expected and k not in optional:
            raise InvalidInput("piv backup unknown field")
    for k in expected:
        if k not in obj:
            raise InvalidInput("piv backup missing field")
    if ("cert" in obj) != ("certinfo" in obj):
        raise InvalidInput("piv backup certificate")
    policy = _uint(obj, "pin_policy")
    if policy not in (pc.PIN_POLICY_NEVER, pc.PIN_POLICY_ONCE, pc.PIN_POLICY_ALWAYS):
        raise InvalidInput("piv backup pin policy")
    if policy < pc.DEFAULT_PIN_POLICY[slot]:
        raise InvalidInput("piv backup pin policy weaker than default")
    d = storage.SlotData(slot, alg, pin_policy=policy, origin=pc.ORIGIN_IMPORTED)
    try:
        if alg == pc.ALG_P256:
            d.sk = _bstr(obj, "sk", 32)
            d.pub = crypto.p256_public(d.sk)  # range-checks the scalar
        else:
            half = pc.RSA_BYTES // 2
            d.p = _bstr(obj, "p", half)
            d.q = _bstr(obj, "q", half)
            d.e = _uint(obj, "e")
            if d.e != pc.RSA_E:
                raise InvalidInput("piv backup exponent")
            pi = int.from_bytes(d.p, "big")
            qi = int.from_bytes(d.q, "big")
            if pi == qi or not (pi & 1 and qi & 1) or not (d.p[0] & 0x80 and d.q[0] & 0x80):
                raise InvalidInput("piv backup rsa factors")
            if len(d.rsa_key().n) != pc.RSA_BYTES:
                raise InvalidInput("piv backup modulus")
    except crypto.CryptoError:
        raise InvalidInput("piv backup key")
    except ValueError:  # non-invertible exponent etc. (host backend)
        raise InvalidInput("piv backup key")
    if "cert" in obj:
        cert = obj["cert"]
        info = _uint(obj, "certinfo")
        if not isinstance(cert, (bytes, bytearray)) or not 0 < len(cert) <= pc.MAX_CERT_LEN:
            raise InvalidInput("piv backup certificate")
        if info not in (0, 1):
            raise InvalidInput("piv backup certinfo")
        d.cert = bytes(cert)
        d.certinfo = info
    if len(d.encode()) > storage.MAX_PAYLOAD:
        raise InvalidInput("piv backup too large")
    return d


def _label(slot: int) -> str:
    return f"PIV {slot:02X} {t(pc.SLOT_ROLE_KEYS[slot])}"


class PivBackupProvider(BackupProvider):
    """Registered with :func:`feuristic.apps.backup.provider.register`."""

    TYPE = "piv"
    LABEL_KEY = "piv.title"

    def __init__(self, store=None) -> None:
        self._store = store

    @property
    def store(self):
        return storage.default() if self._store is None else self._store

    def list_identities(self) -> list:
        out = []
        for slot in pc.KEY_SLOTS:
            d = self.store.get_slot(slot)
            if d is not None and d.has_key:
                out.append((storage.slot_uid(slot), _label(slot)))
        return out

    def _slot_of(self, uid) -> int:
        uid = bytes(uid)
        if len(uid) != 8 or uid[:7] != b"PIVslot" or uid[7] not in pc.KEY_SLOTS:
            raise NotFound
        return uid[7]

    def export_identity(self, uid) -> dict:
        slot = self._slot_of(uid)
        d = self.store.get_slot(slot)
        if d is None or not d.has_key:
            raise NotFound
        obj = {"type": self.TYPE, "v": SCHEMA_VERSION, "slot": slot, "alg": d.alg, "pin_policy": d.pin_policy}
        if d.alg == pc.ALG_P256:
            obj["sk"] = d.sk
        else:
            obj["p"] = d.p
            obj["q"] = d.q
            obj["e"] = d.e
        if d.cert is not None:
            obj["cert"] = d.cert
            obj["certinfo"] = d.certinfo
        return obj

    def validate(self, obj) -> None:
        super().validate(obj)
        slot_from_object(obj)

    def exists(self, obj) -> bool:
        d = slot_from_object(obj)
        cur = self.store.get_slot(d.slot)
        return cur is not None and (cur.has_key or cur.cert is not None)

    def describe(self, obj) -> tuple:
        d = slot_from_object(obj)
        return _label(d.slot), d.fingerprint()

    def restore_identity(self, obj, overwrite: bool) -> bytes:
        d = slot_from_object(obj)
        if self.exists(obj) and not overwrite:
            raise PolicyDenied("PIV slot in use")
        self.store.put_slot(d)  # single copy-on-write record: atomic
        return storage.slot_uid(d.slot)

    def on_exported(self, uid) -> None:
        return
