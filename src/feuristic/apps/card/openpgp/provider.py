# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Backup provider for the OpenPGP card identity (spec §8.2, §8.3).

The card holds exactly one OpenPGP identity (three key slots and their
data objects); it is exported and restored as a whole. Item schema
(normative description in docs/protocols/backup-openpgp.md, CDDL)::

    openpgp-identity = {
      "type": "openpgp", "v": 1,
      "keys": [3* key],                     ; index 0 sig, 1 dec, 2 aut
      "name": bstr .size (0..39), "lang": bstr .size (0..8),
      "sex": bstr .size (0..1), "url": bstr .size (0..254),
      "login": bstr .size (0..254), "private": [4* bstr .size (0..254)],
      "cert": bstr .size (0..2048),
      "pw1": pin, "pw3": pin, "rc": pin / null,
      "pw1_status": 0 / 1, "dsc": uint .le 16777215,
    }
    key = { "attr": bstr, "secret": bstr / null, "fpr": bstr .size 20,
            "ca": bstr .size 20, "date": uint .le 4294967295,
            "origin": 0 / 1 / 2 }
    pin = { "kdf": 1..1000000, "salt": bstr .size 16,
            "hash": bstr .size 32, "len": 1..127 }

PINs travel as their salted PBKDF2 references (never in clear); the
restored card keeps the same PINs. Retry counters are restored to 3.
"""

from micropython import const

from ....core.errors import InvalidInput, NotFound, PolicyDenied
from ...backup import provider as _bp
from . import const as pgp
from . import keys as alg
from .storage import ZERO20, Identity, KeySlot, PinRef

SCHEMA_VERSION = const(1)
UID = b"openpgp"

_ITEM_KEYS = (
    "type",
    "v",
    "keys",
    "name",
    "lang",
    "sex",
    "url",
    "login",
    "private",
    "cert",
    "pw1",
    "pw3",
    "rc",
    "pw1_status",
    "dsc",
)
_KEY_KEYS = ("attr", "secret", "fpr", "ca", "date", "origin")
_PIN_KEYS = ("kdf", "salt", "hash", "len")


def _pin_obj(ref):
    if ref is None:
        return None
    return {"kdf": ref.iterations, "salt": ref.salt, "hash": ref.digest, "len": ref.length}


def _exact_keys(obj, names, what: str) -> None:
    if not isinstance(obj, dict) or len(obj) != len(names):
        raise InvalidInput(what)
    for k in names:
        if k not in obj:
            raise InvalidInput(what)


def _int(v, lo: int, hi: int, what: str) -> int:
    if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
        raise InvalidInput(what)
    return v


def _bstr(v, max_len: int, what: str) -> bytes:
    if not isinstance(v, (bytes, bytearray)) or len(v) > max_len:
        raise InvalidInput(what)
    return bytes(v)


def _pin_from(obj, which: int):
    _exact_keys(obj, _PIN_KEYS, "pin")
    ref = PinRef.decode([obj["kdf"], obj["salt"], obj["hash"], obj["len"]])
    if ref.length < pgp.PW_MIN[which]:
        raise InvalidInput("pin length")
    return ref


def identity_from_item(obj) -> tuple:
    """Validate ``obj`` strictly; return ``(Identity, dsc)``."""
    _bp.check_item_common(obj, "openpgp")
    if obj.get("v") != SCHEMA_VERSION:
        raise InvalidInput("openpgp item version")
    _exact_keys(obj, _ITEM_KEYS, "openpgp item fields")
    ident = Identity()
    ks = obj["keys"]
    if not isinstance(ks, list) or len(ks) != 3:
        raise InvalidInput("keys")
    slots = []
    for role in pgp.ROLES:
        k = ks[role]
        _exact_keys(k, _KEY_KEYS, "key")
        attr = _bstr(k["attr"], 16, "attr")
        kind = alg.parse_attr(role, attr)  # also enforces role/algorithm pairs
        if alg.canonical_attr(kind) != attr:
            raise InvalidInput("attr not canonical")
        secret = k["secret"]
        origin = _int(k["origin"], 0, 2, "origin")
        if secret is None:
            if origin != pgp.ORIGIN_NONE:
                raise InvalidInput("origin")
        else:
            secret = _bstr(secret, 512, "secret")
            alg.check_secret(kind, secret)
            if origin == pgp.ORIGIN_NONE:
                raise InvalidInput("origin")
        fpr = _bstr(k["fpr"], 20, "fpr")
        ca = _bstr(k["ca"], 20, "ca")
        if len(fpr) != 20 or len(ca) != 20:
            raise InvalidInput("fingerprint length")
        date = _int(k["date"], 0, 0xFFFFFFFF, "date")
        slots.append(KeySlot(attr, secret, fpr, ca, date, origin))
    ident.keys = slots
    ident.name = _bstr(obj["name"], pgp.MAX_NAME, "name")
    ident.lang = _bstr(obj["lang"], pgp.MAX_LANG, "lang")
    ident.sex = _bstr(obj["sex"], 1, "sex")
    if ident.sex and ident.sex not in (b"0", b"1", b"2", b"9"):
        raise InvalidInput("sex")
    ident.url = _bstr(obj["url"], pgp.MAX_SPECIAL_DO, "url")
    ident.login = _bstr(obj["login"], pgp.MAX_SPECIAL_DO, "login")
    priv = obj["private"]
    if not isinstance(priv, list) or len(priv) != 4:
        raise InvalidInput("private")
    ident.private = [_bstr(p, pgp.MAX_SPECIAL_DO, "private DO") for p in priv]
    ident.cert = _bstr(obj["cert"], pgp.MAX_CERT, "cert")
    ident.pins[pgp.PW1] = _pin_from(obj["pw1"], pgp.PW1)
    ident.pins[pgp.PW3] = _pin_from(obj["pw3"], pgp.PW3)
    ident.pins[pgp.RC] = None if obj["rc"] is None else _pin_from(obj["rc"], pgp.RC)
    ident.pw1_status = _int(obj["pw1_status"], 0, 1, "pw1_status")
    dsc = _int(obj["dsc"], 0, 0xFFFFFF, "dsc")
    return ident, dsc


def _primary_fingerprint(keys_list) -> str:
    for k in keys_list:
        if k.fpr != ZERO20:
            return k.fpr.hex().upper()
    return ""


class OpenPgpBackupProvider(_bp.BackupProvider):
    TYPE = "openpgp"
    LABEL_KEY = "openpgp.backup.label"

    def __init__(self, store) -> None:
        self.store = store

    def _label(self, ident) -> str:
        # ISO 8859-1 → str without codecs (MicroPython only decodes UTF-8)
        name = "".join(chr(b) for b in ident.name)
        name = name.replace("<<", " ").replace("<", " ").strip()
        label = "OpenPGP"
        if name:
            label += " - " + name
        return label[:64]

    def list_identities(self) -> list:
        ident = self.store.ident
        if ident.terminated or not (ident.has_keys() or ident.has_aux() or ident.name):
            return []
        return [(UID, self._label(ident))]

    def export_identity(self, uid: bytes) -> dict:
        if bytes(uid) != UID or not self.list_identities():
            raise NotFound
        ident = self.store.ident
        return {
            "type": self.TYPE,
            "v": SCHEMA_VERSION,
            "keys": [
                {
                    "attr": k.attr,
                    "secret": k.secret,
                    "fpr": k.fpr,
                    "ca": k.ca_fpr,
                    "date": k.date,
                    "origin": k.origin,
                }
                for k in ident.keys
            ],
            "name": ident.name,
            "lang": ident.lang,
            "sex": ident.sex,
            "url": ident.url,
            "login": ident.login,
            "private": list(ident.private),
            "cert": ident.cert,
            "pw1": _pin_obj(ident.pins[pgp.PW1]),
            "pw3": _pin_obj(ident.pins[pgp.PW3]),
            "rc": _pin_obj(ident.pins[pgp.RC]),
            "pw1_status": ident.pw1_status,
            "dsc": self.store.signature_count(),
        }

    def validate(self, obj: dict) -> None:
        identity_from_item(obj)

    def exists(self, obj: dict) -> bool:
        """The card has a single OpenPGP identity: any non-empty one is replaced."""
        return bool(self.list_identities())

    def describe(self, obj: dict) -> tuple:
        ident, _ = identity_from_item(obj)
        return self._label(ident), _primary_fingerprint(ident.keys)

    def restore_identity(self, obj: dict, overwrite: bool) -> bytes:
        ident, dsc = identity_from_item(obj)
        if self.exists(obj) and not overwrite:
            raise PolicyDenied("identity exists")
        # displayed counter = dsc_base offset from the monotonic counter
        ident.dsc_base = self.store.dsc.get() - dsc
        self.store.replace(ident)
        for t in self.store.tries:
            t.clear()
        return UID

    def on_exported(self, uid: bytes) -> None:
        return
