# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Backup provider for OTP accounts (spec §8.2, §8.3).

The backup application (``feuristic.apps.backup``) serialises the object
returned by :meth:`OtpBackupProvider.export_identity` with canonical CBOR,
encrypts it and splits it into QR frames. The schema (CDDL, RFC 8610) is
normative in ``docs/protocols/backup-otp.md``::

    otp-identity = {
      "v": 1, "type": "otp", "kind": "totp" / "hotp",
      "issuer": tstr .size (0..32), "account": tstr .size (1..64),
      "secret": bstr .size (1..64),
      "algorithm": "SHA1" / "SHA256" / "SHA512", "digits": 6..8,
      ? "period": 15..300,          ; kind = "totp" (required)
      ? "counter": uint .size 8,    ; kind = "hotp" (required): next unused value
    }

Restored objects come from an authenticated envelope but are still
validated field by field (types, bounds, no unknown keys).
"""

from micropython import const

from ...core.errors import InvalidInput
from ...platform import crypto
from ..backup import provider as _backup
from . import accounts as _accounts
from . import uri as _uri

SCHEMA_VERSION = const(1)
FINGERPRINT_BYTES = const(8)

_COMMON_KEYS = ("v", "type", "kind", "issuer", "account", "secret", "algorithm", "digits")


def params_from_object(obj):
    """Validate a backup object and return :class:`~feuristic.apps.otp.uri.OtpParams`."""
    if not isinstance(obj, dict):
        raise InvalidInput("otp backup object")
    if obj.get("v") != SCHEMA_VERSION or isinstance(obj.get("v"), bool):
        raise InvalidInput("otp backup version")
    if obj.get("type") != "otp":
        raise InvalidInput("otp backup type")
    kind = obj.get("kind")
    if kind == _uri.TOTP:
        extra = "period"
    elif kind == _uri.HOTP:
        extra = "counter"
    else:
        raise InvalidInput("otp backup kind")
    for k in _COMMON_KEYS + (extra,):
        if k not in obj:
            raise InvalidInput("otp backup field missing")
    if len(obj) != len(_COMMON_KEYS) + 1:
        raise InvalidInput("otp backup unknown field")
    secret = obj["secret"]
    if not isinstance(secret, (bytes, bytearray)):
        raise InvalidInput("otp backup secret")
    for k in ("digits", extra):
        if isinstance(obj[k], bool) or not isinstance(obj[k], int):
            raise InvalidInput("otp backup integer")
    return _uri.OtpParams(
        kind,
        obj["issuer"],
        obj["account"],
        bytes(secret),
        obj["algorithm"],
        obj["digits"],
        obj.get("period"),
        obj.get("counter"),
    )


def fingerprint(secret) -> str:
    """Short hex fingerprint safe to display: first 8 bytes of SHA-256(secret)."""
    return crypto.sha256(bytes(secret))[:FINGERPRINT_BYTES].hex()


class OtpBackupProvider(_backup.BackupProvider):
    """Backup provider registered with ``feuristic.apps.backup.provider``.

    Firmware boot: ``provider.register(OtpBackupProvider())``.
    """

    TYPE = "otp"
    LABEL_KEY = "otp.title"

    def __init__(self, accounts=None) -> None:
        self._accounts = accounts

    @property
    def accounts(self):
        if self._accounts is None:
            return _accounts.default()
        return self._accounts

    def list_identities(self) -> list:
        """``[(uid, label)]`` sorted by issuer, account."""
        return [(acc.uid, acc.label()) for acc in self.accounts.accounts()]

    def export_identity(self, uid) -> dict:
        """Canonical-CBOR-able map of ``uid`` (HOTP: current counter)."""
        p = self.accounts.export_params(uid)
        obj = {
            "v": SCHEMA_VERSION,
            "type": self.TYPE,
            "kind": p.kind,
            "issuer": p.issuer,
            "account": p.account,
            "secret": p.secret,
            "algorithm": p.algorithm,
            "digits": p.digits,
        }
        if p.kind == _uri.TOTP:
            obj["period"] = p.period
        else:
            obj["counter"] = p.counter
        return obj

    def validate(self, obj) -> None:
        """Strict validation of an authenticated item (raises InvalidInput)."""
        _backup.check_item_common(obj, self.TYPE)
        params_from_object(obj)

    def exists(self, obj) -> bool:
        """True if an account with the same issuer and account name exists."""
        p = params_from_object(obj)
        return self.accounts.find(p.issuer, p.account) is not None

    def describe(self, obj):
        """``(label, fingerprint)`` shown before overwriting (spec §8.2)."""
        p = params_from_object(obj)
        return p.label(), fingerprint(p.secret)

    def restore_identity(self, obj, overwrite: bool) -> bytes:
        """Store ``obj``; returns the uid.

        If an account with the same issuer + account exists, raises
        :class:`~feuristic.apps.otp.accounts.AlreadyExists` (a
        ``PolicyDenied``) without writing, unless
        ``overwrite`` (the backup UI has then shown :meth:`describe` and
        obtained the specific confirmation). Overwriting an HOTP account
        holding the same secret never moves its counter backwards.
        """
        p = params_from_object(obj)
        existing = self.accounts.find(p.issuer, p.account)
        if existing is None:
            return self.accounts.add(p)
        if not overwrite:
            raise _accounts.AlreadyExists("account exists")
        return self.accounts.add(p, existing.uid)

    def on_exported(self, uid) -> None:
        """Nothing to record for OTP accounts."""
        return
