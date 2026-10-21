# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Backup provider interface and registry (spec §8.2, §8.3, §10.6).

Every application whose data can be backed up (OTP, FIDO2, OpenPGP, PIV,
AES) implements one :class:`BackupProvider` and registers it at boot::

    from feuristic.apps.backup import provider

    class OtpBackupProvider(provider.BackupProvider):
        TYPE = "otp"
        ...

    provider.register(OtpBackupProvider())

The backup core never interprets an application's data: it asks the
provider for a CBOR-able ``dict`` per identity, encrypts it, and on restore
hands the authenticated ``dict`` back. The normative description (item
schema rules, method contracts, atomicity) is
``docs/protocols/backup-format-v1.md`` §7.

Identity item rules (enforced by :func:`check_item_common` and by the
envelope schema validation):

* a ``dict`` whose keys are all text strings;
* ``"type"``: the provider's :attr:`BackupProvider.TYPE`;
* ``"v"``: the provider's item schema version, an int in ``1..255``;
* values limited to ``int`` (|x| < 2**64), ``bytes``, ``str``, ``bool``,
  ``None``, ``list`` and ``dict`` (text keys) — no floats, no tags;
* nesting depth ≤ 5 below the item map and ≤ 1024 CBOR data items per item.
"""

from micropython import const

from ...core.errors import InvalidInput, NotFound
from ...platform._backend import FIRMWARE
from .errors import UnsupportedItem

TYPE_MAX_LEN = const(16)
UID_MIN_LEN = const(1)
UID_MAX_LEN = const(32)
LABEL_MAX_BYTES = const(128)
FINGERPRINT_MAX_LEN = const(64)
ITEM_VERSION_MAX = const(255)


class BackupProvider:
    """Interface implemented by every backed-up application.

    All methods are synchronous (they only touch storage); user interaction
    is done by :mod:`feuristic.apps.backup.export` / ``restore``.
    """

    #: stable item type, e.g. ``"otp"``, ``"fido2"``, ``"openpgp"``,
    #: ``"piv"``, ``"aes"`` (lower-case ``[a-z][a-z0-9_-]{0,15}``)
    TYPE = ""
    #: i18n key of the category name shown in menus and prompts
    LABEL_KEY = ""

    def list_identities(self) -> list:
        """Return ``[(uid, label), ...]`` for every exportable identity.

        ``uid`` is a stable ``bytes`` identifier (1..32 bytes, e.g. the record
        uid of :mod:`feuristic.core.store`) and ``label`` a short
        human-readable name (``str``, ≤ 128 UTF-8 bytes, e.g.
        ``"github.com — alice"``). Identities whose secret is not backup-able
        are omitted."""
        raise NotImplementedError

    def export_identity(self, uid: bytes) -> dict:
        """Return the complete item ``dict`` for ``uid`` (keys ``"type"``,
        ``"v"`` and the application fields, including secrets).

        Must contain everything needed to restore the identity on another
        device of either hardware revision (spec §8.3): no device-bound key
        material, no wrapped blobs. Raises ``NotFound`` if ``uid`` vanished."""
        raise NotImplementedError

    def iter_uids(self):
        """Snapshot identifiers without retaining all display labels."""
        for uid, _label in self.list_identities():
            yield uid

    def identity_label(self, uid):
        for candidate, label in self.list_identities():
            if bytes(candidate) == uid:
                return label
        raise NotFound("identity not found")

    def validate(self, obj: dict) -> None:
        """Strictly validate an authenticated item (types, lengths, ranges).

        Called for **every** item of a restore set before anything is written.
        Implementations call ``super().validate(obj)`` first and raise
        :class:`feuristic.core.errors.InvalidInput` on any violation."""
        check_item_common(obj, self.TYPE)

    def exists(self, obj: dict) -> bool:
        """True if restoring ``obj`` would replace an existing identity
        (same OTP issuer+account, same FIDO rpId+credential id, same PIV slot,
        same OpenPGP key slot, same AES key id, ...)."""
        raise NotImplementedError

    def describe(self, obj: dict) -> tuple:
        """Return ``(label, fingerprint)`` for an item.

        Shown before restoring and in the overwrite confirmation (spec §8.2
        "afficher son nom, son empreinte"). ``fingerprint`` is an upper- or
        lower-case hex string (≤ 64 chars) identifying the key material (e.g.
        SHA-256 prefix of the public key, OpenPGP v4 fingerprint) or ``""``
        when the application has no meaningful fingerprint."""
        raise NotImplementedError

    def restore_identity(self, obj: dict, overwrite: bool) -> bytes:
        """Atomically write the identity described by ``obj``; return its uid.

        * Atomic: after a power cut or an exception either the previous state
          or the complete new identity is visible, never a partial one
          (spec §3.3 "règle d'intégrité", §10.6).
        * If :meth:`exists` is true and ``overwrite`` is False, raise
          ``PolicyDenied`` without writing.
        * Raise ``StorageFull`` (nothing written) when capacity is exhausted.
        * Restored FIDO2 credentials must carry the WebAuthn backup flags
          (BE=1, BS=1): they demonstrably exist in a backup."""
        raise NotImplementedError

    def on_exported(self, uid: bytes) -> None:
        """Called after an envelope containing ``uid`` was produced and before
        its QR codes are displayed (e.g. FIDO2 sets the WebAuthn backup-state
        flag BS; spec §5 "indicateurs de sauvegarde"). Default: nothing."""
        return


# ---------------------------------------------------------------------------
# validation helpers shared by providers and the backup core
# ---------------------------------------------------------------------------


class LazyProvider(BackupProvider):
    """Delegate each operation without keeping an application/server alive.

    The factory receives TYPE and returns a short-lived concrete provider.
    In particular, a registry entry must not retain a FIDO HID server while
    the exclusive image-import mode needs its RAM.
    """

    def __init__(self, kind, label_key, factory) -> None:
        self.TYPE = kind
        self.LABEL_KEY = label_key
        self._factory = factory

    def _call(self, name, *args):
        if not FIRMWARE:
            return getattr(self._factory(self.TYPE), name)(*args)
        import sys

        from trezor import utils

        # A compact immutable name snapshot suffices for membership checks;
        # a hash set of every loaded module costs several KiB on the device.
        modules = tuple(sys.modules)
        try:
            return getattr(self._factory(self.TYPE), name)(*args)
        finally:
            # Only modules newly loaded by this operation are removed. Live
            # NORMAL transport modules and their session policies survive.
            utils.unimport_end(modules)

    def list_identities(self):
        return self._call("list_identities")

    def iter_uids(self):
        if not FIRMWARE:
            yield from self._factory(self.TYPE).iter_uids()
            return
        import sys

        from trezor import utils

        modules = tuple(sys.modules)
        try:
            uids = list(self._factory(self.TYPE).iter_uids())
        finally:
            utils.unimport_end(modules)
        yield from uids

    def identity_label(self, uid):
        return self._call("identity_label", uid)

    def export_identity(self, uid):
        return self._call("export_identity", uid)

    def validate(self, obj) -> None:
        self._call("validate", obj)

    def exists(self, obj):
        return self._call("exists", obj)

    def describe(self, obj):
        return self._call("describe", obj)

    def restore_identity(self, obj, overwrite):
        return self._call("restore_identity", obj, overwrite)

    def on_exported(self, uid) -> None:
        self._call("on_exported", uid)


def is_valid_type(t) -> bool:
    """``[a-z][a-z0-9_-]{0,15}``."""
    if not isinstance(t, str) or not 1 <= len(t) <= TYPE_MAX_LEN:
        return False
    for i in range(len(t)):
        ch = t[i]
        if "a" <= ch <= "z":
            continue
        if i > 0 and ("0" <= ch <= "9" or ch in "_-"):
            continue
        return False
    return True


def check_item_common(obj, expected_type=None) -> None:
    """Validate the provider-independent part of an item."""
    if not isinstance(obj, dict):
        raise InvalidInput("item must be a map")
    for k in obj:
        if not isinstance(k, str):
            raise InvalidInput("item keys must be text")
    t = obj.get("type")
    if not is_valid_type(t):
        raise InvalidInput("item type")
    if expected_type is not None and t != expected_type:
        raise InvalidInput("item type mismatch")
    v = obj.get("v")
    if not isinstance(v, int) or isinstance(v, bool) or not 1 <= v <= ITEM_VERSION_MAX:
        raise InvalidInput("item version")


def check_uid(uid) -> bytes:
    if not isinstance(uid, (bytes, bytearray)) or not UID_MIN_LEN <= len(uid) <= UID_MAX_LEN:
        raise InvalidInput("identity uid")
    return bytes(uid)


def check_label(label) -> str:
    if not isinstance(label, str) or len(label.encode()) > LABEL_MAX_BYTES:
        raise InvalidInput("identity label")
    return label


def check_fingerprint(fp) -> str:
    if fp is None:
        return ""
    if not isinstance(fp, str) or len(fp) > FINGERPRINT_MAX_LEN:
        raise InvalidInput("fingerprint")
    for ch in fp:
        if not ("0" <= ch <= "9" or "a" <= ch <= "f" or "A" <= ch <= "F"):
            raise InvalidInput("fingerprint")
    return fp


# ---------------------------------------------------------------------------
# registry
# ---------------------------------------------------------------------------

_by_type = {}
_order = []  # registration order (MicroPython dicts are not ordered)


def register(p) -> None:
    """Register provider ``p``. Registering a second provider for the same
    ``TYPE`` is a programming error (``ValueError``)."""
    t = getattr(p, "TYPE", None)
    if not is_valid_type(t):
        raise ValueError("invalid provider TYPE")
    if t in _by_type:
        if _by_type[t] is p:
            return
        raise ValueError("duplicate backup provider: " + t)
    _by_type[t] = p
    _order.append(p)


def unregister(t: str) -> None:
    """Remove the provider for ``t`` (tests / app teardown)."""
    p = _by_type.pop(t, None)
    if p is not None:
        _order.remove(p)


def clear() -> None:
    """Remove every provider (tests)."""
    _by_type.clear()
    del _order[:]


def get(t) -> BackupProvider:
    """Return the provider for type ``t`` or raise :class:`UnsupportedItem`."""
    p = _by_type.get(t) if isinstance(t, str) else None
    if p is None:
        raise UnsupportedItem("no provider for item type")
    return p


def all() -> list:  # noqa: A001 - name fixed by the provider contract
    """Registered providers in registration order (= export order)."""
    return list(_order)
