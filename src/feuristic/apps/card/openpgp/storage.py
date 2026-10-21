# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Persistence of the OpenPGP card identity (docs/architecture.md §6).

Layout in the protected namespace ``CARD`` (``0x14``), OpenPGP key range
``0x00–0x0F``: one :class:`~feuristic.core.store.RecordStore` of capacity 3
(slots/keys ``0x00–0x03``; slot ``i`` is key ``i``, so no key offset is
needed for OpenPGP) holding

* the **identity record** (uid ``OPGP-ID\\0``, canonical CBOR ≤ 1536 B): keys,
  algorithm attributes, fingerprints, CA fingerprints, generation dates, key
  origins, cardholder name/language/sex, salted PIN hashes, PW1 status byte,
  signature-counter base, life cycle state and a reference to
* one of two **aux records** (uids ``OPGP-AXA`` / ``OPGP-AXB``, ≤ 3712 B):
  URL, login data, private DOs 0101–0104 and the cardholder certificate.

The aux record is replaced copy-on-write *across uids*: a new aux record is
written under the uid that is not referenced, then the identity record is
replaced (atomically, by :class:`RecordStore`) to reference it, then the old
aux record is deleted. A power cut at any point leaves either the old or the
new (identity, aux) pair visible; :meth:`IdentityStore.load` garbage-collects
an unreferenced aux record.

Counters live in the public namespace ``CARD_COUNTERS`` (``0x94``), keys
``0x10–0x1F`` (see :mod:`.const`): for each PIN a monotonic "fail" counter
and a monotonic "ok mark" counter (:class:`TryCounter`), and the digital
signature counter. All are :class:`~feuristic.core.counters.RedundantCounter`
so a power cut never gives back a consumed PIN try.
"""

from micropython import const

from ....core import cbor, namespaces
from ....core import store as record_store
from ....core.counters import RedundantCounter
from ....core.errors import InvalidInput, StorageCorrupted, StorageFull
from ....core.store import RecordStore
from ....platform import crypto
from . import const as pgp
from . import keys as alg

SCHEMA = const(1)
PIN_KDF_ITERATIONS = const(1000)
PIN_SALT_LEN = const(16)
PIN_HASH_LEN = const(32)
_PIN_DOMAIN = b"feuristic/openpgp/pin\x00"

ZERO20 = bytes(20)


# ---------------------------------------------------------------------------
# PINs
# ---------------------------------------------------------------------------


class PinRef:
    """Salted PBKDF2-HMAC-SHA256 reference of a PIN (never the PIN itself)."""

    def __init__(self, iterations: int, salt: bytes, digest: bytes, length: int) -> None:
        self.iterations = iterations
        self.salt = salt
        self.digest = digest
        self.length = length

    @staticmethod
    def hash(pin, salt: bytes, iterations: int) -> bytes:
        return crypto.pbkdf2_hmac_sha256(bytes(pin), _PIN_DOMAIN + bytes(salt), iterations)

    @classmethod
    def create(cls, pin) -> "PinRef":
        salt = crypto.random_bytes(PIN_SALT_LEN)
        return cls(PIN_KDF_ITERATIONS, salt, cls.hash(pin, salt, PIN_KDF_ITERATIONS), len(pin))

    def matches(self, pin) -> bool:
        """Constant-time comparison of the PIN's hash with the reference."""
        candidate = self.hash(pin, self.salt, self.iterations)
        return crypto.ct_equal(candidate, self.digest) and len(pin) == self.length

    def encode(self) -> list:
        return [self.iterations, self.salt, self.digest, self.length]

    @classmethod
    def decode(cls, obj) -> "PinRef":
        if not isinstance(obj, list) or len(obj) != 4:
            raise InvalidInput("pin reference")
        it, salt, digest, length = obj
        if (
            not isinstance(it, int)
            or isinstance(it, bool)
            or not 1 <= it <= 1_000_000
            or not isinstance(salt, bytes)
            or len(salt) != PIN_SALT_LEN
            or not isinstance(digest, bytes)
            or len(digest) != PIN_HASH_LEN
            or not isinstance(length, int)
            or isinstance(length, bool)
            or not 1 <= length <= pgp.PW_MAX
        ):
            raise InvalidInput("pin reference")
        return cls(it, salt, digest, length)


def check_pin_length(which: int, pin) -> None:
    if not pgp.PW_MIN[which] <= len(pin) <= pgp.PW_MAX:
        raise InvalidInput("PIN length")


class TryCounter:
    """Remaining tries of a PIN = ``3 - (fail - ok_mark)``, power-loss safe.

    ``consume()`` (before comparing!) increments ``fail``; ``clear()`` raises
    ``ok_mark`` to ``fail``. Both only ever increase, so no power cut can
    give back a consumed try.
    """

    def __init__(self, base: int) -> None:
        app = namespaces.CARD_COUNTERS
        self.fail = RedundantCounter(app, base, base + 1, public=True)
        self.ok = RedundantCounter(app, base + 2, base + 3, public=True)

    def used(self) -> int:
        f = self.fail.get()
        m = self.ok.get()
        return f - m if f > m else 0

    def remaining(self) -> int:
        u = self.used()
        return pgp.PW_RETRIES - u if u < pgp.PW_RETRIES else 0

    def consume(self) -> None:
        self.fail.increment()

    def clear(self) -> None:
        f = self.fail.get()
        if self.ok.get() < f:
            self.ok.advance_to(f)


# ---------------------------------------------------------------------------
# identity model
# ---------------------------------------------------------------------------


class KeySlot:
    def __init__(
        self, attr: bytes, secret=None, fpr=ZERO20, ca_fpr=ZERO20, date: int = 0, origin: int = 0
    ) -> None:
        self.attr = attr
        self.secret = secret
        self.fpr = fpr
        self.ca_fpr = ca_fpr
        self.date = date
        self.origin = origin
        self._pub = None

    @property
    def kind(self) -> str:
        return alg.kind_of(self.attr)

    @property
    def present(self) -> bool:
        return self.secret is not None

    def public(self) -> bytes:
        if self.secret is None:
            raise InvalidInput("no key")
        if self._pub is None:
            self._pub = alg.public_key(self.kind, self.secret)
        return self._pub

    def set_secret(self, secret, origin: int) -> None:
        self.secret = secret
        self.origin = origin if secret is not None else pgp.ORIGIN_NONE
        self._pub = None

    def clear(self) -> None:
        self.set_secret(None, pgp.ORIGIN_NONE)
        self.fpr = ZERO20
        self.date = 0

    def encode(self) -> dict:
        return {0: self.attr, 1: self.secret, 2: self.fpr, 3: self.ca_fpr, 4: self.date, 5: self.origin}

    @classmethod
    def decode(cls, role: int, obj) -> "KeySlot":
        if not isinstance(obj, dict) or sorted(obj) != [0, 1, 2, 3, 4, 5]:
            raise InvalidInput("key slot")
        attr, secret, fpr, ca, date, origin = obj[0], obj[1], obj[2], obj[3], obj[4], obj[5]
        if not isinstance(attr, bytes):
            raise InvalidInput("key attr")
        kind = alg.kind_of(attr)
        if role == pgp.DEC and kind == pgp.KIND_ED25519 or role != pgp.DEC and kind == pgp.KIND_X25519:
            raise InvalidInput("key attr role")
        if secret is not None and (not isinstance(secret, bytes) or len(secret) != alg.secret_len(kind)):
            raise InvalidInput("key secret")
        for v in (fpr, ca):
            if not isinstance(v, bytes) or len(v) != 20:
                raise InvalidInput("fingerprint")
        if not isinstance(date, int) or isinstance(date, bool) or not 0 <= date <= 0xFFFFFFFF:
            raise InvalidInput("date")
        if origin not in (0, 1, 2) or (secret is None) != (origin == 0):
            raise InvalidInput("origin")
        return cls(attr, secret, fpr, ca, date, origin)


def _bytes_field(obj, key, max_len: int) -> bytes:
    v = obj.get(key, b"")
    if not isinstance(v, bytes) or len(v) > max_len:
        raise InvalidInput("field")
    return v


class Identity:
    """In-memory OpenPGP card state (everything persistent but counters)."""

    def __init__(self) -> None:
        self.terminated = False
        self.keys = [KeySlot(a) for a in pgp.DEFAULT_ATTRS]
        self.name = b""
        self.lang = b""
        self.sex = b""
        self.pins = [None, None, None]  # PinRef; pins[RC] None = no resetting code
        self.pw1_status = pgp.DEFAULT_PW1_STATUS
        self.dsc_base = 0
        # aux data
        self.url = b""
        self.login = b""
        self.private = [b"", b"", b"", b""]
        self.cert = b""

    @classmethod
    def fresh(cls) -> "Identity":
        """Factory state: default PINs, default algorithms, no keys."""
        ident = cls()
        ident.pins[pgp.PW1] = PinRef.create(pgp.DEFAULT_PW1)
        ident.pins[pgp.PW3] = PinRef.create(pgp.DEFAULT_PW3)
        return ident

    @classmethod
    def terminated_state(cls) -> "Identity":
        ident = cls()
        ident.terminated = True
        return ident

    def has_keys(self) -> bool:
        return any(k.present for k in self.keys)

    def has_aux(self) -> bool:
        return bool(self.url or self.login or self.cert or any(self.private))

    # -- encoding ----------------------------------------------------------------
    def encode_main(self, aux_ref) -> bytes:
        obj = {
            0: SCHEMA,
            1: self.terminated,
            2: [k.encode() for k in self.keys],
            3: self.name,
            4: self.lang,
            5: self.sex,
            6: [p.encode() if p is not None else None for p in self.pins],
            7: self.pw1_status,
            8: self.dsc_base,
            9: aux_ref,
        }
        return record_store.encode_payload(obj)

    def encode_aux(self):
        obj = {0: self.url, 1: self.login, 2: list(self.private), 3: self.cert}
        return record_store.encode_payload(obj)

    @classmethod
    def decode_main(cls, raw: bytes):
        """Return ``(identity, aux_ref)``; raises :class:`InvalidInput`."""
        obj = cbor.decode(raw, canonical=True)
        if not isinstance(obj, dict) or sorted(obj) != list(range(10)) or obj[0] != SCHEMA:
            raise InvalidInput("identity record")
        ident = cls()
        if not isinstance(obj[1], bool):
            raise InvalidInput("terminated")
        ident.terminated = obj[1]
        ks = obj[2]
        if not isinstance(ks, list) or len(ks) != 3:
            raise InvalidInput("keys")
        ident.keys = [KeySlot.decode(i, ks[i]) for i in range(3)]
        ident.name = _bytes_field(obj, 3, pgp.MAX_NAME)
        ident.lang = _bytes_field(obj, 4, pgp.MAX_LANG)
        ident.sex = _bytes_field(obj, 5, 1)
        pins = obj[6]
        if not isinstance(pins, list) or len(pins) != 3:
            raise InvalidInput("pins")
        ident.pins = [None if p is None else PinRef.decode(p) for p in pins]
        if not ident.terminated and (ident.pins[pgp.PW1] is None or ident.pins[pgp.PW3] is None):
            raise InvalidInput("pins")
        if obj[7] not in (0, 1):
            raise InvalidInput("pw1 status")
        ident.pw1_status = obj[7]
        if not isinstance(obj[8], int) or isinstance(obj[8], bool):
            raise InvalidInput("dsc base")
        ident.dsc_base = obj[8]
        aux_ref = obj[9]
        if aux_ref not in (None, 0, 1):
            raise InvalidInput("aux ref")
        return ident, aux_ref

    def decode_aux(self, raw: bytes) -> None:
        obj = cbor.decode(raw, canonical=True)
        if not isinstance(obj, dict) or sorted(obj) != [0, 1, 2, 3]:
            raise InvalidInput("aux record")
        url = _bytes_field(obj, 0, pgp.MAX_SPECIAL_DO)
        login = _bytes_field(obj, 1, pgp.MAX_SPECIAL_DO)
        priv = obj[2]
        if not isinstance(priv, list) or len(priv) != 4:
            raise InvalidInput("private DOs")
        for p in priv:
            if not isinstance(p, bytes) or len(p) > pgp.MAX_SPECIAL_DO:
                raise InvalidInput("private DO")
        cert = _bytes_field(obj, 3, pgp.MAX_CERT)
        self.url, self.login, self.private, self.cert = url, login, list(priv), cert


# ---------------------------------------------------------------------------
# store
# ---------------------------------------------------------------------------


class IdentityStore:
    """Loads, caches and atomically persists the OpenPGP identity.

    Shared by the applet, the device-menu functions (:mod:`.localmgmt`) and
    the backup provider (:mod:`.provider`). :attr:`epoch` increases on every
    wholesale change made outside the applet (restore, factory reset, local
    PIN change, local key generation) so the applet drops its volatile
    access status.
    """

    def __init__(self) -> None:
        self.records = RecordStore(namespaces.CARD, pgp.STORE_CAPACITY, pgp.MAX_AUX_PAYLOAD, pgp.STORE_RTYPE)
        self.tries = [TryCounter(b) for b in pgp.CTR_BASES]
        self.dsc = RedundantCounter(namespaces.CARD_COUNTERS, pgp.CTR_DSC, pgp.CTR_DSC + 1, public=True)
        self._ident = None
        self._aux_ref = None
        self.persisted = False
        self.epoch = 0

    # -- loading ---------------------------------------------------------------
    def load(self) -> None:
        self.records.load()
        raw = self.records.get(pgp.UID_IDENTITY)
        aux_ref = None
        if raw is None:
            # never initialised: factory defaults (not persisted until the
            # first change). Try counters are NOT touched here, so a reboot
            # never gives back tries (activate() clears them only after the
            # fresh record is written).
            ident = Identity.fresh()
            self.persisted = False
        else:
            try:
                ident, aux_ref = Identity.decode_main(raw)
            except InvalidInput:
                raise StorageCorrupted("openpgp identity")
            if aux_ref is not None:
                aux_raw = self.records.get(pgp.UID_AUX[aux_ref])
                if aux_raw is None:
                    raise StorageCorrupted("openpgp aux record missing")
                try:
                    ident.decode_aux(aux_raw)
                except InvalidInput:
                    raise StorageCorrupted("openpgp aux record")
            self.persisted = True
        # garbage-collect an aux record left by an interrupted update
        for i in (0, 1):
            if i != aux_ref and pgp.UID_AUX[i] in self.records:
                self.records.delete(pgp.UID_AUX[i])
        self._ident = ident
        self._aux_ref = aux_ref

    @property
    def ident(self) -> Identity:
        if self._ident is None:
            self.load()
        return self._ident

    def reload(self) -> None:
        self._ident = None
        self.load()

    # -- saving ------------------------------------------------------------------
    def save(self, aux_changed: bool = False) -> None:
        """Persist :attr:`ident` atomically; on failure reload and re-raise."""
        ident = self.ident
        try:
            new_ref = self._aux_ref
            old_ref = self._aux_ref
            if aux_changed or (self._aux_ref is None and ident.has_aux()):
                if ident.has_aux():
                    new_ref = 1 if old_ref == 0 else 0
                    aux_raw = ident.encode_aux()
                    if len(aux_raw) > pgp.MAX_AUX_PAYLOAD:
                        raise StorageFull("openpgp aux too large")
                    self.records.put(pgp.UID_AUX[new_ref], aux_raw)
                else:
                    new_ref = None
            main = ident.encode_main(new_ref)
            if len(main) > pgp.MAX_IDENTITY_PAYLOAD:
                raise StorageFull("openpgp identity too large")
            self.records.put(pgp.UID_IDENTITY, main)
            self._aux_ref = new_ref
            self.persisted = True
            if old_ref is not None and old_ref != new_ref:
                self.records.delete(pgp.UID_AUX[old_ref])
        except Exception:
            self._ident = None
            try:
                self.load()
            except Exception:  # noqa: S110 - keep the original error
                pass
            raise

    def replace(self, ident: Identity) -> None:
        """Atomically make ``ident`` the identity (restore / reset paths)."""
        old = self._ident
        self._ident = ident
        try:
            self.save(aux_changed=True)
        except Exception:
            if self._ident is None:
                self._ident = old
            raise
        self.epoch += 1

    # -- life cycle -----------------------------------------------------------------
    def terminate(self) -> None:
        """TERMINATE DF: wipe everything, keep only the terminated marker."""
        self.replace(Identity.terminated_state())

    def activate(self) -> None:
        """ACTIVATE FILE / factory reset: fresh identity, full retry counters.

        The identity is written *before* the counters are cleared so that a
        power cut can never restore tries for the old PINs.
        """
        self.replace(Identity.fresh())
        self._clear_tries()

    def _clear_tries(self) -> None:
        for t in self.tries:
            t.clear()

    # -- signature counter ------------------------------------------------------------
    def signature_count(self) -> int:
        v = self.dsc.get() - self.ident.dsc_base
        if v < 0:
            return 0
        return v if v <= 0xFFFFFF else 0xFFFFFF

    def reset_signature_count(self) -> None:
        """Set the base so that the counter reads 0 (caller saves)."""
        self.ident.dsc_base = self.dsc.get()

    def set_signature_count(self, value: int) -> None:
        self.ident.dsc_base = self.dsc.get() - value

    # -- PIN tries ------------------------------------------------------------------------
    def remaining(self, which: int) -> int:
        if which == pgp.RC and self.ident.pins[pgp.RC] is None:
            return 0
        return self.tries[which].remaining()


_default = None


def default() -> IdentityStore:
    """The single :class:`IdentityStore` shared by the applet, the device
    menus and the backup provider (one in-RAM view of the identity)."""
    global _default
    if _default is None:
        _default = IdentityStore()
    return _default


def _reset_default() -> None:
    """Tests only: forget the shared instance."""
    global _default
    _default = None
