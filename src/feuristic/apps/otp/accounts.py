# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""OTP account model and persistence (spec F01, §4, §5, §8.1; R04, R08).

Storage
-------

* Account records live in a :class:`feuristic.core.store.RecordStore` in the
  protected namespace :data:`feuristic.core.namespaces.OTP` (capacity
  :data:`CAPACITY` = 32, spec §5; payload ≤ 256 B, docs/architecture.md §6.3).
  The record ``uid`` is 8 random bytes. Updates are copy-on-write, so records
  move between slots: nothing may be keyed by slot number.
* The payload is a canonical CBOR map (RFC 8949 §4.2.1) with small integer
  keys::

      { 0: 1 (schema), 1: kind (0 TOTP / 1 HOTP), 2: issuer (tstr),
        3: account (tstr), 4: secret (bstr), 5: algorithm (0 SHA1 /
        1 SHA256 / 2 SHA512), 6: digits, 7: period (TOTP only),
        8: counter base (HOTP only), 9: counter index (HOTP only) }

* HOTP counters (spec §4 "compteur persistant, avance atomique") are
  :class:`feuristic.core.counters.RedundantCounter` pairs in the public
  namespace :data:`feuristic.core.namespaces.OTP_COUNTERS`, keys
  ``2*i`` / ``2*i + 1`` for a **stable counter index** ``i`` in
  ``0..CAPACITY`` allocated when the account is created and stored in the
  record. ``CAPACITY + 1`` indices exist so that a replacement can always
  take a fresh index before releasing the old one. The persisted value is
  the number of codes generated since import; the next RFC 4226 moving
  factor is ``counter_base + persisted``.

Power-loss safety
-----------------

* HOTP: the counter is advanced (``advance_to``) **before** the code is
  returned; a cut before the advance shows nothing, a cut after it skips a
  value. A moving factor is therefore never used twice.
* Create: the counter pair at the new index is reset *before* the record is
  written; replace: a fresh index is reset, the new record written
  (atomic copy-on-write), then the old index is reset; delete: the record is
  deleted, then its counter reset. Orphaned counter values left by a cut are
  always reset before an index is reused.
* Replacing (or restoring over) an HOTP account **with the same secret**
  never moves its counter backwards (``max`` of both values), so restoring
  an old backup cannot replay codes.

UI contract
-----------

Methods that need a user decision take the injected ``ui`` object
(:mod:`feuristic.core.interaction`) and raise
:class:`feuristic.core.errors.UserCancelled` on refusal/timeout. The others
are synchronous; the UI glue shows the matching ``*_prompt`` first.
"""

from micropython import const

from ...core import cbor, namespaces
from ...core.counters import RedundantCounter
from ...core.errors import (
    InvalidInput,
    NotFound,
    PolicyDenied,
    StorageCorrupted,
    StorageFull,
    UserCancelled,
)
from ...core.i18n import t
from ...core.interaction import DANGER, NORMAL, SENSITIVE, Prompt
from ...core.store import UID_LEN, RecordStore
from ...platform import crypto
from . import hotp as _hotp
from . import strings as _strings
from . import totp as _totp
from . import uri as _uri

_strings.register()

RTYPE = const(0x01)  # RecordStore record type of an OTP account
CAPACITY = const(32)  # spec §5
MAX_PAYLOAD = const(256)  # docs/architecture.md §6.3
COUNTER_INDICES = const(33)  # CAPACITY + 1
SCHEMA = const(1)
EXPORT_DISPLAY_TIMEOUT_MS = const(60_000)  # spec §8.1: QR auto-hidden after 60 s

# classify_import() results
IMPORT_NEW = const(0)
IMPORT_DUPLICATE = const(1)  # same issuer + account + secret
IMPORT_CONFLICT = const(2)  # same issuer + account, different secret

_K_SCHEMA = const(0)
_K_KIND = const(1)
_K_ISSUER = const(2)
_K_ACCOUNT = const(3)
_K_SECRET = const(4)
_K_ALG = const(5)
_K_DIGITS = const(6)
_K_PERIOD = const(7)
_K_CBASE = const(8)
_K_CIDX = const(9)

_ALG_CODES = (_hotp.SHA1, _hotp.SHA256, _hotp.SHA512)
_KIND_CODES = (_uri.TOTP, _uri.HOTP)


class AlreadyExists(PolicyDenied):
    """An account with the same issuer and account name already exists
    (a ``PolicyDenied`` so that the backup restore contract is honoured)."""


class Account:
    """A stored OTP account (decoded record). ``period``/``counter_*`` are
    ``None`` when not applicable. Never log or print ``secret``."""

    def __init__(self, uid, params, counter_index) -> None:
        self.uid = uid
        self.kind = params.kind
        self.issuer = params.issuer
        self.account = params.account
        self.secret = params.secret
        self.algorithm = params.algorithm
        self.digits = params.digits
        self.period = params.period
        self.counter_base = params.counter
        self.counter_index = counter_index

    @property
    def is_hotp(self) -> bool:
        return self.kind == _uri.HOTP

    def label(self) -> str:
        return _uri.label_of(self.issuer, self.account)

    def __repr__(self) -> str:  # never print the secret
        return f"Account({self.uid.hex()}, {self.kind!r}, {self.issuer!r}, {self.account!r})"


def _sort_key(acc):
    return (acc.issuer.lower(), acc.account.lower(), acc.issuer, acc.account, acc.uid)


def _encode(params, counter_index) -> bytes:
    m = {
        _K_SCHEMA: SCHEMA,
        _K_KIND: _KIND_CODES.index(params.kind),
        _K_ISSUER: params.issuer,
        _K_ACCOUNT: params.account,
        _K_SECRET: params.secret,
        _K_ALG: _ALG_CODES.index(params.algorithm),
        _K_DIGITS: params.digits,
    }
    if params.kind == _uri.TOTP:
        m[_K_PERIOD] = params.period
    else:
        m[_K_CBASE] = params.counter
        m[_K_CIDX] = counter_index
    return cbor.encode(m)


def _small_index(m, key, table):
    v = m.get(key)
    if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v < len(table):
        raise StorageCorrupted("otp record field")
    return table[v]


def _decode(uid: bytes, payload: bytes) -> Account:
    try:
        m = cbor.decode(payload, canonical=True, max_depth=1, max_items=32)
    except InvalidInput:
        raise StorageCorrupted("otp record encoding")
    if not isinstance(m, dict) or m.get(_K_SCHEMA) != SCHEMA:
        raise StorageCorrupted("otp record schema")
    kind = _small_index(m, _K_KIND, _KIND_CODES)
    algorithm = _small_index(m, _K_ALG, _ALG_CODES)
    expected = (_K_SCHEMA, _K_KIND, _K_ISSUER, _K_ACCOUNT, _K_SECRET, _K_ALG, _K_DIGITS)
    expected += (_K_PERIOD,) if kind == _uri.TOTP else (_K_CBASE, _K_CIDX)
    if len(m) != len(expected) or any(k not in m for k in expected):
        raise StorageCorrupted("otp record keys")
    cidx = None
    if kind == _uri.HOTP:
        cidx = m[_K_CIDX]
        if isinstance(cidx, bool) or not isinstance(cidx, int) or not 0 <= cidx < COUNTER_INDICES:
            raise StorageCorrupted("otp counter index")
    try:
        params = _uri.OtpParams(
            kind,
            m[_K_ISSUER],
            m[_K_ACCOUNT],
            m[_K_SECRET],
            algorithm,
            m[_K_DIGITS],
            m.get(_K_PERIOD),
            m.get(_K_CBASE),
        )
    except InvalidInput:
        raise StorageCorrupted("otp record value")
    return Account(uid, params, cidx)


def _counter(index: int) -> RedundantCounter:
    return RedundantCounter(namespaces.OTP_COUNTERS, 2 * index, 2 * index + 1, public=True)


class OtpAccounts:
    """The OTP account database (one instance per running firmware; see :func:`default`)."""

    def __init__(self, store=None) -> None:
        if store is None:
            store = RecordStore(namespaces.OTP, CAPACITY, MAX_PAYLOAD, RTYPE, public=False)
        self.store = store
        self.corrupt_uids = []

    # -- loading / queries --------------------------------------------------
    def load(self) -> None:
        """Scan storage (run at unlock): resolves interrupted updates."""
        self.store.load()
        for _account in self._iter_accounts():
            pass

    def __len__(self) -> int:
        return len(self.store)

    def is_full(self) -> bool:
        return self.store.is_full()

    def get(self, uid) -> Account:
        """Decoded account ``uid``. Raises NotFound / StorageCorrupted."""
        uid = bytes(uid)
        rec = self.store.get_record(uid)
        return _decode(uid, rec.payload)

    def _iter_accounts(self):
        """Scan records without retaining every decoded OTP secret."""
        corrupt = []
        for uid in self.store.uids():
            try:
                account = self.get(uid)
            except StorageCorrupted:
                corrupt.append(uid)
                continue
            yield account
        self.corrupt_uids = corrupt

    def accounts(self) -> list:
        """All readable accounts sorted by issuer, then account (case-insensitive).

        Undecodable records are skipped and listed in :attr:`corrupt_uids`.
        """
        out = list(self._iter_accounts())
        out.sort(key=_sort_key)
        return out

    def find(self, issuer: str, account: str):
        """Account with exactly this issuer and account name, or ``None``."""
        found = None
        for acc in self._iter_accounts():
            if acc.issuer == issuer and acc.account == account and (found is None or acc.uid < found.uid):
                found = acc
        return found

    def classify_import(self, params):
        """Return ``(IMPORT_NEW | IMPORT_DUPLICATE | IMPORT_CONFLICT, existing_or_None)``."""
        existing = self.find(params.issuer, params.account)
        if existing is None:
            return IMPORT_NEW, None
        if crypto.ct_equal(existing.secret, params.secret):
            return IMPORT_DUPLICATE, existing
        return IMPORT_CONFLICT, existing

    # -- creation / replacement ------------------------------------------------
    def _new_uid(self) -> bytes:
        while True:
            uid = crypto.random_bytes(UID_LEN)
            if uid not in self.store:
                return uid

    def _used_indices(self) -> set:
        used = set()
        for acc in self._iter_accounts():
            if acc.counter_index is not None:
                used.add(acc.counter_index)
        return used

    def _alloc_index(self) -> int:
        used = self._used_indices()
        for i in range(COUNTER_INDICES):
            if i not in used:
                # an orphan value may remain after a power cut: reset before use
                _counter(i).reset()
                return i
        raise StorageFull("no HOTP counter index")  # pragma: no cover - CAPACITY + 1 indices

    def add(self, params, replace_uid=None) -> bytes:
        """Store ``params`` (validated :class:`~feuristic.apps.otp.uri.OtpParams`).

        Without ``replace_uid`` a new account is created (raises
        :class:`AlreadyExists` if issuer + account are taken, StorageFull at
        capacity). With ``replace_uid`` that account is atomically replaced
        (same uid). No user interaction: callers confirm first.
        """
        if not isinstance(params, _uri.OtpParams):
            raise InvalidInput("params")
        other = self.find(params.issuer, params.account)
        if replace_uid is None:
            if other is not None:
                raise AlreadyExists("account exists")
            if self.is_full():
                raise StorageFull("otp store full")
            uid = self._new_uid()
            cidx = self._alloc_index() if params.kind == _uri.HOTP else None
            self.store.put(uid, _encode(params, cidx))
            return uid

        uid = bytes(replace_uid)
        old = self.get(uid)
        if other is not None and other.uid != uid:
            raise AlreadyExists("account exists")
        if params.kind == _uri.HOTP and old.is_hotp and crypto.ct_equal(old.secret, params.secret):
            # never move the moving factor of the same key backwards
            current = self.hotp_counter(old)
            if current > params.counter:
                params = _uri.OtpParams(
                    params.kind,
                    params.issuer,
                    params.account,
                    params.secret,
                    params.algorithm,
                    params.digits,
                    None,
                    current,
                )
        cidx = self._alloc_index() if params.kind == _uri.HOTP else None
        self.store.put(uid, _encode(params, cidx))
        if old.counter_index is not None:
            _counter(old.counter_index).reset()
        return uid

    async def import_params(self, params, ui) -> bytes:
        """Interactive import of parsed URI ``params`` (QR import flow).

        * duplicate (same issuer, account and secret) → :class:`AlreadyExists`
          (UI: ``otp.import.exists``);
        * same issuer and account, different secret → ``replace_prompt`` (DANGER);
        * otherwise → ``import_prompt`` (shows a weak-secret warning when needed).

        Raises UserCancelled if the user refuses, StorageFull at capacity.
        Returns the uid of the stored account.
        """
        status, existing = self.classify_import(params)
        if status == IMPORT_DUPLICATE:
            raise AlreadyExists("duplicate account")
        if status == IMPORT_CONFLICT:
            if not await ui.confirm(self.replace_prompt(params)):
                raise UserCancelled
            return self.add(params, existing.uid)
        if self.is_full():
            raise StorageFull("otp store full")
        if not await ui.confirm(self.import_prompt(params)):
            raise UserCancelled
        return self.add(params)

    async def import_uri(self, text, ui) -> bytes:
        """Parse an ``otpauth://`` URI (InvalidInput if malformed) and import it."""
        return await self.import_params(_uri.parse(text), ui)

    # -- modification ------------------------------------------------------------
    def rename(self, uid, issuer: str, account: str) -> None:
        """Change issuer and account name (bounded, validated; HOTP counter kept)."""
        _uri.check_issuer(issuer)
        _uri.check_account(account)
        acc = self.get(uid)
        other = self.find(issuer, account)
        if other is not None and other.uid != acc.uid:
            raise AlreadyExists("account exists")
        params = _uri.OtpParams(
            acc.kind,
            issuer,
            account,
            acc.secret,
            acc.algorithm,
            acc.digits,
            acc.period,
            acc.counter_base,
        )
        self.store.put(acc.uid, _encode(params, acc.counter_index))

    def delete(self, uid) -> bool:
        """Delete the account and reset its HOTP counter. False if absent."""
        uid = bytes(uid)
        try:
            acc = self.get(uid)
            cidx = acc.counter_index
        except StorageCorrupted:
            cidx = None  # orphan counter is reset when its index is reused
        except NotFound:
            return False
        deleted = self.store.delete(uid)
        if cidx is not None:
            _counter(cidx).reset()
        return deleted

    def wipe(self) -> None:
        """Erase every account and counter (factory reset)."""
        self.store.wipe()
        for i in range(COUNTER_INDICES):
            _counter(i).reset()
        self.corrupt_uids = []

    # -- codes ---------------------------------------------------------------------
    def hotp_counter(self, acc) -> int:
        """Next unused RFC 4226 moving factor of HOTP account ``acc`` (or uid)."""
        if not isinstance(acc, Account):
            acc = self.get(acc)
        if not acc.is_hotp:
            raise InvalidInput("not an HOTP account")
        return acc.counter_base + _counter(acc.counter_index).get()

    async def generate_hotp(self, uid, ui) -> str:
        """Confirm, persist the counter advance, then return the HOTP code.

        Spec §4: "compteur persistant, avance atomique et confirmation avant
        génération". The moving factor shown in the prompt is the one used.
        Raises UserCancelled, NotFound, InvalidInput (not HOTP) or
        StorageFull (counter exhausted).
        """
        acc = self.get(uid)
        value = self.hotp_counter(acc)
        if value >= _hotp.MAX_COUNTER:
            raise StorageFull("counter exhausted")
        if not await ui.confirm(self.hotp_prompt(acc, value)):
            raise UserCancelled
        # state may have changed while the prompt was displayed: re-read
        acc = self.get(uid)
        if not acc.is_hotp:
            raise NotFound
        ctr = _counter(acc.counter_index)
        used = ctr.get()
        value = acc.counter_base + used
        if value >= _hotp.MAX_COUNTER:
            raise StorageFull("counter exhausted")
        ctr.advance_to(used + 1)  # persist BEFORE releasing the code
        return _hotp.hotp(acc.secret, value, acc.digits, acc.algorithm)

    def totp_code(self, uid, clock=None):
        """``(code, seconds_remaining)`` of TOTP account ``uid``.

        Raises :class:`~feuristic.apps.otp.totp.TimeNotSynchronised` when the
        session clock is not set (UI: ``otp.time_not_set``).
        """
        acc = self.get(uid)
        if acc.is_hotp:
            raise InvalidInput("not a TOTP account")
        return _totp.totp_now(acc.secret, acc.period, acc.digits, acc.algorithm, clock)

    # -- export (spec §8.1) --------------------------------------------------------
    def export_params(self, uid):
        """:class:`~feuristic.apps.otp.uri.OtpParams` of ``uid`` with the
        current (next unused) HOTP counter."""
        acc = self.get(uid)
        counter = self.hotp_counter(acc) if acc.is_hotp else None
        return _uri.OtpParams(
            acc.kind,
            acc.issuer,
            acc.account,
            acc.secret,
            acc.algorithm,
            acc.digits,
            acc.period,
            counter,
        )

    def export_uri(self, uid) -> str:
        """Standard ``otpauth://`` URI of ``uid`` for QR display (spec §8.1).

        **Contract for the UI glue** — this reveals the secret, so the glue
        MUST, in this order:

        1. re-authenticate the user with the device PIN (spec §9);
        2. ``await ui.confirm(export_prompt(account))`` (DANGER, hold to
           confirm) and stop unless it returns True;
        3. call ``export_uri(uid)`` and render it as a QR code on the screen
           only (never over USB, spec §10.3);
        4. hide the QR after :data:`EXPORT_DISPLAY_TIMEOUT_MS` (60 s) or on
           any button press, and drop the string reference.

        HOTP URIs carry ``counter=`` = the next unused moving factor, so an
        authenticator importing it continues without reusing a value.
        """
        return _uri.build(self.export_params(uid))

    # -- prompts ---------------------------------------------------------------------
    @staticmethod
    def _id_fields(issuer: str, account: str) -> list:
        fields = []
        if issuer:
            fields.append(("otp.field.issuer", issuer))
        fields.append(("otp.field.account", account))
        return fields

    def import_prompt(self, params) -> Prompt:
        fields = self._id_fields(params.issuer, params.account)
        fields.append(("otp.field.type", params.kind.upper()))
        fields.append(("otp.field.algorithm", params.algorithm))
        fields.append(("otp.field.digits", str(params.digits)))
        if params.kind == _uri.TOTP:
            fields.append(("otp.field.period", t("otp.unit.seconds", params.period)))
        else:
            fields.append(("otp.field.counter", str(params.counter)))
        p = Prompt("otp.import", "otp.import.title", fields, SENSITIVE if params.weak_secret else NORMAL)
        p.warning = None
        if params.weak_secret:
            p.warning = "otp.import.weak_secret"
            p.fields += (("otp.field.warning", t("otp.import.weak_secret")),)
        return p

    def replace_prompt(self, params) -> Prompt:
        fields = self._id_fields(params.issuer, params.account)
        fields.append(("otp.field.warning", t("otp.replace.warning")))
        p = Prompt("otp.replace", "otp.replace.title", fields, DANGER)
        p.warning = "otp.replace.warning"
        return p

    def hotp_prompt(self, acc, counter: int) -> Prompt:
        fields = self._id_fields(acc.issuer, acc.account)
        fields.append(("otp.field.counter", str(counter)))
        p = Prompt("otp.hotp_generate", "otp.hotp_generate.title", fields, SENSITIVE)
        p.warning = "otp.hotp_generate.warning"
        return p

    def delete_prompt(self, acc) -> Prompt:
        fields = self._id_fields(acc.issuer, acc.account)
        fields.append(("otp.field.warning", t("otp.delete.warning")))
        p = Prompt("otp.delete", "otp.delete.title", fields, DANGER)
        p.warning = "otp.delete.warning"
        return p

    def export_prompt(self, acc) -> Prompt:
        """DANGER prompt shown before :meth:`export_uri` (spec §8.1).

        ``prompt.warning`` is ``"otp.export.warning"`` ("anyone who
        photographs this QR code can reproduce your codes"); the translated
        text is also included as the last field.
        """
        fields = self._id_fields(acc.issuer, acc.account)
        fields.append(("otp.field.type", acc.kind.upper()))
        fields.append(("otp.field.warning", t("otp.export.warning")))
        p = Prompt("otp.export", "otp.export.title", fields, DANGER)
        p.warning = "otp.export.warning"
        return p


_default = None


def default() -> OtpAccounts:
    """The firmware-wide :class:`OtpAccounts` instance (shared by menus,
    importer and backup provider so that they see one consistent index)."""
    global _default
    if _default is None:
        _default = OtpAccounts()
    return _default


def _reset_default() -> None:
    """Drop the shared instance (tests, wipe)."""
    global _default
    _default = None
