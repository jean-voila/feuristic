# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Persistent state of the PIV application (docs/architecture.md §6, §7).

Records (protected namespace ``CARD``, norcow keys ``0x10..0x16``, one
:class:`~feuristic.apps.card.piv.recstore.OffsetRecordStore`, record type
:data:`RTYPE`, copy-on-write so every update is atomic):

=================  ==================  =======================================
uid (8 bytes)      payload (canonical CBOR map, integer keys)
=================  ==================  =======================================
``PIVslot`` ‖ ref  slot identity       0 schema, 1 slot, 2 alg, 3 sk (P-256),
                                       4 public point (P-256), 5 p, 6 q, 7 e
                                       (RSA), 8 PIN policy, 9 origin,
                                       10 certificate DER, 11 CertInfo byte
``PIVdata\\0``      data objects        { object tag (int): value (bstr) }
``PIVcred\\0``      credentials         0 schema, 1 PIN salt, 2 PIN hash,
                                       3 PUK salt, 4 PUK hash, 5 admin key
                                       alg, 6 admin key, 7 default flags,
                                       8 PIN max retries, 9 PUK max retries
=================  ==================  =======================================

* A slot record is at most :data:`MAX_PAYLOAD` = 2400 bytes (key +
  certificate ≤ 2048 bytes, architecture §6.3); all PIV records together are
  bounded by :data:`TOTAL_MAX` = 10 KiB.
* PIN and PUK are stored as ``HMAC-SHA-256(key=salt16, msg=padded8)`` inside
  the protected (storage-DEK encrypted) namespace; the administration key is
  stored raw in the same protected namespace.
* Retry counters are *failure* counters in the public namespace
  ``CARD_COUNTERS`` (PIN: keys ``0x20/0x21``, PUK: ``0x22/0x23``), as
  :class:`~feuristic.core.counters.RedundantCounter` pairs. A verification
  first **persists the incremented failure count, then compares**
  (SP 800-73-4 Part 2 §3.2.1 retry semantics; a power cut during the compare
  can only cost an attempt, never grant a free one). Success resets it.
* Until the user sets their own values the credentials are the factory
  defaults (PIN ``123456``, PUK ``12345678``, AES-192 administration key
  ``0102…08``×3) and :attr:`Credentials.flags` records which ones are still
  default so menus can warn (see docs/protocols/piv.md §PIN policy).
"""

from micropython import const

from ....core import cbor, namespaces
from ....core import store as record_store
from ....core.counters import RedundantCounter
from ....core.errors import (
    InvalidInput,
    PinBlocked,
    PinInvalid,
    StorageCorrupted,
    StorageFull,
)
from ....platform import crypto
from . import consts as pc
from . import x509
from .recstore import OffsetRecordStore

RTYPE = const(0x50)
KEY_OFFSET = const(0x10)
CAPACITY = const(6)  # 4 slot identities + data objects + credentials
MAX_PAYLOAD = const(2400)
TOTAL_MAX = const(10240)
SCHEMA = const(1)

UID_DATA = b"PIVdata\x00"
UID_CREDS = b"PIVcred\x00"

CTR_PIN_A = const(0x20)
CTR_PIN_B = const(0x21)
CTR_PUK_A = const(0x22)
CTR_PUK_B = const(0x23)

FLAG_PIN_DEFAULT = const(0x01)
FLAG_PUK_DEFAULT = const(0x02)
FLAG_MGMT_DEFAULT = const(0x04)

PIN_LEN = const(8)
PIN_MIN = const(6)
SALT_LEN = const(16)


def slot_uid(slot: int) -> bytes:
    return b"PIVslot" + bytes((slot,))


def pad_pin(pin: bytes) -> bytes:
    """Pad a 6..8 byte PIN/PUK with ``0xFF`` to 8 bytes (SP 800-73-4 Part 2 §2.4.3)."""
    pin = bytes(pin)
    if not PIN_MIN <= len(pin) <= PIN_LEN:
        raise InvalidInput("PIN length")
    return pin + b"\xff" * (PIN_LEN - len(pin))


def pin_format_ok(block: bytes) -> bool:
    """True for 6..8 printable ASCII bytes followed by ``0xFF`` padding to 8 bytes."""
    if len(block) != PIN_LEN:
        return False
    n = 0
    while n < PIN_LEN and block[n] != 0xFF:
        if not 0x20 <= block[n] <= 0x7E:
            return False
        n += 1
    if n < PIN_MIN:
        return False
    return all(block[i] == 0xFF for i in range(n, PIN_LEN))


def _hash_secret(salt: bytes, padded: bytes) -> bytes:
    return crypto.hmac_sha256(salt, padded)


def _bstr(m: dict, k: int, size=None, optional: bool = False):
    v = m.get(k)
    if v is None and optional:
        return None
    if not isinstance(v, (bytes, bytearray)):
        raise StorageCorrupted("piv record field")
    if size is not None and len(v) != size:
        raise StorageCorrupted("piv record size")
    return bytes(v)


def _uint(m: dict, k: int, optional: bool = False):
    v = m.get(k)
    if v is None and optional:
        return None
    if isinstance(v, bool) or not isinstance(v, int) or v < 0:
        raise StorageCorrupted("piv record int")
    return v


# ---------------------------------------------------------------------------
# slot identity
# ---------------------------------------------------------------------------


class SlotData:
    """Key and certificate of one PIV key slot."""

    def __init__(
        self,
        slot: int,
        alg=None,
        sk=None,
        p=None,
        q=None,
        e: int = pc.RSA_E,
        pub=None,
        pin_policy=None,
        origin: int = pc.ORIGIN_GENERATED,
        cert=None,
        certinfo: int = 0,
    ) -> None:
        if slot not in pc.KEY_SLOTS:
            raise InvalidInput("PIV slot")
        self.slot = slot
        self.alg = alg
        self.sk = sk
        self.p = p
        self.q = q
        self.e = e
        self.pub = pub
        self.pin_policy = pc.DEFAULT_PIN_POLICY[slot] if pin_policy is None else pin_policy
        self.origin = origin
        self.cert = cert
        self.certinfo = certinfo
        self._rsa = None

    def __repr__(self) -> str:  # never print key material
        return f"SlotData({self.slot:02X}, alg={self.alg}, cert={self.cert is not None})"

    @property
    def has_key(self) -> bool:
        return self.alg is not None

    # -- key material helpers ------------------------------------------------
    def rsa_key(self):
        """Completed :class:`~feuristic.platform.crypto.RsaKey` (cached)."""
        if self.alg != pc.ALG_RSA2048:
            raise InvalidInput("not an RSA slot")
        if self._rsa is None:
            self._rsa = crypto.rsa_complete(crypto.RsaKey(self.p, self.q, self.e))
        return self._rsa

    def public_tlv(self) -> bytes:
        """Content of the ``7F49`` public key template (SP 800-73-4 Part 2 Table 10)."""
        from ....core import tlv

        if self.alg == pc.ALG_P256:
            return tlv.build(0x86, self.pub)
        if self.alg == pc.ALG_RSA2048:
            k = self.rsa_key()
            return tlv.build(0x81, k.n) + tlv.build(0x82, self.e.to_bytes(3, "big"))
        raise InvalidInput("empty slot")

    def spki(self) -> bytes:
        if self.alg == pc.ALG_P256:
            return x509.spki_p256(self.pub)
        if self.alg == pc.ALG_RSA2048:
            return x509.spki_rsa(self.rsa_key().n, self.e)
        raise InvalidInput("empty slot")

    def fingerprint(self) -> str:
        """Display fingerprint: first 8 bytes of SHA-256(SPKI DER), upper-case hex."""
        return x509.display_fingerprint(self.spki())

    # -- (de)serialisation -----------------------------------------------------
    def encode(self) -> bytes:
        m = {0: SCHEMA, 1: self.slot, 8: self.pin_policy, 9: self.origin}
        if self.alg == pc.ALG_P256:
            m[2] = self.alg
            m[3] = self.sk
            m[4] = self.pub
        elif self.alg == pc.ALG_RSA2048:
            m[2] = self.alg
            m[5] = self.p
            m[6] = self.q
            m[7] = self.e
        elif self.alg is not None:
            raise InvalidInput("PIV algorithm")
        if self.cert is not None:
            m[10] = self.cert
            m[11] = self.certinfo
        return record_store.encode_payload(m)

    @classmethod
    def decode(cls, payload: bytes) -> "SlotData":
        try:
            m = cbor.decode(payload, canonical=True)
        except InvalidInput:
            raise StorageCorrupted("piv slot cbor")
        if not isinstance(m, dict) or m.get(0) != SCHEMA:
            raise StorageCorrupted("piv slot schema")
        slot = _uint(m, 1)
        if slot not in pc.KEY_SLOTS:
            raise StorageCorrupted("piv slot id")
        alg = _uint(m, 2, optional=True)
        d = cls(slot, pin_policy=_uint(m, 8), origin=_uint(m, 9))
        if alg == pc.ALG_P256:
            d.alg = alg
            d.sk = _bstr(m, 3, 32)
            d.pub = _bstr(m, 4, 65)
        elif alg == pc.ALG_RSA2048:
            d.alg = alg
            d.p = _bstr(m, 5)
            d.q = _bstr(m, 6)
            d.e = _uint(m, 7)
            if len(d.p) != pc.RSA_BYTES // 2 or len(d.q) != pc.RSA_BYTES // 2:
                raise StorageCorrupted("piv rsa size")
        elif alg is not None:
            raise StorageCorrupted("piv slot alg")
        d.cert = _bstr(m, 10, optional=True)
        if d.cert is not None:
            d.certinfo = _uint(m, 11)
        return d


# ---------------------------------------------------------------------------
# credentials
# ---------------------------------------------------------------------------


class Credentials:
    def __init__(self) -> None:
        self.pin_salt = b""
        self.pin_hash = b""
        self.puk_salt = b""
        self.puk_hash = b""
        self.mgmt_alg = pc.DEFAULT_MGMT_ALG
        self.mgmt_key = pc.DEFAULT_MGMT_KEY
        self.flags = FLAG_PIN_DEFAULT | FLAG_PUK_DEFAULT | FLAG_MGMT_DEFAULT
        self.pin_max = pc.DEFAULT_PIN_RETRIES
        self.puk_max = pc.DEFAULT_PUK_RETRIES

    def __repr__(self) -> str:
        return f"Credentials(mgmt_alg={self.mgmt_alg:#x}, flags={self.flags:#x})"

    @classmethod
    def defaults(cls) -> "Credentials":
        c = cls()
        c.set_secret(pc.REF_PIN, pad_pin(pc.DEFAULT_PIN))
        c.set_secret(pc.REF_PUK, pad_pin(pc.DEFAULT_PUK))
        return c

    def set_secret(self, ref: int, padded: bytes) -> None:
        if not pin_format_ok(padded):
            raise InvalidInput("PIN format")
        salt = crypto.random_bytes(SALT_LEN)
        h = _hash_secret(salt, padded)
        if ref == pc.REF_PIN:
            self.pin_salt, self.pin_hash = salt, h
            is_default = crypto.ct_equal(padded, pad_pin(pc.DEFAULT_PIN))
            bit = FLAG_PIN_DEFAULT
        elif ref == pc.REF_PUK:
            self.puk_salt, self.puk_hash = salt, h
            is_default = crypto.ct_equal(padded, pad_pin(pc.DEFAULT_PUK))
            bit = FLAG_PUK_DEFAULT
        else:
            raise InvalidInput("reference")
        self.flags = (self.flags | bit) if is_default else (self.flags & ~bit)

    def matches(self, ref: int, padded: bytes) -> bool:
        if ref == pc.REF_PIN:
            salt, h = self.pin_salt, self.pin_hash
        else:
            salt, h = self.puk_salt, self.puk_hash
        return crypto.ct_equal(_hash_secret(salt, padded), h)

    def set_mgmt_key(self, alg: int, key: bytes) -> None:
        if pc.MGMT_ALGS.get(alg) != len(key):
            raise InvalidInput("management key")
        self.mgmt_alg = alg
        self.mgmt_key = bytes(key)
        default = alg == pc.DEFAULT_MGMT_ALG and crypto.ct_equal(key, pc.DEFAULT_MGMT_KEY)
        if default:
            self.flags |= FLAG_MGMT_DEFAULT
        else:
            self.flags &= ~FLAG_MGMT_DEFAULT

    def encode(self) -> bytes:
        return cbor.encode(
            {
                0: SCHEMA,
                1: self.pin_salt,
                2: self.pin_hash,
                3: self.puk_salt,
                4: self.puk_hash,
                5: self.mgmt_alg,
                6: self.mgmt_key,
                7: self.flags,
                8: self.pin_max,
                9: self.puk_max,
            }
        )

    @classmethod
    def decode(cls, payload: bytes) -> "Credentials":
        try:
            m = cbor.decode(payload, canonical=True)
        except InvalidInput:
            raise StorageCorrupted("piv creds cbor")
        if not isinstance(m, dict) or m.get(0) != SCHEMA:
            raise StorageCorrupted("piv creds schema")
        c = cls()
        c.pin_salt = _bstr(m, 1, SALT_LEN)
        c.pin_hash = _bstr(m, 2, 32)
        c.puk_salt = _bstr(m, 3, SALT_LEN)
        c.puk_hash = _bstr(m, 4, 32)
        c.mgmt_alg = _uint(m, 5)
        c.mgmt_key = _bstr(m, 6)
        if pc.MGMT_ALGS.get(c.mgmt_alg) != len(c.mgmt_key):
            raise StorageCorrupted("piv mgmt key")
        c.flags = _uint(m, 7)
        c.pin_max = _uint(m, 8)
        c.puk_max = _uint(m, 9)
        if not 1 <= c.pin_max <= 15 or not 1 <= c.puk_max <= 15:
            raise StorageCorrupted("piv retries")
        return c


# ---------------------------------------------------------------------------
# store
# ---------------------------------------------------------------------------


class PivStore:
    """All persistent PIV state; one instance per running firmware (:func:`default`)."""

    def __init__(self, store=None) -> None:
        if store is None:
            store = OffsetRecordStore(namespaces.CARD, CAPACITY, MAX_PAYLOAD, RTYPE, KEY_OFFSET)
        self.store = store
        self._creds = None
        self._objects = None
        #: bumped whenever credentials change or PIV is wiped; applets drop
        #: their volatile security status when it changes
        self.epoch = 0
        self.pin_counter = RedundantCounter(namespaces.CARD_COUNTERS, CTR_PIN_A, CTR_PIN_B, public=True)
        self.puk_counter = RedundantCounter(namespaces.CARD_COUNTERS, CTR_PUK_A, CTR_PUK_B, public=True)

    def load(self) -> None:
        """Scan storage (at unlock): finishes interrupted copy-on-write updates."""
        self.store.load()
        self._creds = None
        self._objects = None

    # -- budget ----------------------------------------------------------------
    def _check_budget(self, uid: bytes, new_len: int) -> None:
        total = new_len
        for other in self.store.uids():
            if other != uid:
                p = self.store.get(other)
                total += len(p) if p is not None else 0
        if total > TOTAL_MAX:
            raise StorageFull("PIV storage budget")

    def _put(self, uid: bytes, payload: bytes) -> None:
        if len(payload) > MAX_PAYLOAD:
            raise StorageFull("PIV record too large")
        self._check_budget(uid, len(payload))
        self.store.put(uid, payload)

    def used_bytes(self) -> int:
        total = 0
        for uid in self.store.uids():
            p = self.store.get(uid)
            total += len(p) if p is not None else 0
        return total

    # -- slots -------------------------------------------------------------------
    def get_slot(self, slot: int):
        """:class:`SlotData` of ``slot`` or ``None`` (neither key nor certificate)."""
        payload = self.store.get(slot_uid(slot))
        if payload is None:
            return None
        d = SlotData.decode(payload)
        if d.slot != slot:
            raise StorageCorrupted("piv slot mismatch")
        return d

    def put_slot(self, data: SlotData) -> None:
        if not data.has_key and data.cert is None:
            self.delete_slot(data.slot)
            return
        self._put(slot_uid(data.slot), data.encode())

    def delete_slot(self, slot: int) -> bool:
        return self.store.delete(slot_uid(slot))

    # -- data objects ------------------------------------------------------------
    def objects(self) -> dict:
        if self._objects is None:
            payload = self.store.get(UID_DATA)
            objs = {}
            if payload is not None:
                try:
                    m = cbor.decode(payload, canonical=True)
                except InvalidInput:
                    raise StorageCorrupted("piv objects")
                if not isinstance(m, dict):
                    raise StorageCorrupted("piv objects")
                for k, v in m.items():
                    if k not in pc.DATA_OBJECT_CAPS or not isinstance(v, (bytes, bytearray)):
                        raise StorageCorrupted("piv object entry")
                    objs[k] = bytes(v)
            self._objects = objs
        return self._objects

    def get_object(self, tag: int):
        return self.objects().get(tag)

    def put_object(self, tag: int, value) -> None:
        """Store (``value`` bytes) or delete (``None``) a non-certificate data object."""
        cap = pc.DATA_OBJECT_CAPS.get(tag)
        if cap is None:
            raise InvalidInput("PIV object")
        objs = dict(self.objects())
        if value is None:
            objs.pop(tag, None)
        else:
            if len(value) > cap:
                raise StorageFull("PIV object too large")
            objs[tag] = bytes(value)
        if objs:
            self._put(UID_DATA, cbor.encode(objs))
        else:
            self.store.delete(UID_DATA)
        self._objects = objs

    # -- credentials ---------------------------------------------------------------
    def creds(self) -> Credentials:
        if self._creds is None:
            payload = self.store.get(UID_CREDS)
            self._creds = Credentials.defaults() if payload is None else Credentials.decode(payload)
        return self._creds

    def save_creds(self, creds: Credentials) -> None:
        self._put(UID_CREDS, creds.encode())
        self._creds = creds

    def is_customized(self) -> bool:
        """True once credentials were explicitly stored (user set PIN/PUK/key)."""
        return UID_CREDS in self.store

    def _counter(self, ref: int) -> RedundantCounter:
        if ref == pc.REF_PIN:
            return self.pin_counter
        if ref == pc.REF_PUK:
            return self.puk_counter
        raise InvalidInput("reference")

    def max_retries(self, ref: int) -> int:
        c = self.creds()
        return c.pin_max if ref == pc.REF_PIN else c.puk_max

    def retries_remaining(self, ref: int) -> int:
        left = self.max_retries(ref) - self._counter(ref).get()
        return left if left > 0 else 0

    def is_blocked(self, ref: int) -> bool:
        return self.retries_remaining(ref) == 0

    def check_secret(self, ref: int, padded: bytes) -> None:
        """Verify PIN/PUK. Raises :class:`PinBlocked` or :class:`PinInvalid`.

        The failure counter is persisted *before* the comparison and cleared
        only after a successful one.
        """
        ctr = self._counter(ref)
        mx = self.max_retries(ref)
        failures = ctr.get()
        if failures >= mx:
            raise PinBlocked
        ctr.advance_to(failures + 1)
        if self.creds().matches(ref, padded):
            ctr.reset()
            return
        raise PinInvalid(mx - failures - 1)

    def set_secret(self, ref: int, padded: bytes) -> None:
        """Replace PIN or PUK and clear its failure counter."""
        creds = self.creds()
        creds.set_secret(ref, padded)
        self.save_creds(creds)
        self._counter(ref).reset()
        self.epoch += 1

    def set_mgmt_key(self, alg: int, key: bytes) -> None:
        creds = self.creds()
        creds.set_mgmt_key(alg, key)
        self.save_creds(creds)
        self.epoch += 1

    # -- reset -----------------------------------------------------------------------
    def wipe(self) -> None:
        """Delete every PIV record and counter (back to factory defaults)."""
        self.store.wipe()
        self.pin_counter.reset()
        self.puk_counter.reset()
        self._creds = None
        self._objects = None
        self.epoch += 1


_default = None


def default() -> PivStore:
    """The firmware-wide :class:`PivStore` (shared by applet, menus and backup)."""
    global _default
    if _default is None:
        _default = PivStore()
    return _default


def _reset_default() -> None:  # tests
    global _default
    _default = None
