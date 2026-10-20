# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""AES-256-GCM keys and nonce allocation (spec F05, §7, §10.6; R12).

Storage
-------

* Up to :data:`MAX_KEYS` = 16 keys, identifiers ``1..16``, in the protected
  namespace ``CARD`` (norcow keys ``0x40..0x50``, one
  :class:`~feuristic.apps.card.piv.recstore.OffsetRecordStore`, record type
  :data:`RTYPE`). The record uid is 8 random bytes chosen at creation and
  kept when the key is modified or overwritten by a restore.
* Payload (canonical CBOR, ≤ 96 bytes, architecture §6.3)::

      { 0: 1 (schema), 1: id (1..16), 2: key (32 B), 3: name (tstr ≤ 16),
        4: enabled (bool), 5: policy (0 every operation / 1 once per session) }

* Keys are 32 bytes from the strong RNG, after the RNG health tests of
  :mod:`feuristic.apps.card.aes.rng`; they are generated on the device only
  and leave it only inside an encrypted backup (spec §8.2).

Nonces (spec §7 "aucun réemploi de nonce pour une même clé, y compris après
coupure de courant")
--------------------------------------------------------------------------

``nonce = namespace(8) || index(4)`` (96 bits, big-endian index) where

* ``namespace = HKDF(master secret, "card/aes-nonce-namespace", context =
  record uid || uint32(counter >> 32))[:8]`` separates devices, key instances
  and counter epochs (residual collision probability 2**-64 per pair);
* ``index = counter & 0xffffffff`` never wraps within a namespace: crossing
  2**32 selects the next epoch instead;
* ``counter`` comes from a :class:`~feuristic.core.counters.NonceAllocator`
  over the redundant public counter ``CARD_COUNTERS`` keys ``0x00/0x01``.
  It is **global across keys**, strictly increasing, reserved in flash
  *before* use (blocks of :data:`NONCE_BLOCK`), so a value is never handed
  out twice, even across power loss (at most ``NONCE_BLOCK − 1`` values are
  skipped). It is never reset, not even by deleting all AES keys.

A restored key also raises the counter to the ``nonce_floor`` recorded in
its backup (the source device's counter at export time), see
docs/protocols/backup-aes.md. Legacy ``prefix(4) || counter(8)`` ciphertexts
remain decryptable: APDU/backup v1 carry an opaque 12-byte nonce, not its
internal construction. The legacy KDF helper remains for migration vectors.
"""

from micropython import const

from ....core import cbor, kdf, namespaces
from ....core.counters import NonceAllocator, RedundantCounter
from ....core.errors import InvalidInput, NotFound, StorageCorrupted, StorageFull
from ....core.store import UID_LEN
from ....platform import crypto
from ..piv.recstore import OffsetRecordStore

RTYPE = const(0x60)
KEY_OFFSET = const(0x40)
MAX_KEYS = const(16)
MAX_PAYLOAD = const(96)
NAME_MAX = const(16)
KEY_LEN = const(32)
SCHEMA = const(1)
NONCE_BLOCK = const(256)
NONCE_PREFIX_LEN = const(4)
NONCE_NAMESPACE_LEN = const(8)

POLICY_EVERY = const(0)  # confirmation on the device for every operation
POLICY_SESSION = const(1)  # first operation of the card session only
POLICIES = (POLICY_EVERY, POLICY_SESSION)


def check_name(name) -> str:
    if not isinstance(name, str) or not 1 <= len(name) <= NAME_MAX:
        raise InvalidInput("AES key name")
    for ch in name:
        if not " " <= ch <= "~":
            raise InvalidInput("AES key name characters")
    return name


def check_kid(kid) -> int:
    if isinstance(kid, bool) or not isinstance(kid, int) or not 1 <= kid <= MAX_KEYS:
        raise InvalidInput("AES key id")
    return kid


def check_policy(policy) -> int:
    if isinstance(policy, bool) or policy not in POLICIES:
        raise InvalidInput("AES policy")
    return policy


def key_check_value(key: bytes) -> str:
    """Non-secret fingerprint of a key: SHA-256("feuristic/aes-kcv\\0" || key)[:8], hex."""
    return crypto.sha256(b"feuristic/aes-kcv\x00" + bytes(key))[:8].hex().upper()


class AesKey:
    def __init__(
        self, uid: bytes, kid: int, key: bytes, name: str, enabled: bool = True, policy: int = 0
    ) -> None:
        self.uid = uid
        self.kid = kid
        self.key = key
        self.name = name
        self.enabled = enabled
        self.policy = policy

    def __repr__(self) -> str:  # never print the key
        return f"AesKey(#{self.kid} {self.name!r}, enabled={self.enabled}, policy={self.policy})"

    def fingerprint(self) -> str:
        return key_check_value(self.key)

    def encode(self) -> bytes:
        return cbor.encode(
            {0: SCHEMA, 1: self.kid, 2: self.key, 3: self.name, 4: bool(self.enabled), 5: self.policy}
        )

    @classmethod
    def decode(cls, uid: bytes, payload: bytes) -> "AesKey":
        try:
            m = cbor.decode(payload, canonical=True)
        except InvalidInput:
            raise StorageCorrupted("aes key cbor")
        if not isinstance(m, dict) or m.get(0) != SCHEMA or len(m) != 6:
            raise StorageCorrupted("aes key schema")
        key = m.get(2)
        enabled = m.get(4)
        if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_LEN or not isinstance(enabled, bool):
            raise StorageCorrupted("aes key fields")
        try:
            return cls(
                uid, check_kid(m.get(1)), bytes(key), check_name(m.get(3)), enabled, check_policy(m.get(5))
            )
        except InvalidInput:
            raise StorageCorrupted("aes key fields")


class AesKeyStore:
    """AES keys + global nonce allocator; one instance per firmware (:func:`default`)."""

    def __init__(self, store=None) -> None:
        if store is None:
            store = OffsetRecordStore(namespaces.CARD, MAX_KEYS, MAX_PAYLOAD, RTYPE, KEY_OFFSET)
        self.store = store
        self.counter = RedundantCounter(
            namespaces.CARD_COUNTERS,
            namespaces.CARD_CTR_AES_NONCE_A,
            namespaces.CARD_CTR_AES_NONCE_B,
            public=True,
        )
        self.allocator = NonceAllocator(self.counter, NONCE_BLOCK)
        self.corrupt_uids = []
        #: bumped on every key change; the applet then drops its security
        #: environment and per-session confirmations
        self.epoch = 0
        self._namespace_cache = {}

    def load(self) -> None:
        self.store.load()
        self.entries()

    # -- queries -------------------------------------------------------------------
    def entries(self) -> list:
        """Readable keys sorted by id (corrupt records listed in :attr:`corrupt_uids`)."""
        out = []
        corrupt = []
        for uid in self.store.uids():
            try:
                out.append(AesKey.decode(uid, self.store.get_record(uid).payload))
            except StorageCorrupted:
                corrupt.append(uid)
        self.corrupt_uids = corrupt
        out.sort(key=lambda k: k.kid)
        return out

    def get(self, kid: int):
        for k in self.entries():
            if k.kid == kid:
                return k
        return None

    def get_by_uid(self, uid: bytes) -> AesKey:
        rec = self.store.get_record(bytes(uid))
        return AesKey.decode(rec.uid, rec.payload)

    def free_ids(self) -> list:
        used = {k.kid for k in self.entries()}
        return [i for i in range(1, MAX_KEYS + 1) if i not in used]

    # -- updates -------------------------------------------------------------------
    def _new_uid(self) -> bytes:
        while True:
            uid = crypto.random_bytes(UID_LEN)
            if uid not in self.store:
                return uid

    def _write(self, k: AesKey) -> None:
        self.store.put(k.uid, k.encode())
        self.epoch += 1

    def create(self, name: str, policy: int = POLICY_EVERY, kid=None, rng=None) -> AesKey:
        """Generate and store a new key. ``rng(n)`` defaults to the health-checked RNG."""
        check_name(name)
        check_policy(policy)
        free = self.free_ids()
        if kid is None:
            if not free:
                raise StorageFull("no free AES key id")
            kid = free[0]
        elif check_kid(kid) not in free:
            raise InvalidInput("AES key id in use")
        if rng is None:
            from . import rng as _rng

            rng = _rng.default().health.random_bytes
        material = rng(KEY_LEN)
        if len(material) != KEY_LEN:
            raise InvalidInput("rng")
        k = AesKey(self._new_uid(), kid, bytes(material), name, True, policy)
        self._write(k)
        return k

    def put_restored(self, kid: int, key: bytes, name: str, enabled: bool, policy: int) -> AesKey:
        """Store a restored key (atomic; an existing key with ``kid`` is replaced in place)."""
        check_kid(kid)
        check_name(name)
        check_policy(policy)
        if len(key) != KEY_LEN:
            raise InvalidInput("AES key length")
        cur = self.get(kid)
        uid = cur.uid if cur is not None else self._new_uid()
        k = AesKey(uid, kid, bytes(key), name, bool(enabled), policy)
        self._write(k)
        return k

    def _modify(self, kid: int):
        k = self.get(check_kid(kid))
        if k is None:
            raise NotFound
        return k

    def rename(self, kid: int, name: str) -> None:
        k = self._modify(kid)
        k.name = check_name(name)
        self._write(k)

    def set_enabled(self, kid: int, enabled: bool) -> None:
        k = self._modify(kid)
        k.enabled = bool(enabled)
        self._write(k)

    def set_policy(self, kid: int, policy: int) -> None:
        k = self._modify(kid)
        k.policy = check_policy(policy)
        self._write(k)

    def delete(self, kid: int) -> bool:
        k = self.get(check_kid(kid))
        if k is None:
            return False
        self.store.delete(k.uid)
        self._namespace_cache.pop(k.uid, None)
        self.epoch += 1
        return True

    def wipe(self) -> None:
        """Delete all keys. The nonce counter is deliberately kept."""
        self.store.wipe()
        self._namespace_cache = {}
        self.epoch += 1

    # -- nonces --------------------------------------------------------------------
    def nonce_prefix(self, master_secret: bytes, uid: bytes) -> bytes:
        """Legacy four-byte construction, never used for new encryption."""
        return kdf.derive(master_secret, b"card/aes-nonce-prefix", NONCE_PREFIX_LEN, uid)

    def nonce_namespace(self, master_secret: bytes, uid: bytes, epoch: int) -> bytes:
        # One store belongs to one device power session. Retain only the
        # current public namespace per key; old epochs never grow the cache.
        cached = self._namespace_cache.get(uid)
        if cached is None or cached[0] != epoch:
            context = uid + epoch.to_bytes(4, "big")
            value = kdf.derive(master_secret, b"card/aes-nonce-namespace", NONCE_NAMESPACE_LEN, context)
            cached = (epoch, value)
            self._namespace_cache[uid] = cached
        return cached[1]

    def allocate_nonce(self, master_secret: bytes, k: AesKey) -> bytes:
        """A fresh 12-byte nonce, persisted as used before it is returned."""
        value = self.allocator.allocate()
        namespace = self.nonce_namespace(master_secret, k.uid, value >> 32)
        return namespace + (value & 0xFFFFFFFF).to_bytes(4, "big")

    def nonce_floor(self) -> int:
        """Upper bound (exclusive) of every counter value ever handed out."""
        return self.counter.get()

    def raise_nonce_floor(self, value: int) -> None:
        """Ensure future counter values are ``>= value`` (backup restore)."""
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise InvalidInput("nonce floor")
        if value > self.counter.get():
            self.counter.advance_to(value)
        # restart allocation from the persisted value (skips the in-memory
        # remainder of the current reservation, never reuses it)
        self.allocator = NonceAllocator(self.counter, NONCE_BLOCK)


_default = None


def default() -> AesKeyStore:
    global _default
    if _default is None:
        _default = AesKeyStore()
    return _default


def _reset_default() -> None:  # tests
    global _default
    _default = None
