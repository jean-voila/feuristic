# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Power-loss-safe record store on top of the platform key/value storage.

norcow (upstream storage) deletes an item *before* appending its new value,
so a power cut during an update can lose the value. :class:`RecordStore`
provides atomic insert/replace/delete with **copy-on-write slots**:

1. a new version of a record is written into a *free* slot with a larger
   ``generation`` number;
2. only then the slot holding the previous version is deleted.

If power is lost between the two steps both versions exist; :meth:`load`
(run at every unlock) keeps the highest generation per ``uid`` and removes
the stale copy. A partially written new item is either invisible (T3B1
validity flag) or rejected by the storage MAC, so the old version survives.

Record layout (all integers big-endian)::

    0      1        2      3      4            8          16
    | 0xFE | schema | type | flags| generation | uid (8B) | payload ... |
"""

from micropython import const

from ..platform import kv
from .errors import InvalidInput, NotFound, StorageCorrupted, StorageFull
from .packed_index import RecordIndex

MAGIC = const(0xFE)
HEADER_LEN = const(16)
UID_LEN = const(8)
SCHEMA = const(1)


class Record:
    """Decoded record (header fields + payload)."""

    def __init__(self, uid: bytes, rtype: int, flags: int, generation: int, payload: bytes) -> None:
        self.uid = uid
        self.rtype = rtype
        self.flags = flags
        self.generation = generation
        self.payload = payload


def pack(rtype: int, flags: int, generation: int, uid: bytes, payload: bytes) -> bytes:
    if len(uid) != UID_LEN:
        raise InvalidInput("uid length")
    return (
        bytes((MAGIC, SCHEMA, rtype & 0xFF, flags & 0xFF))
        + (generation & 0xFFFFFFFF).to_bytes(4, "big")
        + bytes(uid)
        + bytes(payload)
    )


def unpack(raw: bytes) -> Record:
    if raw is None or len(raw) < HEADER_LEN or raw[0] != MAGIC:
        raise StorageCorrupted("bad record header")
    if raw[1] != SCHEMA:
        raise StorageCorrupted("unsupported record schema")
    return Record(
        bytes(raw[8:16]),
        raw[2],
        raw[3],
        int.from_bytes(raw[4:8], "big"),
        bytes(raw[HEADER_LEN:]),
    )


class RecordStore:
    """A fixed-size array of slots in one storage namespace.

    ``capacity`` is the maximum number of live records; the store uses
    ``capacity + 1`` slots so that a replacement is always possible when the
    store is full.
    """

    def __init__(
        self, app: int, capacity: int, max_payload: int, rtype: int, public: bool = False, key_offset: int = 0
    ) -> None:
        if capacity + 1 + key_offset > 256:
            raise ValueError("too many slots")
        #: first storage key used by slot 0 (lets several stores share a namespace)
        self.key_offset = key_offset
        self.app = app
        self.capacity = capacity
        self.slots = capacity + 1
        self.max_payload = max_payload
        self.rtype = rtype
        self.public = public
        self._index = None  # packed uid -> (slot, generation, flags)
        self._next_gen = 1
        self.corrupt_slots = []

    # -- loading / recovery ------------------------------------------------
    def load(self) -> None:
        """Scan all slots, resolve interrupted updates and build the index."""
        index = RecordIndex(self.slots)
        stale = []
        self.corrupt_slots = []
        max_gen = 0
        for slot in range(self.slots):
            raw = kv.get(self.app, self.key_offset + slot, self.public)
            if raw is None:
                continue
            try:
                rec = unpack(raw)
            except StorageCorrupted:
                self.corrupt_slots.append(slot)
                continue
            if rec.rtype != self.rtype:
                self.corrupt_slots.append(slot)
                continue
            max_gen = max(max_gen, rec.generation)
            prev = index.get(rec.uid)
            if prev is None:
                index[rec.uid] = (slot, rec.generation, rec.flags)
            elif rec.generation > prev[1]:
                stale.append(prev[0])
                index[rec.uid] = (slot, rec.generation, rec.flags)
            else:
                stale.append(slot)
        # finish interrupted copy-on-write updates
        for slot in stale:
            kv.delete(self.app, self.key_offset + slot, self.public)
        self._index = index
        self._next_gen = max_gen + 1

    def _idx(self) -> RecordIndex:
        if self._index is None:
            self.load()
        return self._index

    # -- queries -------------------------------------------------------------
    def uids(self) -> list:
        """UIDs of live records, ordered by slot number (stable)."""
        idx = self._idx()
        return [uid for uid, _ in sorted(idx.items(), key=lambda kv_: kv_[1][0])]

    def __len__(self) -> int:
        return len(self._idx())

    def __contains__(self, uid: bytes) -> bool:
        return bytes(uid) in self._idx()

    def is_full(self) -> bool:
        return len(self._idx()) >= self.capacity

    def get_record(self, uid: bytes) -> Record:
        entry = self._idx().get(bytes(uid))
        if entry is None:
            raise NotFound
        raw = kv.get(self.app, self.key_offset + entry[0], self.public)
        rec = unpack(raw)
        if rec.uid != bytes(uid):
            raise StorageCorrupted("index mismatch")
        return rec

    def get(self, uid: bytes):
        """Payload of ``uid`` or ``None``."""
        try:
            return self.get_record(uid).payload
        except NotFound:
            return None

    def flags(self, uid: bytes) -> int:
        entry = self._idx().get(bytes(uid))
        if entry is None:
            raise NotFound
        return entry[2]

    # -- updates -------------------------------------------------------------
    def _free_slot(self, exclude: int = -1) -> int:
        used = {e[0] for e in self._idx().values()}
        for slot in range(self.slots):
            if (
                slot not in used
                and slot != exclude
                and kv.get(self.app, self.key_offset + slot, self.public) is None
            ):
                return slot
        raise StorageFull("no free slot")

    def put(self, uid: bytes, payload: bytes, flags: int = 0) -> None:
        """Atomically insert or replace the record ``uid``."""
        uid = bytes(uid)
        if len(payload) > self.max_payload:
            raise InvalidInput("record too large")
        if not 0 <= flags <= 0xFF:
            raise InvalidInput("flags")
        idx = self._idx()
        old = idx.get(uid)
        if old is None and len(idx) >= self.capacity:
            raise StorageFull("store full")
        slot = self._free_slot()
        gen = self._next_gen
        raw = pack(self.rtype, flags, gen, uid, payload)
        kv.set(self.app, self.key_offset + slot, raw, self.public)
        self._next_gen = gen + 1
        idx[uid] = (slot, gen, flags)
        if old is not None:
            kv.delete(self.app, self.key_offset + old[0], self.public)

    def delete(self, uid: bytes) -> bool:
        """Delete ``uid``. Returns False if it did not exist."""
        uid = bytes(uid)
        idx = self._idx()
        entry = idx.get(uid)
        if entry is None:
            return False
        kv.delete(self.app, self.key_offset + entry[0], self.public)
        del idx[uid]
        return True

    def wipe(self) -> None:
        """Delete every slot of the namespace (including corrupt ones)."""
        for slot in range(self.slots):
            kv.delete(self.app, self.key_offset + slot, self.public)
        if self._index is not None:
            self._index.clear()
        self._next_gen = 1
        self.corrupt_slots.clear()

    def replace_all(self, items) -> None:
        """Atomically (per record) make the store contain exactly ``items``.

        ``items`` is an iterable of ``(uid, payload, flags)``. Records not in
        ``items`` are deleted *after* all new versions are written.
        """
        items = list(items)
        keep = set()
        for uid, payload, flags in items:
            self.put(uid, payload, flags)
            keep.add(bytes(uid))
        for uid in self.uids():
            if uid not in keep:
                self.delete(uid)


class Blob:
    """A single atomically replaceable value stored in two alternating keys.

    Used for objects that must be replaced as a whole (largeBlob array,
    settings maps). Layout of each copy: ``generation(u32) || payload``.
    """

    def __init__(self, app: int, key_a: int, key_b: int, max_len: int, public: bool = False) -> None:
        self.app = app
        self.keys = (key_a, key_b)
        self.max_len = max_len
        self.public = public

    def _read(self):
        best = None
        best_key = None
        for k in self.keys:
            raw = kv.get(self.app, k, self.public)
            if raw is None or len(raw) < 4:
                continue
            gen = int.from_bytes(raw[:4], "big")
            if best is None or gen > best[0]:
                best = (gen, bytes(raw[4:]))
                best_key = k
        return best, best_key

    def get(self):
        best, _ = self._read()
        return None if best is None else best[1]

    def set(self, payload: bytes) -> None:  # noqa: A003
        if len(payload) > self.max_len:
            raise InvalidInput("blob too large")
        best, best_key = self._read()
        gen = 1 if best is None else best[0] + 1
        target = self.keys[1] if best_key == self.keys[0] else self.keys[0]
        kv.set(self.app, target, gen.to_bytes(4, "big") + bytes(payload), self.public)
        # the older copy is left in place as a fallback; it is overwritten by
        # the next update (A/B alternation).

    def clear(self) -> None:
        for k in self.keys:
            kv.delete(self.app, k, self.public)
