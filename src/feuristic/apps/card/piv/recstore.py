# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""A :class:`~feuristic.core.store.RecordStore` living in a key sub-range.

The protected namespace ``CARD`` is shared by three applications
(docs/architecture.md §6.1): OpenPGP uses norcow keys ``0x00–0x0F``, PIV
``0x10–0x3F`` and AES ``0x40–0x5F``. :class:`RecordStore` maps slot ``i`` to
key ``i``; :class:`OffsetRecordStore` maps slot ``i`` to key
``key_offset + i`` with identical copy-on-write semantics (same record
layout, same recovery rules in :meth:`load`).

This module is used by both the PIV and the AES applets. It disappears
once ``RecordStore`` grows an optional ``key_offset`` parameter (requested
change, see the PIV/AES report).
"""

from ....core.errors import InvalidInput, NotFound, StorageCorrupted, StorageFull
from ....core.store import RecordStore, pack, unpack
from ....platform import kv


class OffsetRecordStore(RecordStore):
    def __init__(
        self, app: int, capacity: int, max_payload: int, rtype: int, key_offset: int, public: bool = False
    ) -> None:
        super().__init__(app, capacity, max_payload, rtype, public)
        if key_offset < 0 or key_offset + self.slots > 256:
            raise ValueError("key range")
        self.key_offset = key_offset

    def key_range(self) -> tuple:
        """``(first_key, last_key)`` (inclusive) used in the namespace."""
        return self.key_offset, self.key_offset + self.slots - 1

    def _key(self, slot: int) -> int:
        return self.key_offset + slot

    # The methods below mirror RecordStore with slot -> key translation.
    def load(self) -> None:
        index = {}
        stale = []
        self.corrupt_slots = []
        max_gen = 0
        for slot in range(self.slots):
            raw = kv.get(self.app, self._key(slot), self.public)
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
        for slot in stale:
            kv.delete(self.app, self._key(slot), self.public)
        self._index = index
        self._next_gen = max_gen + 1

    def get_record(self, uid: bytes):
        entry = self._idx().get(bytes(uid))
        if entry is None:
            raise NotFound
        rec = unpack(kv.get(self.app, self._key(entry[0]), self.public))
        if rec.uid != bytes(uid):
            raise StorageCorrupted("index mismatch")
        return rec

    def _free_slot(self, exclude: int = -1) -> int:
        used = {e[0] for e in self._idx().values()}
        for slot in range(self.slots):
            if slot in used or slot == exclude:
                continue
            if kv.get(self.app, self._key(slot), self.public) is None:
                return slot
        raise StorageFull("no free slot")

    def put(self, uid: bytes, payload: bytes, flags: int = 0) -> None:
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
        kv.set(self.app, self._key(slot), pack(self.rtype, flags, gen, uid, payload), self.public)
        self._next_gen = gen + 1
        idx[uid] = (slot, gen, flags)
        if old is not None:
            kv.delete(self.app, self._key(old[0]), self.public)

    def delete(self, uid: bytes) -> bool:
        uid = bytes(uid)
        idx = self._idx()
        entry = idx.get(uid)
        if entry is None:
            return False
        kv.delete(self.app, self._key(entry[0]), self.public)
        del idx[uid]
        return True

    def wipe(self) -> None:
        for slot in range(self.slots):
            kv.delete(self.app, self._key(slot), self.public)
        self._index = {}
        self._next_gen = 1
        self.corrupt_slots = []
