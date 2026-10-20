# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Fixed-capacity RAM indexes, without persistent per-record Python objects.

Only public identifiers and metadata live here. The protected record bytes
and copy-on-write storage format are unchanged. Reserving these small arenas
before scanning/writing records prevents each new account pinning another
fragment of the non-moving MicroPython heap.
"""


class RecordIndex:
    # occupied(1), uid(8), slot(1), generation(8), flags(1)
    WIDTH = 19

    def __init__(self, capacity):
        self.capacity = capacity
        self.data = bytearray(capacity * self.WIDTH)
        self.count = 0

    def _find(self, uid):
        if len(uid) != 8:
            return -1
        offset = 0
        while offset < len(self.data):
            if self.data[offset]:
                index = 0
                while index < 8 and self.data[offset + 1 + index] == uid[index]:
                    index += 1
                if index == 8:
                    return offset
            offset += self.WIDTH
        return -1

    def _value(self, offset):
        return (
            self.data[offset + 9],
            int.from_bytes(self.data[offset + 10 : offset + 18], "big"),
            self.data[offset + 18],
        )

    def __len__(self):
        return self.count

    def __contains__(self, uid):
        return self._find(uid) >= 0

    def get(self, uid, default=None):
        offset = self._find(uid)
        return default if offset < 0 else self._value(offset)

    def __setitem__(self, uid, value):
        slot, generation, flags = value
        encoded = bytearray(self.WIDTH)
        encoded[0] = 1
        encoded[1:9] = uid
        encoded[9] = slot
        encoded[10:18] = generation.to_bytes(8, "big")
        encoded[18] = flags
        offset = self._find(uid)
        inserted = offset < 0
        if offset < 0:
            for offset in range(0, len(self.data), self.WIDTH):
                if not self.data[offset]:
                    break
            else:
                raise ValueError("record index full")
        self.data[offset : offset + self.WIDTH] = encoded
        if inserted:
            self.count += 1

    def __delitem__(self, uid):
        offset = self._find(uid)
        if offset < 0:
            raise KeyError(uid)
        self.data[offset] = 0
        self.count -= 1

    def items(self):
        for offset in range(0, len(self.data), self.WIDTH):
            if self.data[offset]:
                yield bytes(self.data[offset + 1 : offset + 9]), self._value(offset)

    def values(self):
        for offset in range(0, len(self.data), self.WIDTH):
            if self.data[offset]:
                yield self._value(offset)

    def clear(self):
        offset = 0
        while offset < len(self.data):
            self.data[offset] = 0
            offset += self.WIDTH
        self.count = 0


class CredentialIndex:
    # uid(8), RP SHA-256(32), creation sequence(4)
    WIDTH = 44

    def __init__(self, capacity):
        self.capacity = capacity
        self.data = bytearray(capacity * self.WIDTH)
        self.count = 0

    def __len__(self):
        return self.count

    def __getitem__(self, index):
        if index < 0:
            index += self.count
        if not 0 <= index < self.count:
            raise IndexError(index)
        offset = index * self.WIDTH
        return (
            bytes(self.data[offset : offset + 8]),
            bytes(self.data[offset + 8 : offset + 40]),
            int.from_bytes(self.data[offset + 40 : offset + 44], "big"),
        )

    def __iter__(self):
        for index in range(self.count):
            yield self[index]

    def __setitem__(self, index, value):
        if not 0 <= index < self.count:
            raise IndexError(index)
        uid, rp_hash, sequence = value
        encoded = uid + rp_hash + sequence.to_bytes(4, "big")
        offset = index * self.WIDTH
        self.data[offset : offset + self.WIDTH] = encoded

    def append(self, value):
        if self.count == self.capacity:
            raise ValueError("credential index full")
        self.count += 1
        try:
            self[self.count - 1] = value
        except BaseException:
            self.count -= 1
            raise

    def _sequence(self, index):
        offset = index * self.WIDTH
        return int.from_bytes(self.data[offset + 40 : offset + 44], "big")

    def matching(self, rp_hash):
        positions = []
        for index in range(self.count):
            offset = index * self.WIDTH
            if self.data[offset + 8 : offset + 40] == rp_hash:
                positions.append(index)
        positions.sort(key=self._sequence, reverse=True)
        for index in positions:
            yield self[index]

    def remove_uid(self, uid):
        if len(uid) != 8:
            return
        for index in range(self.count):
            start = index * self.WIDTH
            matched = 0
            while matched < 8 and self.data[start + matched] == uid[matched]:
                matched += 1
            if matched != 8:
                continue
            offset = (index + 1) * self.WIDTH
            end = self.count * self.WIDTH
            # No slices or new objects after mutation starts: an OOM cannot
            # leave duplicate or partially shifted credential metadata.
            while offset < end:
                self.data[offset - self.WIDTH] = self.data[offset]
                offset += 1
            self.count -= 1
            break

    def clear(self):
        self.count = 0
