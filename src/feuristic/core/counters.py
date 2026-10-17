# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Monotonic counters that never go backwards across power cuts.

A :class:`RedundantCounter` keeps its value in two storage keys A and B
(8-byte big-endian each). The value is ``max(A, B)``; an advance first overwrites
the copy holding the *smaller* value, then the other one. Because norcow
deletes before rewriting, at every instant at least one copy holds a value
greater than or equal to the last committed one, so the read value never
goes below a value that was already *used* (callers use a value only after
:meth:`advance_to` returns).

:class:`NonceAllocator` hands out unique 64-bit values backed by a redundant
counter used as a *reservation* high-water mark, so that flash is written
once per ``block`` allocations instead of once per allocation.
"""

from micropython import const

from ..platform import kv
from .errors import InvalidInput, StorageFull

_SIZE = const(8)
MAX_VALUE = 0xFFFFFFFFFFFFFFFF


class RedundantCounter:
    def __init__(self, app: int, key_a: int, key_b: int, public: bool = True) -> None:
        self.app = app
        self.key_a = key_a
        self.key_b = key_b
        self.public = public

    def _read(self, key: int) -> int:
        raw = kv.get(self.app, key, self.public)
        if raw is None or len(raw) != _SIZE:
            return 0
        return int.from_bytes(raw, "big")

    def get(self) -> int:
        return max(self._read(self.key_a), self._read(self.key_b))

    def advance_to(self, value: int) -> None:
        """Persist ``value`` (must be strictly greater than the current value)."""
        if value > MAX_VALUE:
            raise StorageFull("counter exhausted")
        if value <= self.get():
            raise InvalidInput("counter must increase")
        raw = value.to_bytes(_SIZE, "big")
        # Overwrite the *stale* copy first so that, at every instant, at least
        # one copy holds a value >= the last committed one (norcow deletes an
        # item before rewriting it).
        if self._read(self.key_a) >= self._read(self.key_b):
            first, second = self.key_b, self.key_a
        else:
            first, second = self.key_a, self.key_b
        kv.set(self.app, first, raw, self.public)
        kv.set(self.app, second, raw, self.public)

    def increment(self) -> int:
        """Persist ``get() + 1`` and return it."""
        v = self.get() + 1
        self.advance_to(v)
        return v

    def reset(self) -> None:
        """Remove both copies (only for wipe / identity deletion)."""
        kv.delete(self.app, self.key_a, self.public)
        kv.delete(self.app, self.key_b, self.public)


class NonceAllocator:
    """Unique, strictly increasing 64-bit values, power-loss safe.

    The persisted counter stores the *end of the current reservation*. At
    construction (or after power loss) allocation restarts from the
    persisted value, so values handed out before a cut are never reused —
    at worst up to ``block - 1`` values are skipped.
    """

    def __init__(self, counter: RedundantCounter, block: int = 256) -> None:
        if block < 1:
            raise ValueError("block")
        self.counter = counter
        self.block = block
        self._next = None
        self._limit = 0

    def allocate(self) -> int:
        if self._next is None or self._next >= self._limit:
            start = self.counter.get() if self._next is None else self._next
            limit = start + self.block
            self.counter.advance_to(limit)  # reserve before use
            self._next = start
            self._limit = limit
        v = self._next
        self._next = v + 1
        return v
