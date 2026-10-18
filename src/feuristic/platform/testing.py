# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Host-side test doubles for the platform facade (never frozen into firmware).

* :data:`KV` — a :class:`FakeKV` modelling norcow semantics, with power-loss
  injection (``crash_after_ops``) and a byte budget modelling the 64 KiB sector.
* :data:`CLOCK` — a controllable monotonic clock.
* :func:`deterministic_rng` — reproducible ``random_bytes`` for tests.
"""


class PowerLoss(Exception):
    """Raised by FakeKV when an injected power cut happens."""


class StorageFull(Exception):
    """Raised by FakeKV when the modelled sector has no room left."""


class FakeKV:
    # T3B1 blockwise norcow (storage/norcow_blockwise.h, FLASH_BLOCK_SIZE=16).
    # Protected values add a 12-byte ChaCha20 IV and a 16-byte Poly1305 tag
    # (storage/storage.c); public counters/settings are NOT encrypted.
    # This is also an upper bound for T2B1's smaller bitwise item format.
    BLOCK_SIZE = 16
    ENCRYPTION_OVERHEAD = 28
    SECTOR_BYTES = 64 * 1024 - 16

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.data = {}
        self.unlocked = True
        self.crash_after_ops = None  # int: number of low-level ops before PowerLoss
        self.ops = 0
        self.writes = 0
        self.capacity = self.SECTOR_BYTES

    # -- low-level helpers -------------------------------------------------
    def _tick(self) -> None:
        self.ops += 1
        if self.crash_after_ops is not None and self.ops > self.crash_after_ops:
            self.crash_after_ops = None
            raise PowerLoss

    @staticmethod
    def _k(app: int, key: int, public: bool) -> tuple:
        if not 1 <= app <= 0x3F or not 0 <= key <= 255:
            raise ValueError("invalid app/key")
        return (app | (0x80 if public else 0), key)

    def used_bytes(self) -> int:
        return sum(self._item_size(v, bool(k[0] & 0x80)) for k, v in self.data.items())

    def _item_size(self, v: bytes, public: bool = False) -> int:
        n = len(v) + (0 if public else self.ENCRYPTION_OVERHEAD)
        block = self.BLOCK_SIZE
        if n <= block - 4:  # key(2) + length(2) + value fit in one block
            return block
        # A large item has one header block, then the value + validity byte.
        return block + (n + 1 + block - 1) // block * block

    # -- API ---------------------------------------------------------------
    def get(self, app: int, key: int, public: bool = False):
        k = self._k(app, key, public)
        if not public and not self.unlocked:
            raise RuntimeError("storage locked")
        v = self.data.get(k)
        return None if v is None else bytes(v)

    def set(self, app: int, key: int, value: bytes, public: bool = False) -> None:
        k = self._k(app, key, public)
        if not public and not self.unlocked:
            raise RuntimeError("storage locked")
        old = self.data.get(k)
        new_total = self.used_bytes() - (self._item_size(old, public) if old is not None else 0)
        if new_total + self._item_size(value, public) > self.capacity:
            raise StorageFull
        # norcow: delete the old item first, then append the new one
        if old is not None:
            self._tick()
            del self.data[k]
        self._tick()
        self.data[k] = bytes(value)
        self.writes += 1

    def delete(self, app: int, key: int, public: bool = False) -> bool:
        k = self._k(app, key, public)
        if not public and not self.unlocked:
            raise RuntimeError("storage locked")
        if k not in self.data:
            return False
        self._tick()
        del self.data[k]
        return True


class FakeClock:
    def __init__(self) -> None:
        self.ms = 1_000

    def now_ms(self) -> int:
        return self.ms

    def advance(self, ms: int) -> None:
        self.ms += ms


KV = FakeKV()
CLOCK = FakeClock()


def deterministic_rng(seed: bytes = b"feuristic-tests"):
    """Return a ``random_bytes``-compatible callable driven by SHA-256 in counter mode."""
    import hashlib

    state = {"ctr": 0}

    def _rng(n: int) -> bytes:
        out = b""
        while len(out) < n:
            out += hashlib.sha256(seed + state["ctr"].to_bytes(8, "big")).digest()
            state["ctr"] += 1
        return out[:n]

    return _rng


def set_rng(fn) -> None:
    """Install (or with ``None`` remove) a deterministic RNG override."""
    from . import crypto

    crypto._test_rng = fn


def reset_all() -> None:
    KV.reset()
    CLOCK.ms = 1_000
    set_rng(None)
    from ..core import clock as _session_clock

    _session_clock.CLOCK.clear()
