# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Persistent key/value storage facade.

On the device this is upstream's encrypted norcow storage (``trezor.config``):

* ``app`` is a namespace in ``1..0x3F``; ``key`` is ``0..255``;
* ``public=False`` values are encrypted with the storage DEK and are only
  accessible while the storage is unlocked (device PIN entered);
* ``public=True`` values are stored in clear and readable while locked.

Values are at most ``MAX_VALUE_LEN`` bytes. Writes are **not** atomic with
respect to power loss (norcow deletes the old item before appending the new
one): use :mod:`feuristic.core.store` / :mod:`feuristic.core.counters` for
anything that must survive a power cut.

On the host the backend is a :class:`feuristic.platform.testing.FakeKV`
instance that models the same semantics, including power-loss injection.
"""

from micropython import const

from ..core.errors import StorageFull
from . import _backend

MAX_VALUE_LEN = const(4096 + 64)

if _backend.FIRMWARE:
    from trezor import config as _config

    def get(app: int, key: int, public: bool = False):
        return _config.get(app, key, public)

    def set(app: int, key: int, value: bytes, public: bool = False) -> None:  # noqa: A001
        if len(value) > MAX_VALUE_LEN:
            raise ValueError("kv value too long")
        try:
            _config.set(app, key, value, public)
        except RuntimeError:
            # upstream raises RuntimeError when norcow cannot fit the item
            raise StorageFull("storage full")

    def delete(app: int, key: int, public: bool = False) -> bool:
        return _config.delete(app, key, public)

    def is_unlocked() -> bool:
        return _config.is_unlocked()

else:
    from . import testing as _testing

    def get(app: int, key: int, public: bool = False):
        return _testing.KV.get(app, key, public)

    def set(app: int, key: int, value: bytes, public: bool = False) -> None:  # noqa: A001
        if len(value) > MAX_VALUE_LEN:
            raise ValueError("kv value too long")
        try:
            _testing.KV.set(app, key, value, public)
        except _testing.StorageFull:
            raise StorageFull("storage full")

    def delete(app: int, key: int, public: bool = False) -> bool:
        return _testing.KV.delete(app, key, public)

    def is_unlocked() -> bool:
        return _testing.KV.unlocked
