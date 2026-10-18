# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Storage sizes from upstream norcow_blockwise.h and storage.c.

Public 8-byte counters fit in one 16-byte flash block; charging them for
encryption incorrectly rejects the contractual R04 capacity. Conversely,
an exactly full value block needs another block for its validity flag.
"""

import pytest

from feuristic.platform import testing


@pytest.mark.parametrize(
    "public,length,expected",
    [
        (True, 8, 16),
        (True, 12, 16),
        (True, 13, 32),
        (True, 16, 48),
        (False, 0, 48),
        (False, 3, 48),
        (False, 4, 64),
        (False, 4100, 4160),
    ],
)
def test_norcow_live_item_size(kv, public, length, expected):
    kv.set(0x10, 0, bytes(length), public=public)
    assert kv.used_bytes() == expected
    kv.set(0x10, 0, bytes(length), public=public)
    assert kv.used_bytes() == expected  # replacement, not two live items
    kv.delete(0x10, 0, public=public)
    assert kv.used_bytes() == 0


def test_counter_and_protected_value_have_independent_budgets(kv):
    kv.capacity = 96
    kv.set(0x11, 0, bytes(32))  # encrypted, 80 bytes
    kv.set(0x11, 0, bytes(8), public=True)  # public, 16 bytes
    assert kv.used_bytes() == kv.capacity
    with pytest.raises(testing.StorageFull):
        kv.set(0x11, 1, bytes(8), public=True)
    assert kv.get(0x11, 0) == bytes(32)
    assert kv.get(0x11, 0, public=True) == bytes(8)
