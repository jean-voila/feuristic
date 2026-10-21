# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Deletion/reset must work without allocating slices or a replacement arena."""

from feuristic.core.packed_index import CredentialIndex, RecordIndex


class NoSlices(bytearray):
    def __getitem__(self, key):
        if isinstance(key, slice):
            raise MemoryError("no slice allocation possible")
        return super().__getitem__(key)

    def __setitem__(self, key, value):
        if isinstance(key, slice):
            raise MemoryError("no slice allocation possible")
        return super().__setitem__(key, value)


def test_delete_at_low_memory_preserves_order_and_unique_identities():
    index = CredentialIndex(4)
    for number in range(1, 5):
        index.append((number.to_bytes(8, "big"), bytes((number,)) * 32, number))
    index.data = NoSlices(index.data)
    index.remove_uid((1).to_bytes(8, "big"))
    index.remove_uid((3).to_bytes(8, "big"))
    index.data = bytearray(index.data)
    assert [(uid, seq) for uid, _, seq in index] == [
        ((2).to_bytes(8, "big"), 2),
        ((4).to_bytes(8, "big"), 4),
    ]


def test_record_index_delete_and_wipe_reuse_existing_arena():
    index = RecordIndex(4)
    first, second = b"a" * 8, b"b" * 8
    index[first] = (0, 1, 7)
    index[second] = (1, 2, 8)
    index.data = NoSlices(index.data)
    arena = index.data
    del index[first]
    assert first not in index and second in index
    index.clear()
    assert not index and second not in index
    assert index.data is arena


def test_rp_groups_count_interleaved_credentials_once():
    index = CredentialIndex(5)
    for number, service in enumerate((2, 1, 2, 3, 1)):
        index.append((number.to_bytes(8, "big"), bytes((service,)) * 32, number))
    assert list(index.rp_groups()) == [
        ((0).to_bytes(8, "big"), 2),
        ((1).to_bytes(8, "big"), 2),
        ((3).to_bytes(8, "big"), 1),
    ]
