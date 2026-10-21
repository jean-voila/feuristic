# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""A hundred services are enumerated without retaining names or private keys."""

from feuristic.apps.fido2 import credentials as cr
from feuristic.apps.fido2 import localmgmt
from feuristic.core import store as record_store


def test_capacity_rp_snapshot_is_sorted_and_local_labels_are_paged(device):
    store = device.auth.store
    names = [f"{index:03d}." + "a" * 116 + ".example" for index in range(100)]
    for index in range(99, -1, -1):
        store.create_resident(
            names[index],
            bytes((index,)) * 64,
            "n" * 64,
            "d" * 64,
            cr.ALG_ES256,
            (index + 1).to_bytes(32, "big"),
            1,
            True,
            True,
        )
    rps = store.rps()
    assert len(rps) == 100 and len(rps.data) == 900
    assert [rp[0] for rp in rps] == names
    assert all(rp[2] == 1 for rp in rps)
    assert rps[-1][0] == names[-1]
    assert [rp[0] for rp in rps[30:34]] == names[30:34]
    services = localmgmt.list_rps(device.auth)
    assert len(services.labels()) == 100
    assert services.labels()[30:34] == [f"{name} (1)" for name in names[30:34]]
    response = device.auth.credmgmt._rps_begin()
    assert response[5] == 100 and response[3]["id"] == names[0]
    assert [device.auth.credmgmt._next_rp()[3]["id"] for _ in range(99)] == names[1:]


def test_restore_index_loan_is_invalidated_by_record_writes_and_release(device):
    store = device.auth.store
    cred = store.create_resident("example.com", b"u", "name", None, -7, b"k" * 32, 1, False, False)
    store.invalidate()
    buffer = bytearray(5440)
    previous = record_store.use_write_buffer(buffer)
    try:
        assert store.count() == 1
        assert store._index.data.obj is buffer
        unrelated = record_store.RecordStore(0x17, 1, 32, 7)
        unrelated.put(b"otheruid", b"temporary")
        assert store.count() == 1  # Rebuild after serialization overwrote the arena.
        assert store._index[0][0] == cred.uid
        assert store.set_backup_state(cred.uid)
        assert store._index is None
        assert store.count() == 1 and store.get(cred.uid).backup_state
    finally:
        record_store.use_write_buffer(previous)
    assert not any(buffer)
    assert store.count() == 1
    assert store._index.revision is None
