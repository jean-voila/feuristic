# SPDX-License-Identifier: GPL-3.0-only
"""RecordStore / Blob: functional behaviour and power-loss safety."""

import contextlib

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from feuristic.core import store
from feuristic.core.errors import InvalidInput, NotFound, StorageCorrupted, StorageFull
from feuristic.platform import testing

APP = 0x11


def uid(n):
    return n.to_bytes(8, "big")


def make(capacity=4, max_payload=64):
    s = store.RecordStore(APP, capacity, max_payload, rtype=7)
    s.load()
    return s


def test_put_get_replace_delete():
    s = make()
    s.put(uid(1), b"one")
    s.put(uid(2), b"two", flags=3)
    assert s.get(uid(1)) == b"one"
    assert s.flags(uid(2)) == 3
    s.put(uid(1), b"uno")
    assert s.get(uid(1)) == b"uno"
    assert len(s) == 2
    assert s.uids() == [uid(2), uid(1)] or set(s.uids()) == {uid(1), uid(2)}
    assert s.delete(uid(1))
    assert not s.delete(uid(1))
    assert s.get(uid(1)) is None
    with pytest.raises(NotFound):
        s.flags(uid(1))


def test_capacity_and_spare_slot():
    s = make(capacity=2)
    s.put(uid(1), b"a")
    s.put(uid(2), b"b")
    assert s.is_full()
    with pytest.raises(StorageFull):
        s.put(uid(3), b"c")
    # replacing while full must still work thanks to the spare slot
    s.put(uid(2), b"bb")
    assert s.get(uid(2)) == b"bb"


def test_payload_limit():
    s = make(max_payload=4)
    with pytest.raises(InvalidInput):
        s.put(uid(1), b"12345")


def test_persistence_across_load():
    s = make()
    s.put(uid(9), b"persist")
    s2 = make()
    assert s2.get(uid(9)) == b"persist"


def test_record_header_roundtrip_and_corruption():
    raw = store.pack(7, 1, 42, uid(5), b"payload")
    rec = store.unpack(raw)
    assert (rec.rtype, rec.flags, rec.generation, rec.uid, rec.payload) == (7, 1, 42, uid(5), b"payload")
    with pytest.raises(StorageCorrupted):
        store.unpack(b"\x00" * 20)
    with pytest.raises(StorageCorrupted):
        store.unpack(raw[:10])


def test_corrupt_and_foreign_slots_are_ignored_not_deleted(kv):
    kv.set(APP, 0, b"garbage-garbage-garbage")
    kv.set(APP, 1, store.pack(99, 0, 1, uid(1), b"other type"))
    s = make()
    assert len(s) == 0
    assert s.corrupt_slots == [0, 1]
    assert kv.get(APP, 0) is not None  # user data is never silently destroyed


@pytest.mark.parametrize("crash_at", range(4))
def test_power_loss_during_replace_never_loses_record(kv, crash_at):
    s = make()
    s.put(uid(1), b"v1")
    kv.ops = 0
    kv.crash_after_ops = crash_at
    with contextlib.suppress(testing.PowerLoss):
        s.put(uid(1), b"v2")
    kv.crash_after_ops = None
    s2 = make()  # "reboot"
    assert s2.get(uid(1)) in (b"v1", b"v2")
    assert len(s2) == 1
    # stale copies have been cleaned up by load()
    live = [k for k in kv.data if k[0] == APP]
    assert len(live) == 1


def test_duplicate_resolution_keeps_highest_generation(kv):
    kv.set(APP, 0, store.pack(7, 0, 5, uid(1), b"old"))
    kv.set(APP, 3, store.pack(7, 0, 6, uid(1), b"new"))
    s = make()
    assert s.get(uid(1)) == b"new"
    assert kv.get(APP, 0) is None
    s.put(uid(2), b"x")
    assert s.get_record(uid(2)).generation == 7


def test_wipe(kv):
    s = make()
    s.put(uid(1), b"a")
    kv.set(APP, 4, b"junk")
    s.wipe()
    assert len(s) == 0
    assert not [k for k in kv.data if k[0] == APP]


def test_replace_all():
    s = make()
    s.put(uid(1), b"a")
    s.put(uid(2), b"b")
    s.replace_all([(uid(2), b"B", 0), (uid(3), b"C", 1)])
    assert set(s.uids()) == {uid(2), uid(3)}
    assert s.get(uid(2)) == b"B"


def test_underlying_storage_full(kv):
    kv.capacity = 400
    s = make(capacity=10, max_payload=200)
    with pytest.raises(StorageFull):
        for i in range(10):
            s.put(uid(i), bytes(200))


@settings(max_examples=60, deadline=None)
@given(st.lists(st.tuples(st.integers(0, 5), st.binary(max_size=16), st.integers(0, 40)), max_size=12))
def test_random_ops_with_power_loss_model(ops):
    """Model-based test: after any sequence of ops interrupted by power cuts,
    every record holds either its last committed or its in-flight value."""
    testing.KV.reset()
    s = make(capacity=6)
    committed = {}
    for key, value, crash in ops:
        testing.KV.ops = 0
        testing.KV.crash_after_ops = crash % 4
        inflight = (key, value)
        try:
            s.put(uid(key), value)
            committed[key] = value
            inflight = None
        except testing.PowerLoss:
            pass
        testing.KV.crash_after_ops = None
        s = make(capacity=6)
        for k, v in committed.items():
            got = s.get(uid(k))
            if inflight and inflight[0] == k:
                assert got in (v, inflight[1])
                committed[k] = got
            else:
                assert got == v
        if inflight and inflight[0] not in committed:
            got = s.get(uid(inflight[0]))
            assert got in (None, inflight[1])
            if got is not None:
                committed[inflight[0]] = got


def test_blob_ab_alternation_and_power_loss(kv):
    b = store.Blob(0x13, 2, 3, max_len=100)
    assert b.get() is None

    b.set(b"first")
    b.set(b"second")
    assert b.get() == b"second"
    kv.ops = 0
    kv.crash_after_ops = 0
    with pytest.raises(testing.PowerLoss):
        b.set(b"third")
    assert b.get() == b"second"  # previous copy survives
    b.set(b"fourth")
    assert b.get() == b"fourth"
    with pytest.raises(InvalidInput):
        b.set(bytes(101))
    b.clear()
    assert b.get() is None


def test_blob_view_is_independent_and_get_still_returns_bytes():
    blob = store.Blob(0x13, 2, 3, max_len=4096)
    blob.set(b"x" * 4096)
    view = blob.get_view()
    assert isinstance(view, memoryview)
    assert type(blob.get()) is bytes
    blob.set(b"y" * 4096)
    blob.clear()
    assert bytes(view) == b"x" * 4096


def test_blob_head_never_slices_out_a_payload(monkeypatch):
    class Guarded(bytes):
        def __getitem__(self, index):
            if isinstance(index, slice) and index.start == 4:
                raise AssertionError("metadata scan copied the payload")
            return super().__getitem__(index)

    blob = store.Blob(0x13, 2, 3, max_len=4096)
    monkeypatch.setattr(
        store.kv, "get", lambda app, key, public: Guarded(key.to_bytes(4, "big") + b"x" * 4096)
    )
    assert blob._head() == (3, 3)
    assert bytes(blob.get_view()) == b"x" * 4096


@pytest.mark.parametrize("crash_at", range(3))
def test_blob_owned_buffer_power_loss_preserves_latest(kv, crash_at):
    blob = store.Blob(0x13, 2, 3, max_len=4096)
    blob.set(b"a" * 4096)
    blob.set(b"b" * 4096)
    pending = bytearray(4 + 4096)
    pending[4:] = b"c" * 4096
    kv.ops = 0
    kv.crash_after_ops = crash_at
    with contextlib.suppress(testing.PowerLoss):
        blob.set_buffer(pending)
    kv.crash_after_ops = None
    current = store.Blob(0x13, 2, 3, max_len=4096).get()
    assert current == (b"b" * 4096 if crash_at < 2 else b"c" * 4096)


def test_blob_allocation_failure_does_not_change_flash(kv, monkeypatch):
    blob = store.Blob(0x13, 2, 3, max_len=4096)
    blob.set(b"old")
    before = dict(kv.data)

    def fail(size):
        raise MemoryError

    monkeypatch.setattr(store, "bytearray", fail, raising=False)
    with pytest.raises(MemoryError):
        blob.set(b"x" * 4096)
    assert kv.data == before


@pytest.mark.parametrize("value", [b"0000", bytearray(3), bytearray(4101)])
def test_blob_owned_buffer_rejects_invalid_size_or_type(value):
    with pytest.raises(InvalidInput):
        store.Blob(0x13, 2, 3, max_len=4096).set_buffer(value)


def test_key_offset_isolates_stores(kv):
    a = store.RecordStore(0x14, 3, 64, rtype=1)
    b = store.RecordStore(0x14, 3, 64, rtype=2, key_offset=0x10)
    a.load()
    b.load()
    a.put(uid(1), b"a")
    b.put(uid(1), b"b")
    assert a.get(uid(1)) == b"a" and b.get(uid(1)) == b"b"
    assert all(k[1] >= 0x10 for k, v in kv.data.items() if v[2] == 2)
    b.wipe()
    assert a.get(uid(1)) == b"a"
    with pytest.raises(ValueError):
        store.RecordStore(0x14, 250, 64, rtype=3, key_offset=10)
