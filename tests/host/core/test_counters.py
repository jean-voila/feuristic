# SPDX-License-Identifier: GPL-3.0-only
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from feuristic.core import counters
from feuristic.core.errors import InvalidInput, StorageFull
from feuristic.platform import testing


def mk():
    return counters.RedundantCounter(0x14, 0, 1)


def test_increment_and_get():
    c = mk()
    assert c.get() == 0
    assert c.increment() == 1
    assert c.increment() == 2
    assert mk().get() == 2


def test_advance_must_increase():
    c = mk()
    c.advance_to(10)
    with pytest.raises(InvalidInput):
        c.advance_to(10)
    with pytest.raises(StorageFull):
        c.advance_to(counters.MAX_VALUE + 1)


def test_reset():
    c = mk()
    c.increment()
    c.reset()
    assert c.get() == 0


@pytest.mark.parametrize("crash_at", range(5))
def test_power_loss_never_goes_backwards(kv, crash_at):
    c = mk()
    c.advance_to(5)
    kv.ops = 0
    kv.crash_after_ops = crash_at
    try:
        c.advance_to(6)
        used = 6
    except testing.PowerLoss:
        used = 5  # caller never used 6
    kv.crash_after_ops = None
    assert mk().get() >= used


def test_nonce_allocator_unique_and_reserved(kv):
    c = mk()
    a = counters.NonceAllocator(c, block=4)
    vals = [a.allocate() for _ in range(10)]
    assert vals == list(range(10))
    assert c.get() == 12  # reservation high-water mark
    # "reboot": a fresh allocator restarts after the reservation
    b = counters.NonceAllocator(mk(), block=4)
    assert b.allocate() == 12


@settings(max_examples=50, deadline=None)
@given(st.lists(st.tuples(st.integers(1, 30), st.integers(0, 6)), min_size=1, max_size=8))
def test_nonce_allocator_never_reuses_across_power_loss(sessions):
    testing.KV.reset()
    seen = set()
    for n, crash in sessions:
        alloc = counters.NonceAllocator(mk(), block=3)
        testing.KV.ops = 0
        testing.KV.crash_after_ops = crash
        try:
            for _ in range(n):
                v = alloc.allocate()
                assert v not in seen
                seen.add(v)
        except testing.PowerLoss:
            pass
        testing.KV.crash_after_ops = None


def test_nonce_allocator_rejects_bad_block():
    with pytest.raises(ValueError):
        counters.NonceAllocator(mk(), block=0)
