# SPDX-License-Identifier: GPL-3.0-only
"""Bounded collection and real native decoder allocation lifetimes.

The unix heap uses 64-bit objects and keeps the MCU's CCM state on its heap;
these regressions establish release/reuse, not physical hardware RAM fit.
"""

import gc

import feuristic_import
from upytest import run, test

from feuristic.apps.backup import frames
from feuristic.apps.importer.session import DEVICE_MAX_BACKUPS, DEVICE_MAX_BYTES, DUPLICATE, ImportSession


@test
def packed_native_identity_pauses_without_retaining_decoder_workspaces():
    native = feuristic_import.Session(b"Import memory test", 512, 1)
    collector = ImportSession(DEVICE_MAX_BACKUPS, DEVICE_MAX_BYTES, compact=True)
    size = 5127  # maximum OpenPGP export measured by host provider regression
    count = frames.frame_count(size, frames.PROFILE_LARGE)
    base = size // count
    extra = size - count * base
    # No list of all encoded QR texts is kept alongside the decoder.
    for index in range(count - 1, -1, -1):
        length = base + (1 if index < extra else 0)
        text = frames.encode_frame(b"memory01", index + 1, count, b"x" * length)
        assert collector.add_payload(text.encode()).accepted
    assert collector.bytes_used() == size
    gc.collect()
    active = gc.mem_alloc()
    assert native.pause_decode()
    gc.collect()
    paused = gc.mem_alloc()
    assert active - paused >= 110_000
    raw = collector.take_complete()
    assert len(raw) == size and raw == b"x" * size
    assert collector.bytes_used() == 0 and collector.counts() == (0, 0)
    raw = None
    gc.collect()
    assert native.resume_decode()
    assert native.pause_decode()
    native.close()
    collector.abort()


@test
def packed_ledger_cannot_report_an_incomplete_identity_complete():
    collector = ImportSession(DEVICE_MAX_BACKUPS, DEVICE_MAX_BYTES, compact=True)
    text = frames.encode_frame(b"memory02", 2, 3, b"encrypted bytes")
    assert collector.add_payload(text.encode()).accepted
    assert collector.take_complete() is None
    assert collector.counts() == (0, 1)
    assert collector.progress()[0].missing == [1, 3]
    assert collector.add_payload(text.encode()).status == DUPLICATE
    assert collector.bytes_used() == len(b"encrypted bytes")
    collector.abort()


run()
