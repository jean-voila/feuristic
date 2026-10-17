# SPDX-License-Identifier: GPL-3.0-only
"""End-to-end: export → frames as images' payloads → ImportSession → restore."""

import random

import pytest

from feuristic.apps.backup import envelope, export, provider, restore
from feuristic.apps.importer import session as sess
from feuristic.core.interaction import ScriptedInteraction

from ..aio import run
from ..backup.fakes import PASSPHRASE, FakeProvider, passphrases


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setattr(envelope, "ITERATIONS", 1000)
    provider.clear()
    p = FakeProvider("fido2")
    provider.register(p)
    yield p
    provider.clear()


def test_full_export_restore_via_session(env):
    p = env
    for i in range(5):
        p.add(f"site{i}.example user{i}")
    before = p.snapshot()
    exported = run(export.export_full(ScriptedInteraction(), passphrases(PASSPHRASE), "large"))
    stream = [t.encode() for e in exported for t in e.frames]
    held_back = exported[2].frames[0].encode()
    rng = random.Random(5)
    stream += rng.sample(stream, 10)  # duplicates
    rng.shuffle(stream)
    p.data.clear()
    s = sess.ImportSession()
    for t in stream:
        if t != held_back:
            assert s.add_payload(t).accepted
    assert not s.is_ready() and s.action() is None  # one missing frame blocks
    assert s.counts() == (4, 1)
    assert s.add_payload(held_back).status == sess.BACKUP_COMPLETE
    assert s.is_ready()
    rep = run(restore.restore(ScriptedInteraction(), s.action().envelopes, passphrases(PASSPHRASE)))
    s.finish()
    assert rep.ok and len(rep.restored) == 5
    assert p.snapshot() == before
