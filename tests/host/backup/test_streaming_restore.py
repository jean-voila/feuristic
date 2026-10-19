# SPDX-License-Identifier: GPL-3.0-only
"""Low-memory restore keeps only the current authenticated identity alive."""

import pytest

from feuristic.apps.backup import envelope, frames, restore
from feuristic.apps.backup.errors import AuthenticationFailed, FrameConflict, PlaintextError
from feuristic.apps.importer.session import ImportSession
from feuristic.core.errors import InvalidInput, PolicyDenied, UserCancelled
from feuristic.core.interaction import ScriptedInteraction

from ..aio import run
from .fakes import PASSPHRASE, FakeProvider, passphrases


@pytest.fixture
def data(registry, fast_kdf):
    source = FakeProvider()
    first = source.add("first")
    second = source.add("second")
    destination = FakeProvider()
    registry.register(destination)
    key = run(envelope.derive_key(PASSPHRASE, b"s" * 16))

    def sealed(uid, sequence=1, count=2, backup_id=None, salt=b"s" * 16, obj=None):
        return envelope.seal(
            key,
            salt,
            envelope.KIND_FULL,
            [source.export_identity(uid) if obj is None else obj],
            backup_id=backup_id,
            seq=sequence,
            count=count,
        )

    return source, destination, first, second, sealed, key


def test_streamed_full_set_caches_one_kdf_and_releases_chunks(data):
    source, destination, first, second, sealed, _ = data
    raw1 = sealed(first)
    raw2 = sealed(second, 2)
    collector = ImportSession()
    get_phrase = passphrases(PASSPHRASE)
    session = restore.StreamingRestore(ScriptedInteraction(), get_phrase)
    for raw in (raw2, raw1):
        header = envelope.parse_header(raw)
        texts = frames.split(raw, header.backup_id, "large")
        for text in reversed(texts):
            assert collector.add_payload(text.encode()).accepted
        taken = collector.take_complete()
        assert taken == raw and collector.bytes_used() == 0
        assert collector.counts() == (0, 0) and not collector.finished
        run(session.restore_envelope(taken))
    assert destination.snapshot() == source.snapshot()
    assert len(get_phrase.calls) == 1
    assert len(session.report.restored) == 2
    assert session.incomplete_sets() == []
    key = session._keys[0][1]
    session.close()
    assert key == bytearray(32)
    with pytest.raises(PolicyDenied):
        run(session.restore_envelope(raw1))


def test_duplicate_completed_envelope_does_not_restore_twice(data):
    _, destination, first, _, sealed, _ = data
    raw = sealed(first)
    ui = ScriptedInteraction()
    session = restore.StreamingRestore(ui, passphrases(PASSPHRASE))
    run(session.restore_envelope(raw))
    prompts = len(ui.prompts)
    run(session.restore_envelope(raw))
    assert session.last_duplicate and len(ui.prompts) == prompts
    assert destination.restored == ["first"]
    assert session.incomplete_sets() == [(1, 2)]
    changed = raw[:-1] + bytes((raw[-1] ^ 1,))
    with pytest.raises(FrameConflict):
        run(session.restore_envelope(changed))
    assert destination.restored == ["first"]


def test_conflicting_full_sequence_or_count_refused(data):
    _, destination, first, second, sealed, _ = data
    session = restore.StreamingRestore(ScriptedInteraction(), passphrases(PASSPHRASE))
    run(session.restore_envelope(sealed(first)))
    with pytest.raises(FrameConflict):
        run(session.restore_envelope(sealed(second, 1)))
    with pytest.raises(PlaintextError):
        run(session.restore_envelope(sealed(second, 2, count=3)))
    assert destination.restored == ["first"]


def test_later_corruption_preserves_prior_receipts_without_new_writes(data):
    _, destination, first, second, sealed, _ = data
    session = restore.StreamingRestore(ScriptedInteraction(), passphrases(PASSPHRASE))
    run(session.restore_envelope(sealed(first)))
    raw = sealed(second, 2)
    damaged = raw[:-1] + bytes((raw[-1] ^ 1,))
    with pytest.raises(AuthenticationFailed):
        run(session.restore_envelope(damaged))
    assert destination.restored == ["first"]
    assert [label for _, label, _ in session.report.restored] == ["first"]
    assert session.incomplete_sets() == [(1, 2)]


def test_all_items_validated_before_any_current_envelope_write(data):
    source, destination, first, second, _, key = data
    invalid = source.export_identity(second)
    invalid["secret"] = b"short"
    raw = envelope.seal(
        key, b"s" * 16, envelope.KIND_FULL, [source.export_identity(first), invalid], seq=1, count=1
    )
    session = restore.StreamingRestore(ScriptedInteraction(), passphrases(PASSPHRASE))
    with pytest.raises(InvalidInput):
        run(session.restore_envelope(raw))
    assert destination.restored == [] and not session.report.restored


def test_refusal_and_partial_storage_failure_have_clear_receipts(data):
    _, destination, first, second, sealed, _ = data
    ui = ScriptedInteraction([False])
    refused = restore.StreamingRestore(ui, passphrases(PASSPHRASE))
    with pytest.raises(UserCancelled):
        run(refused.restore_envelope(sealed(first)))
    assert not destination.restored and not refused.incomplete_sets()
    session = restore.StreamingRestore(ScriptedInteraction(), passphrases(PASSPHRASE))
    run(session.restore_envelope(sealed(first)))
    destination.fail_on.add("second")
    report = run(session.restore_envelope(sealed(second, 2)))
    assert report.failed[1] == "second"
    assert [label for _, label, _ in report.restored] == ["first"]
    with pytest.raises(PolicyDenied):
        run(session.restore_envelope(sealed(second, 2)))


def test_incomplete_identity_is_never_consumed_or_written(data):
    _, _, first, second, sealed, _ = data
    collector = ImportSession()
    complete = sealed(first)
    pending = sealed(second, 2)
    bid = envelope.parse_header(pending).backup_id
    texts = frames.split(pending, bid, "large")
    collector.add_payload(texts[0].encode())
    for text in frames.split(complete, envelope.parse_header(complete).backup_id, "large"):
        collector.add_payload(text.encode())
    assert not collector.is_ready()
    assert collector.take_complete() == complete
    assert collector.counts() == (0, 1)
    assert collector.take_complete() is None
    assert collector.progress()[0].backup_id == bid


def test_receipts_keep_exact_totals_with_only_four_examples():
    receipts = restore.RecentReceipts()
    for index in range(192):
        receipts.append(("fido2", "x" * 128, index.to_bytes(8, "big")))
    assert len(receipts) == receipts.total == 192
    assert len(receipts.recent) == 4
    assert [int.from_bytes(uid, "big") for _, _, uid in receipts] == [188, 189, 190, 191]
