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


def test_device_envelope_limit_preserves_prior_results_and_accepts_exact_replay(data):
    _, destination, first, second, sealed, _ = data
    ui = ScriptedInteraction()
    streamed = restore.StreamingRestore(ui, passphrases(PASSPHRASE), max_envelopes=1, max_sets=1)
    raw = sealed(first)
    run(streamed.restore_envelope(raw))
    run(streamed.restore_envelope(raw))
    assert streamed.last_duplicate
    prompts = len(ui.prompts)
    with pytest.raises(PolicyDenied, match="finish and reopen"):
        run(streamed.restore_envelope(sealed(second, 2)))
    assert destination.restored == ["first"] and len(streamed.report.restored) == 1
    assert len(ui.prompts) == prompts and streamed.incomplete_sets() == [(1, 2)]


def test_set_limit_counts_identity_salts_before_kdf_or_mutation(data):
    source, destination, first, second, _, key = data
    get_phrase = passphrases(PASSPHRASE)
    streamed = restore.StreamingRestore(ScriptedInteraction(), get_phrase, max_sets=1)
    for index, uid in enumerate((first, second)):
        raw = envelope.seal(key, b"s" * 16, envelope.KIND_IDENTITY, [source.export_identity(uid)])
        run(streamed.restore_envelope(raw))
        assert len(streamed.report.restored) == index + 1
    other = envelope.seal(key, b"t" * 16, envelope.KIND_IDENTITY, [source.export_identity(first)])
    with pytest.raises(PolicyDenied, match="finish and reopen"):
        run(streamed.restore_envelope(other))
    assert len(get_phrase.calls) == 1 and destination.restored == ["first", "second"]
    assert streamed._salts == [b"s" * 16]


@pytest.mark.parametrize(
    "limits",
    [{"max_envelopes": 0}, {"max_envelopes": 1025}, {"max_sets": 0}, {"max_sets": 1025}],
)
def test_restore_limits_cannot_exceed_generic_format(limits):
    with pytest.raises(InvalidInput):
        restore.StreamingRestore(ScriptedInteraction(), passphrases(PASSPHRASE), **limits)


def test_exact_device_bounds_keep_all_receipt_counts(data):
    from feuristic.apps.importer.session import DEVICE_MAX_ENVELOPES, DEVICE_MAX_SETS

    source, destination, first, _, _, key = data
    streamed = restore.StreamingRestore(
        ScriptedInteraction(),
        passphrases(*([PASSPHRASE] * 4)),
        max_envelopes=DEVICE_MAX_ENVELOPES,
        max_sets=DEVICE_MAX_SETS,
    )
    for index in range(DEVICE_MAX_ENVELOPES):
        salt = bytes((index % DEVICE_MAX_SETS,)) * 16
        raw = envelope.seal(
            key,
            salt,
            envelope.KIND_IDENTITY,
            [source.export_identity(first)],
            backup_id=(index + 1).to_bytes(8, "big"),
        )
        # This test checks session bounds independently of KDF salt inputs.
        if not any(old_salt == salt for old_salt, _ in streamed._keys):
            streamed._keys.append((salt, bytearray(key)))
        run(streamed.restore_envelope(raw))
    assert len(streamed.report.restored) == DEVICE_MAX_ENVELOPES == 192
    assert len(streamed.report.restored.recent) == 4
    assert len(streamed._salts) == DEVICE_MAX_SETS == 4
    assert len(streamed._seen) == 192 * 40
    raw = envelope.seal(key, b"z" * 16, envelope.KIND_IDENTITY, [source.export_identity(first)])
    with pytest.raises(PolicyDenied, match="finish and reopen"):
        run(streamed.restore_envelope(raw))
    assert len(destination.restored) == 192
