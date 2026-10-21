# SPDX-License-Identifier: GPL-3.0-only
"""Export / restore orchestration with fake providers (spec §8.2, §3.3)."""

import pytest

from feuristic.apps.backup import envelope, export, frames, restore
from feuristic.apps.backup.errors import (
    AuthenticationFailed,
    BackupFormatError,
    UnsupportedItem,
    WeakPassphrase,
)
from feuristic.apps.importer.session import ImportSession
from feuristic.core import i18n
from feuristic.core.errors import InvalidInput, NotFound, PolicyDenied, StorageFull, UserCancelled
from feuristic.core.interaction import DANGER, NORMAL, SENSITIVE, ScriptedInteraction

from ..aio import run
from .fakes import PASSPHRASE, DuckProvider, FakeProvider, passphrases

WRONG = b"wrong horse battery staple"


@pytest.fixture
def setup(registry, fast_kdf):
    otp = FakeProvider("otp")
    fido = FakeProvider("fido2")
    registry.register(otp)
    registry.register(fido)
    return otp, fido


def _frames_to_envelopes(*exported):
    """Feed every frame through an ImportSession, like the MSC glue does."""
    s = ImportSession()
    for e in exported:
        for t in e.frames:
            assert s.add_payload(t.encode()).accepted
    act = s.action()
    assert act is not None
    return act.envelopes


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------


def test_export_identity_flow(setup):
    otp, fido = setup
    uid = fido.add("github.com alice")
    ui = ScriptedInteraction()
    get = passphrases(PASSPHRASE)
    res = run(export.export_identity(ui, "fido2", uid, get))
    # DANGER prompt with the mandatory warning (spec §8.2)
    assert ui.kinds() == ["backup.export"]
    p = ui.prompts[0]
    assert p.severity == DANGER
    assert p.title == "backup.export.title"
    fields = dict(p.fields)
    assert fields["backup.field.identity"] == "github.com alice"
    assert fields["backup.field.category"] == "fido2"
    assert fields["backup.field.warning"] == i18n.t("backup.warn.recoverable")
    assert "non" in fields["backup.field.warning"].lower()
    # passphrase requested once, for export
    assert [r.purpose for r in get.calls] == [export.PURPOSE_EXPORT]
    # result
    assert res.type == "fido2" and res.uid == uid and res.label == "github.com alice"
    assert res.seq == 1 and res.count == 1 and res.profile == "dense"
    assert len(res.frames) == frames.frame_count(res.envelope_len, "dense")
    assert all(t.startswith("FB1:") for t in res.frames)
    assert fido.exported == [uid]
    # the envelope is an identity backup with exactly this item
    env = _frames_to_envelopes(res)[0]
    c = run(envelope.open_envelope(env, PASSPHRASE))
    assert c.kind == envelope.KIND_IDENTITY and c.backup_id == res.backup_id
    assert c.items == [fido.data[uid]]


def test_export_large_profile(setup):
    otp, _ = setup
    uid = otp.add("acme")
    res = run(export.export_identity(ScriptedInteraction(), "otp", uid, passphrases(PASSPHRASE), "large"))
    assert all(len(t) <= 61 for t in res.frames)
    assert len(res.frames) > 1


def test_export_refused(setup):
    otp, _ = setup
    uid = otp.add("acme")
    get = passphrases()
    with pytest.raises(UserCancelled):
        run(export.export_identity(ScriptedInteraction([False]), "otp", uid, get))
    assert get.calls == [] and otp.exported == []


def test_export_reauth(setup):
    otp, _ = setup
    uid = otp.add("acme")

    async def deny():
        return False

    async def allow():
        return True

    with pytest.raises(PolicyDenied):
        run(export.export_identity(ScriptedInteraction(), "otp", uid, passphrases(), reauth=deny))
    res = run(
        export.export_identity(ScriptedInteraction(), "otp", uid, passphrases(PASSPHRASE), reauth=allow)
    )
    assert res.frames


def test_export_passphrase_cancel_and_policy(setup):
    otp, _ = setup
    uid = otp.add("acme")
    with pytest.raises(UserCancelled):
        run(export.export_identity(ScriptedInteraction(), "otp", uid, passphrases(None)))
    ui = ScriptedInteraction()
    with pytest.raises(WeakPassphrase):
        run(export.export_identity(ui, "otp", uid, passphrases(b"short", b"x" * 11, b"\x01" * 20)))
    assert [n[0] for n in ui.notifications] == ["backup.passphrase_policy"] * 3
    ui = ScriptedInteraction()
    res = run(export.export_identity(ui, "otp", uid, passphrases(b"short", PASSPHRASE)))
    assert len(ui.notifications) == 1 and res.frames
    assert otp.exported == [uid]


def test_export_passphrase_buffer_wiped(setup):
    otp, _ = setup
    uid = otp.add("acme")
    buf = bytearray(PASSPHRASE)

    async def get(req):
        return buf

    run(export.export_identity(ScriptedInteraction(), "otp", uid, get))
    assert buf == bytearray(len(PASSPHRASE))


def test_export_errors(setup):
    otp, _ = setup
    with pytest.raises(NotFound):
        run(export.export_identity(ScriptedInteraction(), "otp", b"\x00" * 8, passphrases()))
    with pytest.raises(UnsupportedItem):
        run(export.export_identity(ScriptedInteraction(), "piv", b"\x00" * 8, passphrases()))
    with pytest.raises(InvalidInput):
        run(export.export_identity(ScriptedInteraction(), "otp", b"", passphrases()))
    uid = otp.add("acme")
    with pytest.raises(ValueError):
        run(export.export_identity(ScriptedInteraction(), "otp", uid, passphrases(), "tiny"))


def test_on_exported_failure_returns_no_frames(setup):
    otp, _ = setup
    uid = otp.add("acme")
    otp.fail_on_exported = True
    with pytest.raises(StorageFull):
        run(export.export_identity(ScriptedInteraction(), "otp", uid, passphrases(PASSPHRASE)))


def test_export_rejects_bad_provider_item(setup):
    otp, _ = setup
    uid = otp.add("acme")
    otp.data[uid]["type"] = "fido2"  # provider bug: wrong type
    with pytest.raises(InvalidInput):
        run(export.export_identity(ScriptedInteraction(), "otp", uid, passphrases(PASSPHRASE)))
    otp.data[uid]["type"] = "otp"
    otp.data[uid]["deep"] = [[[[[[[0]]]]]]]
    with pytest.raises(InvalidInput):
        run(export.export_identity(ScriptedInteraction(), "otp", uid, passphrases(PASSPHRASE)))
    assert otp.exported == []


def test_progress_and_yield_during_export(setup):
    otp, _ = setup
    uid = otp.add("acme")
    ylds = []

    async def y():
        ylds.append(1)

    run(export.export_identity(ScriptedInteraction(), "otp", uid, passphrases(PASSPHRASE), "dense", None, y))
    assert len(ylds) == 3  # 1000 iterations in chunks of 300, no yield after the last


def test_progress_callback_signature(setup):
    otp, _ = setup
    uid = otp.add("acme")
    seen = []
    run(
        export.export_identity(
            ScriptedInteraction(),
            "otp",
            uid,
            passphrases(PASSPHRASE),
            progress=lambda d, t: seen.append((d, t)),
        )
    )
    assert seen[0] == (0, 1000) and seen[-1] == (1000, 1000)


def test_full_export(setup, monkeypatch):
    otp, fido = setup
    otp.add("acme")
    otp.add("bank")
    fido.add("github.com alice")
    derivations = []
    real = envelope.derive_key

    async def counting(*a, **kw):
        derivations.append(1)
        return await real(*a, **kw)

    monkeypatch.setattr(envelope, "derive_key", counting)
    ui = ScriptedInteraction()
    out = run(export.export_full(ui, passphrases(PASSPHRASE)))
    assert len(derivations) == 1  # one PBKDF2 for the whole session
    assert ui.kinds() == ["backup.export_full"]
    assert ui.prompts[0].severity == DANGER
    fields = dict(ui.prompts[0].fields)
    assert fields["backup.field.count"] == "3"
    assert fields["backup.field.warning"] == i18n.t("backup.warn.recoverable")
    assert [(e.type, e.label, e.seq, e.count) for e in out] == [
        ("otp", "acme", 1, 3),
        ("otp", "bank", 2, 3),
        ("fido2", "github.com alice", 3, 3),
    ]
    headers = [envelope.parse_header(env) for env in _frames_to_envelopes(*out)]
    assert len({h.salt for h in headers}) == 1  # shared salt
    assert len({h.nonce for h in headers}) == 3  # unique nonces
    assert len({h.backup_id for h in headers}) == 3
    assert all(h.kind == envelope.KIND_FULL for h in headers)
    assert len(otp.exported) == 2 and len(fido.exported) == 1


def test_packed_uid_snapshot_crosses_pages_without_retaining_labels():
    providers = [object(), object(), object()]
    snapshot = export._Snapshot(providers)
    expected = []
    for index in range(150):
        uid = bytes((index,)) * (1 + index % 32)
        snapshot.append(index % 3, uid)
        expected.append((providers[index % 3], uid, None))
    assert list(snapshot) == expected
    assert snapshot[-1] == expected[-1]
    assert all(len(page) == 256 for page in snapshot.pages)
    with pytest.raises(IndexError):
        snapshot[150]


def test_full_export_session_lazy_and_close(setup):
    otp, _ = setup
    otp.add("a-one")
    otp.add("b-two")
    s = run(export.begin_full_export(ScriptedInteraction(), passphrases(PASSPHRASE)))
    assert len(s) == 2 and s.label(1) == ("otp", "b-two")
    assert otp.exported == []  # nothing built yet
    e2 = s.build(1)
    assert e2.seq == 2 and len(otp.exported) == 1
    again = s.build(1)
    assert again.backup_id != e2.backup_id  # fresh envelope each time
    key = s._key
    s.close()
    assert key == bytearray(32)
    with pytest.raises(PolicyDenied):
        s.build(0)
    s.close()  # idempotent


def test_full_export_nothing(setup):
    with pytest.raises(NotFound):
        run(export.export_full(ScriptedInteraction(), passphrases()))


def test_full_export_refused(setup):
    otp, _ = setup
    otp.add("acme")
    with pytest.raises(UserCancelled):
        run(export.export_full(ScriptedInteraction([False]), passphrases()))
    assert otp.exported == []


def test_category_uses_label_key(registry, fast_kdf):
    p = FakeProvider("otp", label_key="backup.menu.title")
    registry.register(p)
    uid = p.add("acme")
    ui = ScriptedInteraction()
    run(export.export_identity(ui, "otp", uid, passphrases(PASSPHRASE)))
    assert dict(ui.prompts[0].fields)["backup.field.category"] == i18n.t("backup.menu.title")


# ---------------------------------------------------------------------------
# restore
# ---------------------------------------------------------------------------


def _export_all(otp, fido, pw=PASSPHRASE):
    return run(export.export_full(ScriptedInteraction(), passphrases(pw)))


def _wipe_providers(*ps):
    for p in ps:
        p.data.clear()


def test_restore_full_into_empty_device(setup):
    otp, fido = setup
    otp.add("acme")
    fido.add("github.com alice")
    before = (otp.snapshot(), fido.snapshot())
    envs = _frames_to_envelopes(*_export_all(otp, fido))
    _wipe_providers(otp, fido)
    ui = ScriptedInteraction()
    get = passphrases(PASSPHRASE)
    rep = run(restore.restore(ui, envs, get))
    assert len(get.calls) == 1  # one salt → one passphrase, one KDF
    assert get.calls[0].purpose == export.PURPOSE_RESTORE
    assert rep.ok and len(rep.restored) == 2 and rep.skipped == [] and rep.incomplete_sets == []
    assert (otp.snapshot(), fido.snapshot()) == before
    assert ui.kinds() == ["backup.restore"]
    assert ui.prompts[0].severity == SENSITIVE
    assert dict(ui.prompts[0].fields)["backup.field.count"] == "2"
    assert ui.notifications[-1][0] == "backup.restore_done"


def test_restore_single_identity_preview(setup):
    otp, _ = setup
    uid = otp.add("acme")
    res = run(export.export_identity(ScriptedInteraction(), "otp", uid, passphrases(PASSPHRASE)))
    obj = otp.data.pop(uid)
    ui = ScriptedInteraction()
    rep = run(restore.restore(ui, _frames_to_envelopes(res), passphrases(PASSPHRASE)))
    p = ui.prompts[0]
    assert dict(p.fields)["backup.field.identity"] == "acme"
    assert p.fingerprint == otp.describe(obj)[1]
    assert rep.restored == [("otp", "acme", uid)]


def test_restore_overwrite_confirm_and_refuse(setup):
    otp, fido = setup
    otp.add("acme")
    otp.add("bank")
    envs = _frames_to_envelopes(*_export_all(otp, fido))
    # modify the device state: both exist, with different secrets
    for uid in otp.data:
        otp.data[uid]["secret"] = b"\x00" * 32
    # summary yes, overwrite "acme" yes, overwrite "bank" no
    ui = ScriptedInteraction([True, True, False])
    rep = run(restore.restore(ui, envs, passphrases(PASSPHRASE)))
    assert ui.kinds() == ["backup.restore", "backup.overwrite", "backup.overwrite"]
    ow = ui.prompts[1]
    assert ow.severity == DANGER
    assert dict(ow.fields)["backup.field.identity"] == "acme"
    assert ow.fingerprint and len(ow.fingerprint) == 16
    assert [r[1] for r in rep.restored] == ["acme"]
    assert rep.skipped == [("otp", "bank")]
    secrets = {o["name"]: o["secret"] for o in otp.data.values()}
    assert secrets["acme"] != b"\x00" * 32
    assert secrets["bank"] == b"\x00" * 32  # refused: untouched


def test_restore_atomic_failure_midway(setup):
    otp, fido = setup
    otp.add("acme")
    otp.add("bank")
    fido.add("github.com alice")
    envs = _frames_to_envelopes(*_export_all(otp, fido))
    _wipe_providers(otp, fido)
    otp.fail_on = {"bank"}
    rep = run(restore.restore(ScriptedInteraction(), envs, passphrases(PASSPHRASE)))
    assert not rep.ok
    assert [r[1] for r in rep.restored] == ["acme"]
    assert rep.failed[0:2] == ("otp", "bank") and isinstance(rep.failed[2], StorageFull)
    assert rep.not_attempted == [("fido2", "github.com alice")]
    assert [o["name"] for o in otp.data.values()] == ["acme"]  # nothing partial
    assert fido.data == {}


def test_wrong_passphrase_leaves_storage_unchanged(setup):
    otp, fido = setup
    otp.add("acme")
    envs = _frames_to_envelopes(*_export_all(otp, fido))
    otp.data.clear()
    ui = ScriptedInteraction()
    get = passphrases(WRONG, WRONG, WRONG)
    with pytest.raises(AuthenticationFailed):
        run(restore.restore(ui, envs, get))
    assert [r.attempt for r in get.calls] == [1, 2, 3]
    assert [n[0] for n in ui.notifications] == ["backup.wrong_passphrase"] * 2
    assert ui.prompts == []  # no confirmation was even shown
    assert otp.data == {} and otp.restored == []


def test_wrong_then_right_passphrase(setup):
    otp, fido = setup
    otp.add("acme")
    envs = _frames_to_envelopes(*_export_all(otp, fido))
    otp.data.clear()
    rep = run(restore.restore(ScriptedInteraction(), envs, passphrases(WRONG, PASSPHRASE)))
    assert rep.ok and len(rep.restored) == 1


def test_max_attempts_one(setup):
    otp, fido = setup
    otp.add("acme")
    envs = _frames_to_envelopes(*_export_all(otp, fido))
    with pytest.raises(AuthenticationFailed):
        run(restore.restore(ScriptedInteraction(), envs, passphrases(WRONG), max_attempts=1))


def test_tampered_second_envelope_blocks_everything(setup):
    otp, fido = setup
    otp.add("acme")
    otp.add("bank")
    envs = _frames_to_envelopes(*_export_all(otp, fido))
    otp.data.clear()
    bad = bytearray(envs[1])
    bad[-1] ^= 1
    with pytest.raises(AuthenticationFailed):
        run(restore.restore(ScriptedInteraction(), [envs[0], bytes(bad)], passphrases(PASSPHRASE)))
    assert otp.data == {}


def test_restore_malformed_header_before_passphrase(setup):
    get = passphrases()
    with pytest.raises(BackupFormatError):
        run(restore.restore(ScriptedInteraction(), [b"FEBK\x02garbage"], get))
    assert get.calls == []
    with pytest.raises(InvalidInput):
        run(restore.restore(ScriptedInteraction(), [], get))
    with pytest.raises(InvalidInput):
        run(restore.restore(ScriptedInteraction(), [b"x"] * (envelope.MAX_SET_COUNT + 1), get))


def test_restore_unknown_type_writes_nothing(setup, registry):
    otp, fido = setup
    otp.add("acme")
    fido.add("github.com alice")
    envs = _frames_to_envelopes(*_export_all(otp, fido))
    _wipe_providers(otp, fido)
    registry.unregister("fido2")
    with pytest.raises(UnsupportedItem):
        run(restore.restore(ScriptedInteraction(), envs, passphrases(PASSPHRASE)))
    assert otp.data == {}


def test_restore_provider_validation_failure_writes_nothing(setup):
    otp, fido = setup
    otp.add("acme")
    otp.add("bank")
    envs = _frames_to_envelopes(*_export_all(otp, fido))
    otp.data.clear()
    original = otp.validate

    def strict(obj):
        original(obj)
        if obj["name"] == "bank":
            raise InvalidInput("rejected by provider")

    otp.validate = strict
    with pytest.raises(InvalidInput):
        run(restore.restore(ScriptedInteraction(), envs, passphrases(PASSPHRASE)))
    assert otp.data == {}


def test_restore_bad_describe(setup):
    otp, fido = setup
    otp.add("acme")
    envs = _frames_to_envelopes(*_export_all(otp, fido))
    otp.describe = lambda obj: ("acme", "not-hex")
    with pytest.raises(InvalidInput):
        run(restore.restore(ScriptedInteraction(), envs, passphrases(PASSPHRASE)))
    otp.describe = lambda obj: "acme"
    with pytest.raises(InvalidInput):
        run(restore.restore(ScriptedInteraction(), envs, passphrases(PASSPHRASE)))


def test_restore_summary_refused(setup):
    otp, fido = setup
    otp.add("acme")
    envs = _frames_to_envelopes(*_export_all(otp, fido))
    otp.data.clear()
    with pytest.raises(UserCancelled):
        run(restore.restore(ScriptedInteraction([False]), envs, passphrases(PASSPHRASE)))
    assert otp.data == {}


def test_restore_incomplete_full_set(setup):
    otp, fido = setup
    otp.add("acme")
    otp.add("bank")
    fido.add("github.com alice")
    envs = _frames_to_envelopes(*_export_all(otp, fido))
    _wipe_providers(otp, fido)
    partial = [envs[0], envs[2]]
    # refuse the incomplete-set warning
    ui = ScriptedInteraction([False])
    with pytest.raises(UserCancelled):
        run(restore.restore(ui, partial, passphrases(PASSPHRASE)))
    assert ui.kinds() == ["backup.restore_incomplete"]
    assert ui.prompts[0].severity == NORMAL
    assert dict(ui.prompts[0].fields)["backup.field.present"] == "2/3"
    assert otp.data == {} and fido.data == {}
    # accept it
    rep = run(restore.restore(ScriptedInteraction(), partial, passphrases(PASSPHRASE)))
    assert rep.incomplete_sets == [(2, 3)]
    assert sorted(r[1] for r in rep.restored) == ["acme", "github.com alice"]


def test_restore_dedup_identical_envelopes(setup):
    otp, fido = setup
    otp.add("acme")
    envs = _frames_to_envelopes(*_export_all(otp, fido))
    otp.data.clear()
    rep = run(restore.restore(ScriptedInteraction(), envs + envs, passphrases(PASSPHRASE)))
    assert len(rep.restored) == 1


def test_restore_two_exports_two_passphrases(setup):
    otp, fido = setup
    u1 = otp.add("acme")
    u2 = fido.add("github.com alice")
    pw2 = b"another passphrase!"
    e1 = run(export.export_identity(ScriptedInteraction(), "otp", u1, passphrases(PASSPHRASE)))
    e2 = run(export.export_identity(ScriptedInteraction(), "fido2", u2, passphrases(pw2)))
    _wipe_providers(otp, fido)
    get = passphrases(PASSPHRASE, pw2)
    rep = run(restore.restore(ScriptedInteraction(), _frames_to_envelopes(e1, e2), get))
    assert [(r.set_index, r.set_count) for r in get.calls] == [(1, 2), (2, 2)]
    assert len(rep.restored) == 2


def test_restore_storage_full_on_first(setup):
    otp, fido = setup
    otp.add("acme")
    envs = _frames_to_envelopes(*_export_all(otp, fido))
    otp.data.clear()
    otp.fail_on = {"acme"}
    ui = ScriptedInteraction()
    rep = run(restore.restore(ui, envs, passphrases(PASSPHRASE)))
    assert rep.failed[1] == "acme" and rep.restored == [] and otp.data == {}
    kind, _, fields = ui.notifications[-1]
    assert kind == "backup.restore_done"
    assert dict(fields) == {
        "backup.field.restored": "0",
        "backup.field.skipped": "0",
        "backup.field.failed": "1",
    }


def test_duck_typed_provider(registry, fast_kdf):
    d = DuckProvider()
    registry.register(d)
    d.data[b"k1"] = {"type": "duck", "v": 1, "n": "k1"}
    res = run(export.export_identity(ScriptedInteraction(), "duck", b"k1", passphrases(PASSPHRASE)))
    d.data.clear()
    rep = run(restore.restore(ScriptedInteraction(), _frames_to_envelopes(res), passphrases(PASSPHRASE)))
    assert rep.restored == [("duck", "k1", b"k1")]
    assert d.data[b"k1"]["n"] == "k1"


def test_real_iterations_end_to_end(registry):
    """One full round trip with the real 600 000 iterations."""
    p = FakeProvider("otp")
    registry.register(p)
    uid = p.add("acme")
    res = run(export.export_identity(ScriptedInteraction(), "otp", uid, passphrases(PASSPHRASE)))
    env = _frames_to_envelopes(res)[0]
    assert envelope.parse_header(env).iterations == 600_000
    obj = p.data.pop(uid)
    rep = run(restore.restore(ScriptedInteraction(), [env], passphrases(PASSPHRASE)))
    assert rep.ok and p.data[uid] == obj
