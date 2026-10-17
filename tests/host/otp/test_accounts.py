# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
import contextlib

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from feuristic.apps.otp import accounts, hotp, totp, uri
from feuristic.core import cbor, namespaces, store
from feuristic.core import clock as clock_mod
from feuristic.core.errors import (
    InvalidInput,
    NotFound,
    PolicyDenied,
    StorageCorrupted,
    StorageFull,
    UserCancelled,
    UserTimeout,
)
from feuristic.core.interaction import DANGER, NORMAL, SENSITIVE, ScriptedInteraction
from feuristic.platform import testing

from ..aio import run

KEY = b"12345678901234567890"
KEY_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
OTHER = b"abcdefghijabcdefghij"
T0 = 1_800_000_000


def totp_params(issuer="GitHub", account="alice", secret=KEY, **kw):
    return uri.OtpParams("totp", issuer, account, secret, **kw)


def hotp_params(issuer="Corp", account="bob", secret=KEY, counter=0, **kw):
    return uri.OtpParams("hotp", issuer, account, secret, counter=counter, **kw)


def counter_keys(index):
    return [(namespaces.OTP_COUNTERS | 0x80, 2 * index), (namespaces.OTP_COUNTERS | 0x80, 2 * index + 1)]


@pytest.fixture
def db():
    return accounts.OtpAccounts()


def reload():
    db = accounts.OtpAccounts()
    db.load()
    return db


# -- basic CRUD -------------------------------------------------------------------


def test_add_get_list_sorted(db, det_rng):
    u1 = db.add(totp_params("github", "zed"))
    u2 = db.add(totp_params("GitHub", "alice"))
    u3 = db.add(hotp_params("Amazon", "x"))
    u4 = db.add(totp_params("", "standalone"))
    assert len(db) == 4
    assert all(len(u) == store.UID_LEN for u in (u1, u2, u3, u4))
    labels = [a.label() for a in db.accounts()]
    assert labels == ["standalone", "Amazon: x", "GitHub: alice", "github: zed"]
    acc = db.get(u3)
    assert acc.is_hotp and acc.counter_base == 0 and acc.counter_index == 0
    assert "1234" not in repr(acc)
    with pytest.raises(NotFound):
        db.get(b"\x00" * 8)


def test_payload_is_canonical_cbor_within_cap(db):
    p = hotp_params("i" * 32, "a" * 64, bytes(range(64)), counter=2**64 - 1, algorithm="SHA512", digits=8)
    uid = db.add(p)
    payload = db.store.get(uid)
    assert len(payload) <= accounts.MAX_PAYLOAD
    m = cbor.decode(payload, canonical=True)
    assert m[0] == 1 and m[1] == 1 and m[4] == bytes(range(64)) and m[8] == 2**64 - 1
    assert cbor.encode(m) == payload


def test_persistence_across_reload(db, clock):
    u1 = db.add(totp_params(period=60, digits=8, algorithm="SHA256"))
    u2 = db.add(hotp_params(counter=5))
    run(db.generate_hotp(u2, ScriptedInteraction()))
    db2 = reload()
    a1 = db2.get(u1)
    assert (a1.period, a1.digits, a1.algorithm, a1.secret) == (60, 8, "SHA256", KEY)
    assert db2.hotp_counter(u2) == 6
    assert run(db2.generate_hotp(u2, ScriptedInteraction())) == hotp.hotp(KEY, 6)


def test_capacity_32(db):
    for i in range(accounts.CAPACITY):
        db.add(hotp_params(account=f"user{i:02d}", secret=bytes([i + 1]) * 20))
    assert db.is_full()
    with pytest.raises(StorageFull):
        db.add(totp_params(account="one-too-many"))
    with pytest.raises(StorageFull):
        run(db.import_params(totp_params(account="one-too-many"), ScriptedInteraction()))
    # replacement still possible at full capacity (all 32 counter indices in use)
    victim = db.find("Corp", "user07")
    run(db.generate_hotp(victim.uid, ScriptedInteraction()))
    uid = db.add(hotp_params(account="user07", secret=OTHER, counter=100), victim.uid)
    assert uid == victim.uid
    acc = db.get(uid)
    assert acc.counter_index == 32 and acc.secret == OTHER
    assert db.hotp_counter(uid) == 100
    assert len(reload()) == 32
    # indices are all distinct
    idx = [a.counter_index for a in reload().accounts()]
    assert len(set(idx)) == 32


def test_rename(db):
    uid = db.add(hotp_params(counter=3))
    other = db.add(totp_params("X", "y"))
    run(db.generate_hotp(uid, ScriptedInteraction()))
    db.rename(uid, "New Corp", "robert")
    acc = db.get(uid)
    assert (acc.issuer, acc.account, acc.secret) == ("New Corp", "robert", KEY)
    assert db.hotp_counter(uid) == 4
    db.rename(uid, "New Corp", "robert")  # same name: no-op allowed
    with pytest.raises(accounts.AlreadyExists):
        db.rename(uid, "X", "y")
    for issuer, account in (("a" * 33, "b"), ("ok", ""), ("ok", "a" * 65), ("a:b", "c"), ("ok", "x\ny")):
        with pytest.raises(InvalidInput):
            db.rename(uid, issuer, account)
    with pytest.raises(NotFound):
        db.rename(b"\x01" * 8, "a", "b")
    assert db.get(other).issuer == "X"


def test_delete_resets_counters(db, kv):
    uid = db.add(hotp_params())
    for _ in range(3):
        run(db.generate_hotp(uid, ScriptedInteraction()))
    keys = counter_keys(db.get(uid).counter_index)
    assert all(k in kv.data for k in keys)
    assert db.delete(uid)
    assert not any(k in kv.data for k in keys)
    assert not db.delete(uid)
    assert len(db) == 0
    # the index is reused and starts from the imported counter again
    uid2 = db.add(hotp_params(counter=0))
    assert db.get(uid2).counter_index == 0
    assert db.hotp_counter(uid2) == 0


def test_orphan_counter_reset_on_reuse(db, kv):
    # simulate a power cut after the record deletion but before the counter reset
    uid = db.add(hotp_params())
    for _ in range(5):
        run(db.generate_hotp(uid, ScriptedInteraction()))
    db.store.delete(uid)
    assert any(k in kv.data for k in counter_keys(0))
    uid2 = db.add(hotp_params(secret=OTHER, counter=0))
    assert db.hotp_counter(uid2) == 0


def test_wipe(db, kv):
    db.add(hotp_params())
    db.add(totp_params())
    db.wipe()
    assert len(db) == 0
    assert not kv.data


# -- codes ---------------------------------------------------------------------------


def test_totp_code(db, clock):
    uid = db.add(totp_params(period=30, digits=8))
    sc = clock_mod.SessionClock()
    with pytest.raises(totp.TimeNotSynchronised):
        db.totp_code(uid, sc)
    sc.set(T0)
    clock.advance(7_000)
    assert db.totp_code(uid, sc) == totp.totp_at(KEY, T0 + 7, 30, 8)
    hid = db.add(hotp_params())
    with pytest.raises(InvalidInput):
        db.totp_code(hid, sc)


def test_totp_code_default_clock(db):
    uid = db.add(totp_params())
    clock_mod.CLOCK.clear()
    try:
        with pytest.raises(totp.TimeNotSynchronised):
            db.totp_code(uid)
        clock_mod.CLOCK.set(T0)
        assert db.totp_code(uid) == totp.totp_at(KEY, T0)
    finally:
        clock_mod.CLOCK.clear()


def test_hotp_generation_sequence_rfc4226(db):
    uid = db.add(hotp_params(counter=0))
    ui = ScriptedInteraction()
    codes = [run(db.generate_hotp(uid, ui)) for _ in range(10)]
    assert codes == [hotp.hotp(KEY, i) for i in range(10)]
    assert ui.kinds() == ["otp.hotp_generate"] * 10
    p = ui.prompts[3]
    assert p.severity == SENSITIVE
    assert ("otp.field.counter", "3") in p.fields
    assert ("otp.field.issuer", "Corp") in p.fields
    assert p.warning == "otp.hotp_generate.warning"


def test_hotp_initial_counter_from_import(db):
    uid = db.add(hotp_params(counter=1000))
    assert run(db.generate_hotp(uid, ScriptedInteraction())) == hotp.hotp(KEY, 1000)
    assert db.hotp_counter(uid) == 1001


def test_hotp_refused_does_not_advance(db):
    uid = db.add(hotp_params())
    with pytest.raises(UserCancelled):
        run(db.generate_hotp(uid, ScriptedInteraction([False])))
    assert db.hotp_counter(uid) == 0


def test_hotp_on_totp_account_rejected(db):
    uid = db.add(totp_params())
    with pytest.raises(InvalidInput):
        run(db.generate_hotp(uid, ScriptedInteraction()))
    with pytest.raises(InvalidInput):
        db.hotp_counter(uid)


def test_hotp_counter_exhaustion(db):
    uid = db.add(hotp_params(counter=2**64 - 2))
    assert run(db.generate_hotp(uid, ScriptedInteraction())) == hotp.hotp(KEY, 2**64 - 2)
    with pytest.raises(StorageFull):
        run(db.generate_hotp(uid, ScriptedInteraction()))
    assert uri.parse(db.export_uri(uid)).counter == 2**64 - 1


class _MutatingUI(ScriptedInteraction):
    """Changes the state while the prompt is displayed (concurrent task)."""

    def __init__(self, action):
        super().__init__()
        self.action = action

    async def confirm(self, prompt):
        self.prompts.append(prompt)
        self.action()
        return True


def test_hotp_counter_advanced_during_prompt_is_not_reused(db):
    uid = db.add(hotp_params())
    inner = ScriptedInteraction()
    code_inner = []
    ui = _MutatingUI(lambda: code_inner.append(run(db.generate_hotp(uid, inner))))
    code = run(db.generate_hotp(uid, ui))
    assert code_inner == [hotp.hotp(KEY, 0)]
    assert code == hotp.hotp(KEY, 1)
    assert db.hotp_counter(uid) == 2


def test_hotp_account_deleted_during_prompt(db):
    uid = db.add(hotp_params())
    with pytest.raises(NotFound):
        run(db.generate_hotp(uid, _MutatingUI(lambda: db.delete(uid))))


def _crash_run(fn, kv, crash_at):
    kv.crash_after_ops = crash_at
    try:
        return fn(), False
    except testing.PowerLoss:
        return None, True
    finally:
        kv.crash_after_ops = None


def test_power_loss_during_hotp_never_reuses_counter(kv):
    for crash_at in range(6):
        testing.reset_all()
        db = accounts.OtpAccounts()
        uid = db.add(hotp_params())
        used = []
        for _ in range(3):
            used.append(db.hotp_counter(uid))
            run(db.generate_hotp(uid, ScriptedInteraction()))
        value = db.hotp_counter(uid)
        code, crashed = _crash_run(
            lambda db=db, uid=uid: run(db.generate_hotp(uid, ScriptedInteraction())), kv, crash_at
        )
        if not crashed:
            used.append(value)
        db = reload()
        nxt = db.hotp_counter(uid)
        assert nxt > max(used)
        assert run(db.generate_hotp(uid, ScriptedInteraction())) == hotp.hotp(KEY, nxt)


@settings(max_examples=60, deadline=None)
@given(st.lists(st.integers(min_value=-1, max_value=5), min_size=1, max_size=12))
def test_power_loss_property_hotp_values_unique(crashes):
    testing.reset_all()
    db = accounts.OtpAccounts()
    uid = db.add(hotp_params(counter=7))
    released = []
    for crash in crashes:
        before = db.hotp_counter(uid)
        testing.KV.crash_after_ops = None if crash < 0 else crash
        try:
            code = run(db.generate_hotp(uid, ScriptedInteraction()))
            released.append((before, code))
        except testing.PowerLoss:
            db = reload()  # reboot
        finally:
            testing.KV.crash_after_ops = None
    values = [v for v, _ in released]
    assert len(values) == len(set(values))
    assert values == sorted(values)
    for v, code in released:
        assert code == hotp.hotp(KEY, v)
    assert reload().hotp_counter(uid) > (max(values) if values else 6)
    testing.reset_all()


def test_power_loss_during_add_and_replace(kv):
    for crash_at in range(12):
        testing.reset_all()
        db = accounts.OtpAccounts()
        uid = db.add(hotp_params(counter=10))
        run(db.generate_hotp(uid, ScriptedInteraction()))
        _, crashed = _crash_run(
            lambda db=db, uid=uid: db.add(hotp_params(secret=OTHER, counter=50), uid), kv, crash_at
        )
        db = reload()
        acc = db.get(uid)
        if acc.secret == KEY:
            assert crashed
            assert db.hotp_counter(uid) == 11
        else:
            assert acc.secret == OTHER
            assert db.hotp_counter(uid) == 50
        assert len(db) == 1
        # adding a new HOTP account afterwards always starts from its own counter
        u2 = db.add(hotp_params(account="new", secret=b"z" * 20, counter=3))
        assert db.hotp_counter(u2) == 3
    for crash_at in range(6):
        testing.reset_all()
        db = accounts.OtpAccounts()
        _crash_run(lambda db=db: db.add(hotp_params()), kv, crash_at)
        db = reload()
        assert len(db) in (0, 1)
        for a in db.accounts():
            assert db.hotp_counter(a) == 0


# -- import flows ------------------------------------------------------------------------


def test_import_new_with_prompt(db):
    ui = ScriptedInteraction()
    uid = run(db.import_uri(f"otpauth://totp/GitHub:alice?secret={KEY_B32}&issuer=GitHub", ui))
    assert db.get(uid).account == "alice"
    p = ui.prompts[0]
    assert (p.kind, p.title, p.severity, p.warning) == ("otp.import", "otp.import.title", NORMAL, None)
    assert ("otp.field.type", "TOTP") in p.fields
    assert ("otp.field.period", "30 s") in p.fields


def test_import_hotp_prompt_shows_counter(db):
    ui = ScriptedInteraction()
    run(db.import_uri(f"otpauth://hotp/C:me?secret={KEY_B32}&counter=9", ui))
    assert ("otp.field.counter", "9") in ui.prompts[0].fields


def test_import_weak_secret_warning(db):
    ui = ScriptedInteraction()
    run(db.import_uri("otpauth://totp/weak?secret=MZXW6YQ", ui))
    p = ui.prompts[0]
    assert p.warning == "otp.import.weak_secret"
    assert p.severity == SENSITIVE
    assert p.fields[-1][0] == "otp.field.warning"


def test_import_refused(db):
    with pytest.raises(UserCancelled):
        run(db.import_params(totp_params(), ScriptedInteraction([False])))
    assert len(db) == 0


def test_import_invalid_uri(db):
    ui = ScriptedInteraction()
    with pytest.raises(InvalidInput):
        run(db.import_uri("otpauth://totp/x?secret=0000", ui))
    assert ui.prompts == []


def test_duplicate_import(db):
    db.add(totp_params())
    ui = ScriptedInteraction()
    assert db.classify_import(totp_params(digits=8))[0] == accounts.IMPORT_DUPLICATE
    with pytest.raises(accounts.AlreadyExists) as ei:
        run(db.import_params(totp_params(), ui))
    assert isinstance(ei.value, PolicyDenied)
    assert ui.prompts == []
    assert len(db) == 1
    with pytest.raises(accounts.AlreadyExists):
        db.add(totp_params(secret=OTHER))


def test_replace_flow_confirmed(db):
    uid = db.add(totp_params())
    status, existing = db.classify_import(totp_params(secret=OTHER))
    assert status == accounts.IMPORT_CONFLICT and existing.uid == uid
    ui = ScriptedInteraction()
    uid2 = run(db.import_params(totp_params(secret=OTHER, digits=8), ui))
    assert uid2 == uid
    assert db.get(uid).secret == OTHER and db.get(uid).digits == 8
    p = ui.prompts[0]
    assert (p.kind, p.severity, p.warning) == ("otp.replace", DANGER, "otp.replace.warning")
    assert len(db) == 1


def test_replace_flow_refused(db):
    uid = db.add(totp_params())
    with pytest.raises(UserCancelled):
        run(db.import_params(totp_params(secret=OTHER), ScriptedInteraction([False])))
    assert db.get(uid).secret == KEY


def test_replace_totp_by_hotp_and_back(db, kv):
    uid = db.add(totp_params())
    db.add(hotp_params(issuer="GitHub", account="alice", secret=OTHER, counter=4), uid)
    acc = db.get(uid)
    assert acc.is_hotp and db.hotp_counter(uid) == 4
    keys = counter_keys(acc.counter_index)
    run(db.generate_hotp(uid, ScriptedInteraction()))
    db.add(totp_params(), uid)
    assert not db.get(uid).is_hotp
    assert not any(k in kv.data for k in keys)


def test_replace_same_secret_never_rolls_back_counter(db):
    uid = db.add(hotp_params(counter=0))
    for _ in range(5):
        run(db.generate_hotp(uid, ScriptedInteraction()))
    db.add(hotp_params(counter=2, digits=8), uid)
    assert db.hotp_counter(uid) == 5
    assert db.get(uid).digits == 8
    db.add(hotp_params(counter=9), uid)
    assert db.hotp_counter(uid) == 9


def test_replace_errors(db):
    a = db.add(totp_params("A", "a"))
    db.add(totp_params("B", "b"))
    with pytest.raises(accounts.AlreadyExists):
        db.add(totp_params("B", "b", secret=OTHER), a)
    with pytest.raises(NotFound):
        db.add(totp_params("C", "c"), b"\x09" * 8)
    with pytest.raises(InvalidInput):
        db.add({"kind": "totp"})


def test_state_change_during_import_prompt(db):
    ui = _MutatingUI(lambda: db.add(totp_params(secret=OTHER)))
    with pytest.raises(accounts.AlreadyExists):
        run(db.import_params(totp_params(), ui))
    assert db.find("GitHub", "alice").secret == OTHER


# -- export ---------------------------------------------------------------------------------


def test_export_uri_roundtrip_totp(db):
    uid = db.add(totp_params("ACME Co", "jo@x.org", algorithm="SHA512", digits=7, period=45))
    built = db.export_uri(uid)
    assert built == (
        f"otpauth://totp/ACME%20Co:jo@x.org?secret={KEY_B32}&issuer=ACME%20Co"
        "&algorithm=SHA512&digits=7&period=45"
    )
    p = uri.parse(built)
    assert (p.issuer, p.account, p.secret, p.algorithm, p.digits, p.period) == (
        "ACME Co",
        "jo@x.org",
        KEY,
        "SHA512",
        7,
        45,
    )


def test_export_uri_hotp_includes_current_counter(db):
    uid = db.add(hotp_params(counter=10))
    for _ in range(3):
        run(db.generate_hotp(uid, ScriptedInteraction()))
    p = uri.parse(db.export_uri(uid))
    assert p.counter == 13
    # an authenticator importing the export continues with the next unused value
    assert hotp.hotp(p.secret, p.counter) == run(db.generate_hotp(uid, ScriptedInteraction()))


def test_export_reimport_on_other_device_is_duplicate(db):
    uid = db.add(hotp_params(counter=3))
    text = db.export_uri(uid)
    with pytest.raises(accounts.AlreadyExists):
        run(db.import_uri(text, ScriptedInteraction()))
    testing.KV.reset()
    db2 = accounts.OtpAccounts()
    uid2 = run(db2.import_uri(text, ScriptedInteraction()))
    assert db2.hotp_counter(uid2) == 3


def test_export_prompt_and_other_prompts(db):
    uid = db.add(totp_params())
    acc = db.get(uid)
    p = db.export_prompt(acc)
    assert (p.kind, p.title, p.severity, p.warning) == (
        "otp.export",
        "otp.export.title",
        DANGER,
        "otp.export.warning",
    )
    assert p.fields[-1][0] == "otp.field.warning"
    assert "photograph" in p.fields[-1][1]
    assert "1234" not in repr(p)
    d = db.delete_prompt(acc)
    assert (d.kind, d.severity) == ("otp.delete", DANGER)
    assert accounts.EXPORT_DISPLAY_TIMEOUT_MS == 60_000


def test_export_prompt_french():
    from feuristic.core import i18n

    db = accounts.OtpAccounts()
    acc = db.get(db.add(totp_params()))
    i18n.set_language(i18n.FR)
    try:
        p = db.export_prompt(acc)
        assert p.fields[-1][1] == "Toute personne photographiant ce QR peut reproduire les codes."
    finally:
        i18n.set_language(i18n.EN)


# -- corruption ----------------------------------------------------------------------------


def _raw_put(db, uid, payload):
    db.store.put(uid, payload)


@pytest.mark.parametrize(
    "payload",
    [
        b"\xff",
        cbor.encode([1, 2]),
        cbor.encode({0: 2}),
        cbor.encode({0: 1, 1: 5, 2: "i", 3: "a", 4: KEY, 5: 0, 6: 6, 7: 30}),
        cbor.encode({0: 1, 1: 0, 2: "i", 3: "a", 4: KEY, 5: 9, 6: 6, 7: 30}),
        cbor.encode({0: 1, 1: 0, 2: "i", 3: "a", 4: KEY, 5: 0, 6: 6}),
        cbor.encode({0: 1, 1: 0, 2: "i", 3: "a", 4: KEY, 5: 0, 6: 6, 7: 30, 8: 1}),
        cbor.encode({0: 1, 1: 0, 2: "i", 3: "a", 4: KEY, 5: 0, 6: 9, 7: 30}),
        cbor.encode({0: 1, 1: 0, 2: "i", 3: "", 4: KEY, 5: 0, 6: 6, 7: 30}),
        cbor.encode({0: 1, 1: 1, 2: "i", 3: "a", 4: KEY, 5: 0, 6: 6, 8: 0, 9: 33}),
        cbor.encode({0: 1, 1: 1, 2: "i", 3: "a", 4: KEY, 5: 0, 6: 6, 8: 0, 9: True}),
        cbor.encode({0: 1, 1: True, 2: "i", 3: "a", 4: KEY, 5: 0, 6: 6, 7: 30}),
        bytes.fromhex("a2000101a0"),  # non-canonical / nested
    ],
)
def test_corrupt_records_are_skipped(db, payload):
    good = db.add(totp_params())
    bad = b"\xbb" * 8
    _raw_put(db, bad, payload)
    assert [a.uid for a in db.accounts()] == [good]
    assert db.corrupt_uids == [bad]
    with pytest.raises(StorageCorrupted):
        db.get(bad)
    assert db.delete(bad)
    assert db.corrupt_uids == [bad]  # refreshed on next listing
    db.accounts()
    assert db.corrupt_uids == []


def test_default_instance_shared():
    accounts._reset_default()
    a = accounts.default()
    assert accounts.default() is a
    accounts._reset_default()
    assert accounts.default() is not a
    accounts._reset_default()


def test_user_timeout_exception_propagates(db):
    class TimeoutUI(ScriptedInteraction):
        async def confirm(self, prompt):
            raise UserTimeout

    uid = db.add(hotp_params())
    with contextlib.suppress(UserTimeout):
        run(db.generate_hotp(uid, TimeoutUI()))
    assert db.hotp_counter(uid) == 0
