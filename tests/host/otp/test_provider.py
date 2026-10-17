# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
import hashlib

import pytest

from feuristic.apps.backup import provider as registry
from feuristic.apps.otp import accounts, hotp, provider, uri
from feuristic.core import cbor
from feuristic.core.errors import InvalidInput, NotFound, PolicyDenied
from feuristic.core.interaction import ScriptedInteraction
from feuristic.platform import testing

from ..aio import run

KEY = b"12345678901234567890"
OTHER = b"abcdefghijabcdefghij"


@pytest.fixture
def db():
    return accounts.OtpAccounts()


@pytest.fixture
def prov(db):
    return provider.OtpBackupProvider(db)


def _totp(db, issuer="GitHub", account="alice", secret=KEY):
    return db.add(uri.OtpParams("totp", issuer, account, secret, "SHA256", 8, 60))


def _hotp(db, counter=5, secret=KEY):
    return db.add(uri.OtpParams("hotp", "Corp", "bob", secret, counter=counter))


def test_interface_and_registration(prov):
    assert prov.TYPE == "otp"
    assert isinstance(prov, registry.BackupProvider)
    registry.unregister("otp")
    registry.register(prov)
    try:
        assert registry.get("otp") is prov
    finally:
        registry.unregister("otp")


def test_list_and_export(db, prov):
    t = _totp(db)
    h = _hotp(db)
    run(db.generate_hotp(h, ScriptedInteraction()))
    assert prov.list_identities() == [(h, "Corp: bob"), (t, "GitHub: alice")]
    for uid, label in prov.list_identities():
        registry.check_uid(uid)
        registry.check_label(label)
    obj = prov.export_identity(t)
    assert obj == {
        "v": 1,
        "type": "otp",
        "kind": "totp",
        "issuer": "GitHub",
        "account": "alice",
        "secret": KEY,
        "algorithm": "SHA256",
        "digits": 8,
        "period": 60,
    }
    hobj = prov.export_identity(h)
    assert hobj["kind"] == "hotp" and hobj["counter"] == 6 and "period" not in hobj
    for o in (obj, hobj):
        enc = cbor.encode(o)
        assert cbor.decode(enc, canonical=True) == o
        prov.validate(o)
    with pytest.raises(NotFound):
        prov.export_identity(b"\x00" * 8)
    assert prov.on_exported(t) is None


def test_describe_and_fingerprint(prov):
    obj = {
        "v": 1,
        "type": "otp",
        "kind": "totp",
        "issuer": "",
        "account": "me",
        "secret": KEY,
        "algorithm": "SHA1",
        "digits": 6,
        "period": 30,
    }
    label, fp = prov.describe(obj)
    assert label == "me"
    assert fp == hashlib.sha256(KEY).hexdigest()[:16]
    registry.check_fingerprint(fp)
    assert KEY.hex() not in fp


def test_restore_roundtrip_on_fresh_device(db, prov):
    t = _totp(db)
    h = _hotp(db, counter=40)
    run(db.generate_hotp(h, ScriptedInteraction()))
    blobs = [cbor.encode(prov.export_identity(u)) for u, _ in prov.list_identities()]
    testing.KV.reset()
    db2 = accounts.OtpAccounts()
    prov2 = provider.OtpBackupProvider(db2)
    for b in blobs:
        obj = cbor.decode(b, canonical=True)
        prov2.validate(obj)
        assert not prov2.exists(obj)
        prov2.restore_identity(obj, overwrite=False)
    assert [lbl for _, lbl in prov2.list_identities()] == ["Corp: bob", "GitHub: alice"]
    h2 = db2.find("Corp", "bob").uid
    assert db2.hotp_counter(h2) == 41
    assert run(db2.generate_hotp(h2, ScriptedInteraction())) == hotp.hotp(KEY, 41)
    assert db2.get(db2.find("GitHub", "alice").uid).algorithm == "SHA256"
    del t


def test_restore_existing_requires_overwrite(db, prov):
    uid = _totp(db)
    obj = prov.export_identity(uid)
    obj["secret"] = OTHER
    assert prov.exists(obj)
    with pytest.raises(PolicyDenied):
        prov.restore_identity(obj, overwrite=False)
    assert db.get(uid).secret == KEY
    assert prov.restore_identity(obj, overwrite=True) == uid
    assert db.get(uid).secret == OTHER
    assert len(db) == 1


def test_restore_old_backup_never_rolls_back_hotp(db, prov):
    uid = _hotp(db, counter=0)
    old = prov.export_identity(uid)
    for _ in range(4):
        run(db.generate_hotp(uid, ScriptedInteraction()))
    prov.restore_identity(old, overwrite=True)
    assert db.hotp_counter(uid) == 4


def test_restore_when_full(db, prov):
    from feuristic.core.errors import StorageFull

    for i in range(accounts.CAPACITY):
        db.add(uri.OtpParams("totp", "", f"u{i}", bytes([i + 1]) * 10))
    obj = {
        "v": 1,
        "type": "otp",
        "kind": "totp",
        "issuer": "",
        "account": "extra",
        "secret": KEY,
        "algorithm": "SHA1",
        "digits": 6,
        "period": 30,
    }
    with pytest.raises(StorageFull):
        prov.restore_identity(obj, overwrite=False)
    obj["account"] = "u3"
    prov.restore_identity(obj, overwrite=True)  # replacing still works at capacity


BASE = {
    "v": 1,
    "type": "otp",
    "kind": "hotp",
    "issuer": "I",
    "account": "a",
    "secret": KEY,
    "algorithm": "SHA1",
    "digits": 6,
    "counter": 0,
}


@pytest.mark.parametrize(
    "mutation",
    [
        {"v": 2},
        {"v": True},
        {"v": "1"},
        {"type": "fido2"},
        {"kind": "motp"},
        {"kind": "totp"},  # totp without period
        {"issuer": None},
        {"issuer": "x" * 33},
        {"issuer": "a:b"},
        {"account": ""},
        {"account": "a" * 65},
        {"account": "bad\u202e"},
        {"secret": "notbytes"},
        {"secret": b""},
        {"secret": bytes(65)},
        {"algorithm": "sha1"},
        {"algorithm": 0},
        {"digits": 10},
        {"digits": True},
        {"counter": -1},
        {"counter": 2**64},
        {"counter": None},
        {"counter": True},
        {"extra": 1},
        {"period": 30},  # unknown field for hotp
    ],
)
def test_validate_rejects_malformed(prov, mutation):
    obj = dict(BASE)
    obj.update(mutation)
    with pytest.raises(InvalidInput):
        prov.validate(obj)
    with pytest.raises(InvalidInput):
        prov.restore_identity(obj, overwrite=True)


@pytest.mark.parametrize("missing", list(BASE))
def test_validate_rejects_missing_field(prov, missing):
    obj = dict(BASE)
    del obj[missing]
    with pytest.raises(InvalidInput):
        prov.validate(obj)


def test_validate_rejects_non_dict(prov):
    for bad in (None, [], "otp", 1):
        with pytest.raises(InvalidInput):
            prov.validate(bad)
        with pytest.raises(InvalidInput):
            provider.params_from_object(bad)


def test_totp_period_type_checked(prov):
    obj = dict(BASE)
    del obj["counter"]
    obj["kind"] = "totp"
    obj["period"] = None
    with pytest.raises(InvalidInput):
        prov.validate(obj)
    obj["period"] = 30
    prov.validate(obj)


def test_default_accounts_instance():
    accounts._reset_default()
    try:
        p = provider.OtpBackupProvider()
        assert p.accounts is accounts.default()
        assert p.list_identities() == []
    finally:
        accounts._reset_default()
