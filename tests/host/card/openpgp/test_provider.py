# SPDX-License-Identifier: GPL-3.0-only
"""OpenPGP backup provider: export, validation, atomic restore."""

import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from feuristic.apps.backup import provider as bp
from feuristic.apps.card.openpgp import const as pgp
from feuristic.apps.card.openpgp import localmgmt
from feuristic.apps.card.openpgp.provider import UID, OpenPgpBackupProvider
from feuristic.core import cbor
from feuristic.core.errors import InvalidInput, NotFound, PolicyDenied
from feuristic.platform import testing

from ...aio import run
from .conftest import Env, public_from_7f49

T = 1_800_000_000


def make_source():
    e = Env()
    run(localmgmt.generate_keys(e.store, localmgmt.PROFILE_25519, T))
    e.select()
    e.tx(0x24, 0, 0x81, b"123456" + b"user-pin")
    e.admin()
    e.put(0x5B, b"Doe<<Jane")
    e.put(0x5F50, b"https://example.org/jane.asc")
    e.put(0x7F21, b"\x30\x82\x01\x00" + bytes(256))
    e.put(0xD3, b"resetting")
    e.put(0x0102, b"private two")
    e.verify(0x81, b"user-pin")
    for _ in range(5):
        e.tx(0x2A, 0x9E, 0x9A, bytes(32), ne=256)
    return e


def test_list_and_export():
    fresh = Env()
    p = OpenPgpBackupProvider(fresh.store)
    assert p.list_identities() == []
    with pytest.raises(NotFound):
        p.export_identity(UID)
    e = make_source()
    p = OpenPgpBackupProvider(e.store)
    ((uid, label),) = p.list_identities()
    assert uid == UID and label == "OpenPGP - Doe Jane"
    bp.check_uid(uid)
    bp.check_label(label)
    item = p.export_identity(uid)
    assert item["type"] == "openpgp" and item["v"] == 1
    assert item["dsc"] == 5 and item["name"] == b"Doe<<Jane"
    assert item["rc"] is not None and item["pw1"]["len"] == 8
    assert len(item["keys"]) == 3 and all(k["secret"] for k in item["keys"])
    p.validate(item)
    # canonical CBOR round trip, as the backup envelope does
    again = cbor.decode(cbor.encode(item), canonical=True)
    p.validate(again)
    label2, fp = p.describe(again)
    assert label2 == label and fp == item["keys"][0]["fpr"].hex().upper()
    bp.check_fingerprint(fp)
    with pytest.raises(NotFound):
        p.export_identity(b"other")
    p.on_exported(uid)


def test_restore_on_other_device():
    src = make_source()
    item = cbor.decode(cbor.encode(OpenPgpBackupProvider(src.store).export_identity(UID)), canonical=True)
    pub = public_from_7f49(src.read_public(0xB6)[0])[0x86]
    testing.KV.reset()
    dst = Env(ms=b"\x07" * 32)
    p = OpenPgpBackupProvider(dst.store)
    assert not p.exists(item)
    assert p.restore_identity(item, overwrite=False) == UID
    dst.reboot().select()
    assert public_from_7f49(dst.read_public(0xB6)[0])[0x86] == pub
    assert dst.get(0x5B)[0] == b"Doe<<Jane"
    assert dst.get(0x7F21)[0] == b"\x30\x82\x01\x00" + bytes(256)
    assert dst.get(0x0102)[0] == b"private two"
    assert dst.get(0xC4)[0][4:] == b"\x03\x03\x03"
    assert dst.verify(0x81, b"user-pin") == 0x9000  # same PIN after restore
    assert dst.verify(0x83, b"12345678") == 0x9000
    sig, sw = dst.tx(0x2A, 0x9E, 0x9A, b"\x01" * 32, ne=256)
    assert sw == 0x9000
    Ed25519PublicKey.from_public_bytes(pub).verify(sig, b"\x01" * 32)
    data, _ = dst.get(0x7A)
    assert data[-3:] == (6).to_bytes(3, "big")  # 5 restored + 1


def test_restore_overwrite_policy():
    src = make_source()
    item = OpenPgpBackupProvider(src.store).export_identity(UID)
    other = Env()
    run(localmgmt.generate_keys(other.store, localmgmt.PROFILE_25519, T + 5))
    p = OpenPgpBackupProvider(other.store)
    assert p.exists(item)
    with pytest.raises(PolicyDenied):
        p.restore_identity(item, overwrite=False)
    assert localmgmt.status(other.store)["keys"][0]["created"] == T + 5
    p.restore_identity(item, overwrite=True)
    assert other.store.ident.keys[0].secret == item["keys"][0]["secret"]


def test_restore_drops_applet_verification():
    src = make_source()
    item = OpenPgpBackupProvider(src.store).export_identity(UID)
    dst = Env()
    dst.select()
    dst.verify(0x81, b"123456")
    OpenPgpBackupProvider(dst.store).restore_identity(item, overwrite=True)
    assert dst.tx(0x20, 0, 0x81)[1] == 0x63C3


def _mutations():
    def m(fn):
        return fn

    return [
        ("unknown field", lambda o: o.update({"extra": 1})),
        ("missing field", lambda o: o.pop("cert")),
        ("bad version", lambda o: o.update({"v": 2})),
        ("bad type", lambda o: o.update({"type": "piv"})),
        ("two keys", lambda o: o["keys"].pop()),
        ("short secret", lambda o: o["keys"][0].update({"secret": bytes(31)})),
        ("role mismatch", lambda o: o["keys"][1].update({"attr": pgp.ATTR_ED25519})),
        ("unknown attr", lambda o: o["keys"][0].update({"attr": b"\x13\x2a"})),
        ("non canonical attr", lambda o: o["keys"][0].update({"attr": pgp.ATTR_ED25519 + b"\xff"})),
        ("origin without key", lambda o: o["keys"][0].update({"secret": None})),
        ("fpr length", lambda o: o["keys"][0].update({"fpr": bytes(19)})),
        ("date", lambda o: o["keys"][0].update({"date": -1})),
        ("name too long", lambda o: o.update({"name": b"x" * 40})),
        ("sex", lambda o: o.update({"sex": b"5"})),
        ("cert too long", lambda o: o.update({"cert": bytes(2049)})),
        ("private count", lambda o: o.update({"private": [b""] * 3})),
        ("pin short", lambda o: o["pw1"].update({"len": 5})),
        ("pin salt", lambda o: o["pw3"].update({"salt": bytes(8)})),
        ("pin extra", lambda o: o["pw3"].update({"x": 1})),
        ("pw1 missing", lambda o: o.update({"pw1": None})),
        ("pw1_status", lambda o: o.update({"pw1_status": 2})),
        ("bool status", lambda o: o.update({"pw1_status": True})),
        ("dsc", lambda o: o.update({"dsc": 1 << 24})),
        ("keys type", lambda o: o.update({"keys": {}})),
    ]


@pytest.mark.parametrize(("name", "mutate"), _mutations(), ids=[n for n, _ in _mutations()])
def test_validation_rejects(name, mutate):
    src = make_source()
    p = OpenPgpBackupProvider(src.store)
    item = copy.deepcopy(p.export_identity(UID))
    mutate(item)
    with pytest.raises(InvalidInput):
        p.validate(item)
    before = dict(testing.KV.data)
    with pytest.raises(InvalidInput):
        p.restore_identity(item, overwrite=True)
    assert testing.KV.data == before  # nothing written


def test_restore_is_atomic_under_power_loss():
    src = make_source()
    item = OpenPgpBackupProvider(src.store).export_identity(UID)
    testing.KV.reset()
    dst = Env()
    run(localmgmt.generate_keys(dst.store, localmgmt.PROFILE_25519, T + 9))
    dst.select()
    dst.admin()
    dst.put(0x5F50, b"https://old")
    old_secret = dst.store.ident.keys[0].secret
    snapshot = dict(testing.KV.data)
    testing.KV.ops = 0
    OpenPgpBackupProvider(dst.reboot().store).restore_identity(item, overwrite=True)
    n = testing.KV.ops
    for k in range(n):
        testing.KV.data = dict(snapshot)
        dst.reboot()
        testing.KV.ops = 0
        testing.KV.crash_after_ops = k
        with pytest.raises(testing.PowerLoss):
            OpenPgpBackupProvider(dst.store).restore_identity(item, overwrite=True)
        testing.KV.crash_after_ops = None
        dst.reboot().select()
        secret = dst.store.ident.keys[0].secret
        url = dst.get(0x5F50)[0]
        if secret == old_secret:
            assert url == b"https://old"
        else:
            assert secret == item["keys"][0]["secret"]
            assert url == b"https://example.org/jane.asc"


def test_registry_integration():
    bp.clear()
    p = OpenPgpBackupProvider(Env().store)
    bp.register(p)
    assert bp.get("openpgp") is p
    bp.unregister("openpgp")


def test_label_latin1_name():
    e = Env()
    e.store.ident.name = b"M\xfcller<<Hans"
    e.store.save()
    ((_, label),) = OpenPgpBackupProvider(e.store).list_identities()
    assert label == "OpenPGP - Müller Hans"
