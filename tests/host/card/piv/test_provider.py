# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""PIV backup provider (docs/protocols/backup-piv.md)."""

import contextlib
import hashlib

import pytest
from cryptography.hazmat.primitives import serialization

from feuristic.apps.backup import provider as registry
from feuristic.apps.card.piv import consts, provider, storage
from feuristic.core import cbor
from feuristic.core.errors import InvalidInput, NotFound, PolicyDenied
from feuristic.platform import testing

from .pivutil import cert_object, generate, mgmt_auth, put_data


@pytest.fixture
def prov(store):
    return provider.PivBackupProvider(store)


def ec_obj(slot=0x9A, sk=None, **kw):
    obj = {"type": "piv", "v": 1, "slot": slot, "alg": 0x11, "sk": sk or (b"\x11" * 32), "pin_policy": 2}
    obj.update(kw)
    return obj


def test_export_restore_ec_roundtrip(piv, store, prov):
    mgmt_auth(piv)
    generate(piv, 0x9C)
    put_data(piv, consts.OBJ_CERT_9C, cert_object(b"\x30\x03\x02\x01\x07"))
    ids = prov.list_identities()
    assert ids == [(storage.slot_uid(0x9C), "PIV 9C Digital Signature")]
    obj = prov.export_identity(ids[0][0])
    assert set(obj) == {"type", "v", "slot", "alg", "sk", "pin_policy", "cert", "certinfo"}
    registry.check_item_common(obj, "piv")
    prov.validate(obj)
    cbor.decode(cbor.encode(obj), canonical=True)
    label, fp = prov.describe(obj)
    assert fp == store.get_slot(0x9C).fingerprint()
    registry.check_fingerprint(fp)
    registry.check_label(label)

    original = store.get_slot(0x9C)
    store.wipe()
    assert not prov.exists(obj)
    uid = prov.restore_identity(obj, overwrite=False)
    assert uid == storage.slot_uid(0x9C)
    d = store.get_slot(0x9C)
    assert (d.sk, d.pub, d.cert, d.pin_policy) == (original.sk, original.pub, original.cert, 3)
    assert d.origin == consts.ORIGIN_IMPORTED


def test_restore_rsa_and_fingerprint(store, prov, rsa_private_key):
    nums = rsa_private_key.private_numbers()
    obj = {
        "type": "piv",
        "v": 1,
        "slot": 0x9D,
        "alg": 0x07,
        "p": nums.p.to_bytes(128, "big"),
        "q": nums.q.to_bytes(128, "big"),
        "e": 65537,
        "pin_policy": 2,
    }
    der = rsa_private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    assert prov.describe(obj)[1] == hashlib.sha256(der).digest()[:8].hex().upper()
    prov.restore_identity(obj, overwrite=False)
    assert prov.export_identity(storage.slot_uid(0x9D)) == obj


def test_exists_and_overwrite(store, prov):
    prov.restore_identity(ec_obj(), overwrite=False)
    other = ec_obj(sk=b"\x22" * 32)
    assert prov.exists(other)
    with pytest.raises(PolicyDenied):
        prov.restore_identity(other, overwrite=False)
    assert store.get_slot(0x9A).sk == b"\x11" * 32
    prov.restore_identity(other, overwrite=True)
    assert store.get_slot(0x9A).sk == b"\x22" * 32


def test_cert_only_slot_counts_as_existing_but_not_listed(piv, store, prov):
    mgmt_auth(piv)
    put_data(piv, consts.OBJ_CERT_9A, cert_object(b"\x30\x00"))
    assert prov.list_identities() == []
    assert prov.exists(ec_obj())


@pytest.mark.parametrize(
    "mutate",
    [
        lambda o: o.update(type="otp"),
        lambda o: o.update(v=2),
        lambda o: o.update(v=True),
        lambda o: o.update(slot=0x9B),
        lambda o: o.update(alg=0x14),
        lambda o: o.update(sk=b"\x00" * 32),  # scalar 0
        lambda o: o.update(sk=b"\xff" * 32),  # >= n
        lambda o: o.update(sk=b"\x11" * 31),
        lambda o: o.update(pin_policy=4),
        lambda o: o.update(pin_policy=1),  # weaker than 9A default
        lambda o: o.update(extra=1),
        lambda o: o.pop("pin_policy"),
        lambda o: o.update(cert=b"\x30\x00"),  # certinfo missing
        lambda o: o.update(cert=b"", certinfo=0),
        lambda o: o.update(cert=bytes(2049), certinfo=0),
        lambda o: o.update(cert=b"\x30\x00", certinfo=2),
        lambda o: o.update(p=bytes(128)),  # RSA field on an EC item
    ],
)
def test_validation_rejects(prov, mutate):
    obj = ec_obj()
    mutate(obj)
    with pytest.raises(InvalidInput):
        prov.validate(obj)
    with pytest.raises(InvalidInput):
        prov.restore_identity(obj, overwrite=True)


@pytest.mark.parametrize("bad", ["equal", "even", "small", "e"])
def test_rsa_validation(prov, rsa_private_key, bad):
    nums = rsa_private_key.private_numbers()
    p, q, e = nums.p, nums.q, 65537
    if bad == "equal":
        q = p
    elif bad == "even":
        p += 1
    elif bad == "small":
        p >>= 1
    elif bad == "e":
        e = 3
    obj = {
        "type": "piv",
        "v": 1,
        "slot": 0x9A,
        "alg": 0x07,
        "p": p.to_bytes(128, "big"),
        "q": q.to_bytes(128, "big"),
        "e": e,
        "pin_policy": 2,
    }
    with pytest.raises(InvalidInput):
        prov.validate(obj)


def test_unknown_uid(prov):
    for uid in (b"x", storage.slot_uid(0x9A), b"PIVslot\x9b", b"PIVdata\x00"):
        with pytest.raises(NotFound):
            prov.export_identity(uid)


def test_restore_is_atomic_under_power_loss(store, prov):
    prov.restore_identity(ec_obj(), overwrite=False)
    new = ec_obj(sk=b"\x33" * 32)
    for crash_at in range(3):
        testing.KV.crash_after_ops = testing.KV.ops + crash_at
        with contextlib.suppress(testing.PowerLoss):
            prov.restore_identity(new, overwrite=True)
        testing.KV.crash_after_ops = None
        fresh = storage.PivStore()
        fresh.load()
        assert fresh.get_slot(0x9A).sk in (b"\x11" * 32, b"\x33" * 32)


def test_registers_with_backup_registry(store):
    registry.clear()
    try:
        p = provider.PivBackupProvider(store)
        registry.register(p)
        assert registry.get("piv") is p
    finally:
        registry.clear()
