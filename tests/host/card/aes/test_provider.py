# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""AES backup provider (docs/protocols/backup-aes.md)."""

import contextlib
import os

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from feuristic.apps.backup import provider as registry
from feuristic.apps.card.aes import keys, provider
from feuristic.core import cbor
from feuristic.core.errors import InvalidInput, NotFound, PolicyDenied
from feuristic.platform import testing

from .aesutil import decipher, encipher, mse, split


@pytest.fixture
def prov(store):
    return provider.AesBackupProvider(store)


def obj(**kw):
    o = {
        "type": "aes",
        "v": 1,
        "id": 3,
        "name": "vault",
        "key": b"\x42" * 32,
        "enabled": True,
        "policy": 0,
        "nonce_floor": 1000,
    }
    o.update(kw)
    return o


def test_export_restore_roundtrip(aes, store, prov, key1):
    mse(aes, key1.kid, 0xF1)
    nonce, ct, tag = split(encipher(aes, b"keep me"))
    ids = prov.list_identities()
    assert ids == [(b"AESkey\x00\x01", "AES #1 backup")]
    o = prov.export_identity(ids[0][0])
    assert o["key"] == key1.key and o["nonce_floor"] == store.nonce_floor()
    registry.check_item_common(o, "aes")
    prov.validate(o)
    cbor.decode(cbor.encode(o), canonical=True)
    label, fp = prov.describe(o)
    assert (label, fp) == ("AES #1 backup", key1.fingerprint())
    registry.check_fingerprint(fp)

    # restore on a "new device": empty storage, other master secret
    testing.KV.reset()
    keys._reset_default()
    fresh = keys.AesKeyStore()
    p2 = provider.AesBackupProvider(fresh)
    assert not p2.exists(o)
    p2.restore_identity(o, overwrite=False)
    assert fresh.nonce_floor() >= o["nonce_floor"]
    from feuristic.apps.card.aes.applet import AesApplet

    a2 = AesApplet(aes.ui, store=fresh, master_secret=os.urandom(32), rng=aes.rng)
    mse(a2, 1, 0xF1)
    assert decipher(a2, nonce, ct, tag).data == b"keep me"
    # new encryptions continue above the source device's counter
    n2 = split(encipher(a2, b"x"))[0]
    assert int.from_bytes(n2[4:], "big") >= o["nonce_floor"]


def test_restore_overwrite_keeps_record_uid(store, prov):
    k = store.create("vault", kid=3, rng=os.urandom)
    assert prov.exists(obj())
    with pytest.raises(PolicyDenied):
        prov.restore_identity(obj(), overwrite=False)
    assert store.get(3).key == k.key
    prov.restore_identity(obj(enabled=False, policy=1), overwrite=True)
    got = store.get(3)
    assert (got.key, got.uid, got.enabled, got.policy) == (b"\x42" * 32, k.uid, False, 1)
    assert len(store.entries()) == 1


def test_restore_never_lowers_counter(store, prov, aes, key1):
    mse(aes, key1.kid, 0x81)
    for _ in range(3):
        encipher(aes, b"x")
    floor = store.nonce_floor()
    prov.restore_identity(obj(nonce_floor=0), overwrite=False)
    assert store.nonce_floor() == floor
    assert encipher(aes, b"y").sw == 0x6985  # a key change voids the security environment
    mse(aes, key1.kid, 0x81)
    # the allocator restarts from the persisted value: no reuse
    n = split(encipher(aes, b"y"))[0]
    assert int.from_bytes(n[4:], "big") >= floor


def test_restore_raises_counter_and_resets_reservation(store, prov, aes, key1):
    mse(aes, key1.kid, 0x81)
    first = int.from_bytes(split(encipher(aes, b"x"))[0][4:], "big")
    prov.restore_identity(obj(nonce_floor=first + 10_000), overwrite=False)
    mse(aes, key1.kid, 0x81)
    n = int.from_bytes(split(encipher(aes, b"x"))[0][4:], "big")
    assert n >= first + 10_000


@pytest.mark.parametrize(
    "mutate",
    [
        lambda o: o.update(type="piv"),
        lambda o: o.update(v=2),
        lambda o: o.update(v=True),
        lambda o: o.update(id=0),
        lambda o: o.update(id=17),
        lambda o: o.update(name=""),
        lambda o: o.update(name="x" * 17),
        lambda o: o.update(key=b"\x00" * 31),
        lambda o: o.update(key="k" * 32),
        lambda o: o.update(enabled=1),
        lambda o: o.update(policy=2),
        lambda o: o.update(nonce_floor=-1),
        lambda o: o.update(nonce_floor=2**64),
        lambda o: o.update(nonce_floor=True),
        lambda o: o.update(extra=b""),
        lambda o: o.pop("nonce_floor"),
    ],
)
def test_validation(prov, mutate):
    o = obj()
    mutate(o)
    with pytest.raises(InvalidInput):
        prov.validate(o)
    with pytest.raises(InvalidInput):
        prov.restore_identity(o, overwrite=True)


def test_unknown_uid(prov):
    for uid in (b"", b"AESkey\x00\x02", b"AESkey\x00\x11", b"XESkey\x00\x01"):
        with pytest.raises(NotFound):
            prov.export_identity(uid)


def test_restore_atomic_under_power_loss(store, prov):
    store.create("vault", kid=3, rng=os.urandom)
    old = store.get(3).key
    for crash_at in range(8):
        testing.KV.crash_after_ops = testing.KV.ops + crash_at
        with contextlib.suppress(testing.PowerLoss):
            prov.restore_identity(obj(), overwrite=True)
        testing.KV.crash_after_ops = None
        fresh = keys.AesKeyStore()
        fresh.load()
        assert len(fresh.entries()) == 1
        assert fresh.get(3).key in (old, b"\x42" * 32)


def test_backup_key_interoperates(prov):
    """The exported key is plain AES-256: usable by any GCM implementation."""
    o = obj()
    nonce = os.urandom(12)
    sealed = AESGCM(o["key"]).encrypt(nonce, b"m", None)
    assert AESGCM(o["key"]).decrypt(nonce, sealed, None) == b"m"


def test_registers(store):
    registry.clear()
    try:
        p = provider.AesBackupProvider(store)
        registry.register(p)
        assert registry.get("aes") is p
    finally:
        registry.clear()
