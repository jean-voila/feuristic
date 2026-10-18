# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""AES key store and on-device management."""

import contextlib
import os

import pytest

from feuristic.apps.card.aes import keys, localmgmt
from feuristic.core import cbor, i18n, namespaces
from feuristic.core.errors import InvalidInput, NotFound, StorageFull, UserCancelled
from feuristic.core.interaction import DANGER, ScriptedInteraction
from feuristic.platform import testing

from ...aio import run


def test_create_and_list(store, service):
    info = localmgmt.create_key("mail", store=store, rng=service.health.random_bytes)
    assert (info.kid, info.name, info.enabled, info.policy) == (1, "mail", True, 0)
    assert info.policy_key == "aes.policy.every"
    assert len(info.fingerprint) == 16
    localmgmt.create_key("disk", keys.POLICY_SESSION, store=store, rng=os.urandom)
    assert [k.name for k in localmgmt.list_keys(store)] == ["mail", "disk"]
    assert localmgmt.key_info(2, store).policy_key == "aes.policy.session"
    assert localmgmt.free_ids(store) == list(range(3, 17))


def test_keys_are_random_and_never_listed(store):
    a = store.create("a", rng=os.urandom)
    b = store.create("b", rng=os.urandom)
    assert a.key != b.key and len(a.key) == 32
    assert "key" not in vars(localmgmt.key_info(1, store))
    assert a.key.hex() not in repr(a)


def test_explicit_id_and_capacity(store):
    store.create("x", kid=16, rng=os.urandom)
    with pytest.raises(InvalidInput):
        store.create("y", kid=16, rng=os.urandom)
    for i in range(15):
        store.create(f"k{i}", rng=os.urandom)
    assert len(store.entries()) == 16
    with pytest.raises(StorageFull):
        store.create("full", rng=os.urandom)


@pytest.mark.parametrize("name", ["", "x" * 17, "tab\t", "é", 5, None])
def test_name_validation(store, name):
    with pytest.raises(InvalidInput):
        store.create(name, rng=os.urandom)


@pytest.mark.parametrize("kid", [0, 17, -1, True, "1"])
def test_kid_validation(store, kid):
    with pytest.raises(InvalidInput):
        store.create("n", kid=kid, rng=os.urandom)


def test_rename_disable_policy(store):
    k = store.create("old", rng=os.urandom)
    localmgmt.rename_key(k.kid, "new name", store)
    localmgmt.set_enabled(k.kid, False, store)
    localmgmt.set_policy(k.kid, keys.POLICY_SESSION, store)
    fresh = keys.AesKeyStore()
    got = fresh.get(k.kid)
    assert (got.name, got.enabled, got.policy, got.key, got.uid) == ("new name", False, 1, k.key, k.uid)
    with pytest.raises(NotFound):
        store.rename(9, "x")
    with pytest.raises(InvalidInput):
        store.set_policy(k.kid, 2)


def test_delete_with_confirmation(store):
    k = store.create("victim", rng=os.urandom)
    with pytest.raises(UserCancelled):
        run(localmgmt.delete_key(k.kid, ScriptedInteraction(default=False), store))
    assert store.get(k.kid) is not None
    ui = ScriptedInteraction()
    assert run(localmgmt.delete_key(k.kid, ui, store))
    p = ui.prompts[-1]
    assert (p.kind, p.severity) == ("aes.delete", DANGER)
    assert dict(p.fields)["aes.field.key"] == "#1 victim"
    assert not run(localmgmt.delete_key(k.kid, ui, store))


def test_delete_all(store):
    store.create("a", rng=os.urandom)
    store.create("b", rng=os.urandom)
    with pytest.raises(UserCancelled):
        run(localmgmt.delete_all(ScriptedInteraction(default=False), store))
    run(localmgmt.delete_all(ScriptedInteraction(), store))
    assert store.entries() == []


def test_record_size_and_key_range(store):
    for _ in range(16):
        store.create("n" * 16, rng=os.urandom)
    card = [(k, v) for (app, k), v in testing.KV.data.items() if app == namespaces.CARD]
    assert all(0x40 <= k <= 0x50 for k, _ in card)
    assert max(len(v) for _, v in card) <= 16 + keys.MAX_PAYLOAD
    assert store.store.key_range() == (0x40, 0x50)


def test_corrupt_record_skipped(store):
    k = store.create("good", rng=os.urandom)
    store.store.put(b"\x01" * 8, cbor.encode({0: 1, 1: 2, 2: b"short", 3: "bad", 4: True, 5: 0}))
    assert [x.kid for x in store.entries()] == [k.kid]
    assert store.corrupt_uids == [b"\x01" * 8]


def test_update_atomic_under_power_loss(store):
    k = store.create("before", rng=os.urandom)
    for crash_at in range(3):
        testing.KV.crash_after_ops = testing.KV.ops + crash_at
        with contextlib.suppress(testing.PowerLoss):
            store.rename(k.kid, "after")
        testing.KV.crash_after_ops = None
        fresh = keys.AesKeyStore()
        fresh.load()
        assert [x.name for x in fresh.entries()] in (["before"], ["after"])
        store = fresh
        store.rename(k.kid, "before")


def test_epoch_changes(store):
    e = store.epoch
    k = store.create("x", rng=os.urandom)
    store.set_enabled(k.kid, False)
    store.delete(k.kid)
    store.wipe()
    assert store.epoch == e + 4


def test_strings_complete():
    from feuristic.apps.card.aes import strings

    strings.register()
    for key, (en, fr) in strings.STRINGS.items():
        assert key.split(".")[0] in ("aes", "rng") and en and fr
    i18n.set_language(i18n.FR)
    try:
        assert i18n.t("rng.title") == "Aléa"
    finally:
        i18n.set_language(i18n.EN)
