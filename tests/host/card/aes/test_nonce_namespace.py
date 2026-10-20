# SPDX-License-Identifier: GPL-3.0-only
"""Counter epochs widen clone separation without changing v1 ciphertexts."""

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from feuristic.apps.card.aes import keys
from feuristic.apps.card.aes.applet import AesApplet
from feuristic.apps.card.aes.provider import AesBackupProvider
from feuristic.core.errors import StorageFull
from feuristic.platform import testing

from .aesutil import decipher, encipher, mse, split
from .conftest import MS


def test_epoch_boundary_never_wraps_index_in_one_namespace(store, key1):
    store.raise_nonce_floor(2**32 - 2)
    nonces = [store.allocate_nonce(MS, key1) for _ in range(4)]
    assert [int.from_bytes(n[8:], "big") for n in nonces] == [2**32 - 2, 2**32 - 1, 0, 1]
    assert nonces[0][:8] == nonces[1][:8]
    assert nonces[2][:8] == nonces[3][:8] != nonces[1][:8]
    assert len(set(nonces)) == 4
    assert len(store._namespace_cache) == 1 and store._namespace_cache[key1.uid][0] == 1
    # Restart skips the rest of the persisted reservation across this boundary.
    rebooted = keys.AesKeyStore()
    rebooted.load()
    after = rebooted.allocate_nonce(MS, rebooted.get(key1.kid))
    assert after not in nonces and after[:8] == nonces[2][:8]
    assert int.from_bytes(after[8:], "big") >= 2


def test_restored_high_floor_selects_epoch_and_counter_exhaustion_is_closed(store, key1):
    store.raise_nonce_floor(2**32 + 1234)
    nonce = store.allocate_nonce(MS, key1)
    assert nonce[:8] == store.nonce_namespace(MS, key1.uid, 1)
    assert int.from_bytes(nonce[8:], "big") == 1234
    store.raise_nonce_floor(2**64 - 257)
    values = [store.allocate_nonce(MS, key1) for _ in range(256)]
    assert len(set(values)) == 256
    assert int.from_bytes(values[-1][8:], "big") == 2**32 - 2
    assert store.nonce_floor() == 2**64 - 1
    with pytest.raises(StorageFull):
        store.allocate_nonce(MS, key1)
    rebooted = keys.AesKeyStore()
    with pytest.raises(StorageFull):
        rebooted.allocate_nonce(MS, rebooted.get(key1.kid))


def test_legacy_ciphertext_and_repeated_old_backup_remain_usable(store, key1, ui, service):
    # The old construction is input data, not a patched encryption function.
    nonce = store.nonce_prefix(MS, key1.uid) + (42).to_bytes(8, "big")
    aad, plaintext = b"legacy v1", b"must survive nonce migration"
    sealed = AESGCM(key1.key).encrypt(nonce, plaintext, aad)
    store.raise_nonce_floor(256)
    item = AesBackupProvider(store).export_identity(b"AESkey\x00\x01")
    testing.KV.reset()
    fresh = keys.AesKeyStore()
    provider = AesBackupProvider(fresh)
    provider.restore_identity(item, False)
    app = AesApplet(ui, store=fresh, master_secret=b"n" * 32, rng=service)
    assert mse(app, 1, 0xF1).sw == 0x9000
    assert decipher(app, nonce, sealed[:-16], sealed[-16:], aad).data == plaintext
    first = split(encipher(app, b"new format"))[0]
    assert first[:8] == fresh.nonce_namespace(b"n" * 32, fresh.get(1).uid, 0)
    assert int.from_bytes(first[8:], "big") == 256
    floor = fresh.nonce_floor()
    provider.restore_identity(item, True)  # old backup must not rewind a live key
    assert fresh.nonce_floor() == floor
    assert mse(app, 1, 0xF1).sw == 0x9000
    second = split(encipher(app, b"after restore"))[0]
    assert second != first and int.from_bytes(second[8:], "big") >= floor
    assert decipher(app, nonce, sealed[:-16], sealed[-16:], aad).data == plaintext


def test_clones_and_counter_epochs_have_distinct_namespaces(store, key1):
    other = keys.AesKeyStore()
    a = store.nonce_namespace(MS, key1.uid, 0)
    b = other.nonce_namespace(b"n" * 32, key1.uid, 0)
    c = store.nonce_namespace(MS, key1.uid, 1)
    assert len(a) == len(b) == len(c) == 8
    assert len({a, b, c}) == 3
    assert len(store._namespace_cache) == 1


def test_namespace_cache_drops_deleted_keys_and_wipe_keeps_counter_floor(store, key1):
    second = store.put_restored(2, b"s" * 32, "second", True, 0)
    store.allocate_nonce(MS, key1)
    store.allocate_nonce(MS, second)
    assert len(store._namespace_cache) == 2
    floor = store.nonce_floor()
    assert store.delete(key1.kid)
    assert key1.uid not in store._namespace_cache and second.uid in store._namespace_cache
    store.wipe()
    assert not store._namespace_cache and store.nonce_floor() == floor
