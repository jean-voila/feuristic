# SPDX-License-Identifier: GPL-3.0-only
"""Native legacy ciphertext recovery and 64-bit namespace epoch boundaries."""

from upytest import run, storage_setup, test

from feuristic.apps.card import apdu
from feuristic.apps.card.aes.applet import AesApplet
from feuristic.apps.card.aes.keys import AesKeyStore
from feuristic.apps.card.aes.provider import AesBackupProvider
from feuristic.core import tlv
from feuristic.core.interaction import ScriptedInteraction
from feuristic.platform import crypto


def drive(coro):
    try:
        while True:
            coro.send(None)
    except StopIteration as exc:
        return exc.value


def tx(app, ins, p1, p2, data):
    return drive(app.process(apdu.parse(apdu.build(0, ins, p1, p2, data, 65536))))


@test
def legacy_nonce_restore_new_master_epoch_rollover_and_exhaustion():
    key, plaintext = bytes(range(32)), b"legacy native ciphertext"
    source = AesKeyStore()
    original = source.put_restored(1, key, "legacy", True, 1)
    nonce = source.nonce_prefix(b"s" * 32, original.uid) + (42).to_bytes(8, "big")
    ct, tag = crypto.aes256_gcm_encrypt(key, nonce, plaintext)
    source.raise_nonce_floor(256)
    item = AesBackupProvider(source).export_identity(b"AESkey\x00\x01")
    source.wipe()
    fresh = AesKeyStore()  # a fresh store for the different master secret
    provider = AesBackupProvider(fresh)
    provider.restore_identity(item, False)
    app = AesApplet(ScriptedInteraction(), store=fresh, master_secret=b"d" * 32)
    mse = tlv.build(0x80, b"\x47") + tlv.build(0x83, b"\x01")
    assert tx(app, 0x22, 0xF1, 0xB8, mse).sw == 0x9000
    legacy = tlv.build(0x82, nonce) + tlv.build(0x80, ct) + tlv.build(0x83, tag)
    response = tx(app, 0x2A, 0x80, 0x84, legacy)
    assert response.sw == 0x9000 and response.data == plaintext

    def encrypt():
        response = tx(app, 0x2A, 0x84, 0x80, tlv.build(0x80, b"new"))
        assert response.sw == 0x9000
        fields = dict(tlv.parse(response.data))
        assert crypto.aes256_gcm_decrypt(key, fields[0x82], fields[0x80], fields[0x83]) == b"new"
        return fields[0x82]

    first = encrypt()
    assert int.from_bytes(first[8:], "big") == 256
    floor = fresh.nonce_floor()
    provider.restore_identity(item, True)
    assert tx(app, 0x22, 0xF1, 0xB8, mse).sw == 0x9000
    second = encrypt()
    assert second != first and int.from_bytes(second[8:], "big") >= floor
    fresh.raise_nonce_floor(2**32 - 2)
    crossing = [encrypt() for _ in range(4)]
    assert [int.from_bytes(n[8:], "big") for n in crossing] == [2**32 - 2, 2**32 - 1, 0, 1]
    assert crossing[0][:8] == crossing[1][:8] != crossing[2][:8] == crossing[3][:8]
    assert len(set(crossing)) == 4
    assert len(fresh._namespace_cache) == 1
    # Restore did not change the old ciphertext's decryption semantics.
    response = tx(app, 0x2A, 0x80, 0x84, legacy)
    assert response.sw == 0x9000 and response.data == plaintext
    fresh.raise_nonce_floor(2**64 - 1)
    response = tx(app, 0x2A, 0x84, 0x80, tlv.build(0x80, b"exhausted"))
    assert response.sw == 0x6A84 and response.data == b""


storage_setup()
run()
