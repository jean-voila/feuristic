# SPDX-License-Identifier: GPL-3.0-only
"""R14 software bridge: all real providers on each native model runtime.

This intentionally uses the emulator's encrypted norcow, native crypto, real
USB mode lifecycle and lazy provider factory. It does not prove photography,
physical hardware interoperability or MCU RAM fit (the harness has 20 MiB).
"""

import gc

from trezor import config, loop
from upytest import run, storage_setup, test

from feuristic.apps.backup import export, frames, provider, restore
from feuristic.apps.card import apdu
from feuristic.apps.card.aes import keys as aes_keys
from feuristic.apps.card.aes.applet import AesApplet
from feuristic.apps.card.openpgp import localmgmt
from feuristic.apps.card.openpgp import storage as pgp_storage
from feuristic.apps.card.openpgp.applet import OpenPgpApplet
from feuristic.apps.card.piv import consts as pc
from feuristic.apps.card.piv import storage as piv_storage
from feuristic.apps.card.piv.applet import PivApplet
from feuristic.apps.fido2.clientpin import PinProtocolV1
from feuristic.apps.fido2.context import NULL_CHANNEL
from feuristic.apps.fido2.credentials import ALG_EDDSA
from feuristic.apps.importer.session import DEVICE_MAX_BACKUPS, DEVICE_MAX_BYTES, DUPLICATE, ImportSession
from feuristic.apps.otp import hotp
from feuristic.apps.otp.accounts import OtpAccounts
from feuristic.apps.otp.uri import OtpParams
from feuristic.core import cbor, tlv
from feuristic.core.interaction import ScriptedInteraction
from feuristic.fw import backup_providers, device, session, transports, usbmodes
from feuristic.platform import crypto

# Public, disposable RSA-2048 test fixture; never use these primes as real keys.
P = bytes.fromhex(
    "c586f684312e83c9828b98090cb16fc2c37898c96ad2155343c2b2d64c7ccc0f06f8e"
    "c58967324f77bc72c42c820e5ddfa09413f691775c0b363a327b356162dcca496549f"
    "2abd5aec2d6c4d3139c83ef15aabb69d59371c21f3f9a1d2258582eaee28c5344eec"
    "08591411f73a8718641649b02cdd560e866739cab075c88397"
)
Q = bytes.fromhex(
    "be2f45a77de30de5ffce0a6c232d71444e74e555db71b60a4662a5ed5edf72f68e086"
    "f51aa59941c757afb21c65741234ef6f376fddbb4bb954c4024755e21a8f8a45a99ad"
    "8cae0a4b6ccee0dd7003ac96db83e59f7cfaee2257e38efd8f9eba8420cd503747a17"
    "12ee9c88add90698a609f492de85fe3e029b9cd36e3083c99"
)
CERT = bytes.fromhex(
    "308202c9308201b1a00302010202010e300d06092a864886f70d01010b050030283126302406035504030c1d46657572"
    "6973746963207075626c696320746573742066697874757265301e170d3236303130313030303030305a170d33363031"
    "30313030303030305a30283126302406035504030c1d466575726973746963207075626c696320746573742066697874"
    "75726530820122300d06092a864886f70d01010105000382010f003082010a028201010092bea47bfb64169bd49ad2a5"
    "c6ec43f74aa3de0a45bdc233229d5fa0238b5f16949b012d6b2c171b81240b74e0efe0d79ac0db1c7e537076c405f320"
    "3f7df69e2c43844472655e3aa4f7219323b67af9c9c26d394565973b7f7d4fde73a13c408a081cfedbf58efe55eb85fb"
    "9bb34a5ca1a12109a8588abfb932a905fae1c80eebad223fae7763238fcfd44f98d0df006108f34ae98055a5534162c2"
    "e34783d6b8fe73aa508d9e8da0e53c929c9e2dc7f07ab88713afacca6a1fbe8646f37493df4bf2d0d6f1c686fe56e93b"
    "f3cb307c14d3ecc107374d6abc96509fd98aa20628f138a9bc1b426e65b21f8d542a9ff07084038b689efab2bbcaa6de"
    "6566093f0203010001300d06092a864886f70d01010b05000382010100619cbdc2dff149d78b3b67554fb1fa2d0eb304"
    "8af472b5f047a2e346b9fa59fc88ecea176bcaa4f54c1e17969f5f3a1aaab851d31cb321449fabada02fc0786ce10103"
    "4c36c36a77303f7f4a851ed6ce58ed314b47fde0c6660f35a4a3b340d269db26b1769d612230186aa94201dda4f13575"
    "36888b4cf8a0f52d30448a3abc45718b06359d7a2c2899f57894c9996d4a2f5b6f212fdb09157bdedc015f08085b65f8"
    "324b5fc6acfb7ddd92d9cdbd41ca7ad95e47eb6466e34e8b2e5a58a012b7690decd1bf9bfe7bc1a68cb2c78ffc29cad7"
    "29248e3f2efd7853ead5856b59883e5de50052997ff2c4dcadd4db9a862d10f1fd6e75534128c0c1c5a8083663"
)
MESSAGE = b"native backup provider use"


class Interaction(ScriptedInteraction):
    def cancel(self):
        pass


UI = Interaction()


def drive(coro):
    try:
        while True:
            coro.send(None)
    except StopIteration as exc:
        return exc.value


def switch(mode):
    errors = []

    async def transition():
        try:
            await usbmodes.switch(mode)
        except BaseException as exc:
            errors.append(exc)

    loop.schedule(transition())
    loop.run()
    if errors:
        raise errors[0]
    assert usbmodes.current() == mode


def tx(applet, ins, p1=0, p2=0, data=b"", ne=0):
    response = drive(applet.process(apdu.parse(apdu.build(0, ins, p1, p2, data, ne))))
    assert response.sw == 0x9000, hex(response.sw)
    return response.data


def aes_applet():
    applet = AesApplet(UI, master_secret=device.master_secret())
    tx(applet, 0x22, 0xF1, 0xB8, tlv.build(0x80, b"\x47") + tlv.build(0x83, b"\x03"))
    return applet


def aes_encrypt(applet):
    return dict(tlv.parse(tx(applet, 0x2A, 0x84, 0x80, tlv.build(0x80, MESSAGE), 256)))


def fido_use(auth, cred):
    # Both UV domains and two salts exercise the actual hmac-secret output
    # encryption path. Credential selection/PIN protocol are tested separately.
    proto, shared, salts = PinProtocolV1(), b"h" * 32, b"a" * 32 + b"b" * 32
    outputs = []
    for uv in (False, True):
        result = auth._assertion(cred, b"d" * 32, cred.rp_id_hash, True, uv, (proto, shared, salts), True)
        assert crypto.ed25519_verify(cred.public_key(), result[3], result[2] + b"d" * 32)
        extensions = cbor.decode(result[2][37:])
        plaintext = proto.decrypt(shared, extensions["hmac-secret"])
        expected = crypto.hmac_sha256(cred.cred_random(uv), salts[:32])
        expected += crypto.hmac_sha256(cred.cred_random(uv), salts[32:])
        assert plaintext == expected
        assert result[7] == cred.large_blob_key()
        outputs.append(plaintext)
    assert outputs[0] != outputs[1]
    return outputs


def seed():
    otp = OtpAccounts()
    otp_uid = otp.add(OtpParams("hotp", "R14", "native", b"12345678901234567890", "SHA256", 8, counter=40))
    assert drive(otp.generate_hotp(otp_uid, UI)) == hotp.hotp(b"12345678901234567890", 40, 8, "SHA256")

    pgp = pgp_storage.default()
    drive(localmgmt.generate_keys(pgp, localmgmt.PROFILE_25519, 1_800_000_000))
    pgp.ident.name = b"Native R14"
    pgp.ident.cert = CERT
    pgp.ident.private[1] = b"private metadata"
    pgp.dsc.advance_to(17)
    pgp.save(aux_changed=True)
    pgp_public = [slot.public() for slot in pgp.ident.keys]

    piv = backup_providers.create("piv")
    piv.restore_identity(
        {
            "type": "piv",
            "v": 1,
            "slot": pc.SLOT_SIGN,
            "alg": pc.ALG_RSA2048,
            "p": P,
            "q": Q,
            "e": 65537,
            "pin_policy": pc.PIN_POLICY_ALWAYS,
            "cert": CERT,
            "certinfo": 0,
        },
        False,
    )
    rsa_n = piv_storage.default().get_slot(pc.SLOT_SIGN).rsa_key().n

    aes = aes_keys.default()
    aes.put_restored(3, b"k" * 32, "native", True, aes_keys.POLICY_SESSION)
    ciphertext = aes_encrypt(aes_applet())
    nonce_floor = aes.nonce_floor()

    auth = transports.fido_server().app.auth
    cred = auth.store.create_resident(
        "native.example", b"user", "native", "Native R14", ALG_EDDSA, b"f" * 32, 2, True, True
    )
    hmac_outputs = fido_use(auth, cred)
    auth.state.raise_signature_counter(73)
    # Raw DEFLATE of b"native blob", generated once with zlib wbits=-15.
    compressed = bytes.fromhex("cb4b2cc92c4b5548cac94f0200")
    blob_nonce, blob_plain = b"n" * 12, b"native blob"
    ct, tag = crypto.aes256_gcm_encrypt(
        cred.large_blob_key(), blob_nonce, compressed, b"blob" + len(blob_plain).to_bytes(8, "little")
    )
    auth.large_blobs.write_entries([{1: ct + tag, 2: blob_nonce, 3: len(blob_plain)}])
    return (
        otp_uid,
        pgp_public,
        rsa_n,
        ciphertext,
        nonce_floor,
        cred.uid,
        cred.cred_id,
        cred.public_key(),
        hmac_outputs,
        compressed,
    )


@test
def all_five_providers_survive_empty_storage_and_new_master_secret():
    old_ui = transports._ui
    transports._ui = UI
    exported = None
    streaming = None
    try:
        device.initialize()
        old_ms = device.master_secret()
        usbmodes.start_normal()
        session._load_stores()
        expected = seed()

        async def phrase(request):
            return bytearray(b"native provider bridge phrase")

        exported = drive(export.begin_full_export(UI, phrase, profile=frames.PROFILE_LARGE))
        assert len(exported) == 5
        raw_envelopes = []
        for index in range(len(exported)):
            backup = exported.build(index)
            collector = ImportSession(DEVICE_MAX_BACKUPS, DEVICE_MAX_BYTES, compact=True)
            # Real frame parser/reassembly, reverse order, exact duplicate.
            for text in reversed(backup.frames):
                assert collector.add_payload(text.encode()).accepted
            assert collector.add_payload(backup.frames[0].encode()).status == DUPLICATE
            raw_envelopes.append(collector.take_complete())
            collector.abort()
        exported.close()
        exported = None
        assert transports.fido_server().app.auth.store.get(expected[5]).backup_state

        switch(usbmodes.IMPORT)
        session.release_import_stores()
        assert transports._fido is None and transports._card is None
        config.wipe()
        storage_setup()
        device.forget_master_secret()
        device.initialize()
        assert device.master_secret() != old_ms
        session._load_stores()
        for prov in provider.all():
            assert not prov.list_identities(), prov.TYPE
        stored = backup_providers.create("fido2")
        assert isinstance(stored.auth, backup_providers._StoredFido)
        stored = None
        streaming = restore.StreamingRestore(UI, phrase)
        for index, raw in enumerate(raw_envelopes):
            report = drive(streaming.restore_envelope(raw))
            assert report.failed is None and len(report.restored) == index + 1
            session.release_import_stores()
            gc.collect()
        assert streaming.incomplete_sets() == []
        streaming.close()
        streaming = None
        raw_envelopes = None

        switch(usbmodes.NORMAL)  # real reload_stores() and transport resume
        otp_uid, pgp_public, rsa_n, ciphertext, floor, fuid, cid, pub, hs, compressed = expected
        otp = OtpAccounts()
        restored_accounts = otp.accounts()
        assert len(restored_accounts) == 1
        assert (restored_accounts[0].issuer, restored_accounts[0].account) == ("R14", "native")
        otp_uid = restored_accounts[0].uid  # OTP record IDs are local to the device.
        assert otp.hotp_counter(otp_uid) == 41
        assert drive(otp.generate_hotp(otp_uid, UI)) == hotp.hotp(b"12345678901234567890", 41, 8, "SHA256")
        assert otp.hotp_counter(otp_uid) == 42

        # All three OpenPGP roles are usable through real APDUs after reload.
        pgp = OpenPgpApplet(UI, device.master_secret())
        assert [key.public() for key in pgp.store.ident.keys] == pgp_public
        assert pgp.store.signature_count() == 17
        assert tx(pgp, 0xCA, 0x7F, 0x21, ne=65536) == CERT
        assert tx(pgp, 0xCA, 1, 2, ne=256) == b"private metadata"
        tx(pgp, 0x20, 0, 0x81, b"123456")
        sig = tx(pgp, 0x2A, 0x9E, 0x9A, MESSAGE, 256)
        assert crypto.ed25519_verify(pgp_public[0], sig, MESSAGE)
        assert pgp.store.signature_count() == 18
        tx(pgp, 0x20, 0, 0x82, b"123456")
        sig = tx(pgp, 0x88, data=MESSAGE, ne=256)
        assert crypto.ed25519_verify(pgp_public[2], sig, MESSAGE)
        peer = b"p" * 32
        point = crypto.x25519_public(peer)
        challenge = tlv.build(0xA6, tlv.build(0x7F49, tlv.build(0x86, point)))
        shared = tx(pgp, 0x2A, 0x80, 0x86, challenge, 256)
        assert shared == crypto.x25519(peer, pgp_public[1])

        piv = PivApplet(UI, master_secret=device.master_secret())
        assert piv.store.get_slot(pc.SLOT_SIGN).cert == CERT
        cert_object = tx(piv, 0xCB, 0x3F, 0xFF, tlv.build(0x5C, pc.OBJ_CERT_9C.to_bytes(3, "big")), 65536)
        assert tlv.find(tlv.find(cert_object, 0x53), 0x70) == CERT
        tx(piv, 0x20, 0, 0x80, piv_storage.pad_pin(b"123456"))
        block = b"\x00\x01" + b"\xff" * 221 + b"\x00" + crypto.sha256(MESSAGE)
        challenge = tlv.build(0x7C, tlv.build(0x82, b"") + tlv.build(0x81, block))
        signature = tlv.find(
            tlv.find(tx(piv, 0x87, pc.ALG_RSA2048, pc.SLOT_SIGN, challenge, 256), 0x7C), 0x82
        )
        assert crypto.rsa_public(rsa_n, 65537, signature) == block

        aes = aes_applet()
        data = (
            tlv.build(0x82, ciphertext[0x82])
            + tlv.build(0x80, ciphertext[0x80])
            + tlv.build(0x83, ciphertext[0x83])
        )
        assert tx(aes, 0x2A, 0x80, 0x84, data, 256) == MESSAGE
        new_ct = aes_encrypt(aes)
        assert int.from_bytes(new_ct[0x82][8:], "big") >= floor
        assert new_ct[0x82] != ciphertext[0x82]
        assert crypto.aes256_gcm_decrypt(b"k" * 32, new_ct[0x82], new_ct[0x80], new_ct[0x83]) == MESSAGE

        live = transports.fido_server().app.auth
        assert backup_providers.create("fido2").auth is live
        cred = live.store.get(fuid)
        assert cred.cred_id == cid and cred.public_key() == pub and cred.backup_state
        assert live.state.signature_counter() >= 73
        assert fido_use(live, cred) == hs
        assertion = drive(
            live.get_assertion(
                {1: "native.example", 2: b"d" * 32, 3: [{"type": "public-key", "id": cid}]}, NULL_CHANNEL
            )
        )
        assert assertion[1]["id"] == cid
        assert assertion[2][32] & 0x18 == 0x18  # BE=BS=1
        assert int.from_bytes(assertion[2][33:37], "big") > 73
        assert crypto.ed25519_verify(pub, assertion[3], assertion[2] + b"d" * 32)
        entry = live.large_blobs.entries()[0]
        assert (
            crypto.aes256_gcm_decrypt(
                cred.large_blob_key(),
                entry[2],
                entry[1][:-16],
                entry[1][-16:],
                b"blob" + entry[3].to_bytes(8, "little"),
            )
            == compressed
        )
        print("R14 native providers: HOTP, OpenPGP3roles, PIVRSA/cert, AESnonce, FIDO/hmac/blob OK")
    except Exception as exc:
        import sys

        sys.print_exception(exc)
        raise
    finally:
        if exported is not None:
            exported.close()
        if streaming is not None:
            streaming.close()
        transports.on_lock()
        transports._ui = old_ui


storage_setup()
run()
