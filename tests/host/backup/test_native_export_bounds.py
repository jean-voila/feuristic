# SPDX-License-Identifier: GPL-3.0-only
"""Largest native identities must fit the hardware's one-identity collector.

Use real providers, persisted records, RSA keys and authenticated largeBlob
entries. This covers metadata/certificate extremes as well as private keys;
testing only an empty/default identity would miss the restoration RAM bound.
"""

import hashlib
import zlib

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from feuristic.apps.backup import envelope, frames
from feuristic.apps.card.aes import keys as aes_keys
from feuristic.apps.card.aes.provider import AesBackupProvider
from feuristic.apps.card.openpgp import const as pgp
from feuristic.apps.card.openpgp import localmgmt as pgp_mgmt
from feuristic.apps.card.openpgp import storage as pgp_storage
from feuristic.apps.card.openpgp.provider import UID, OpenPgpBackupProvider
from feuristic.apps.card.piv import consts as pc
from feuristic.apps.card.piv import storage as piv_storage
from feuristic.apps.card.piv.provider import PivBackupProvider
from feuristic.apps.fido2.context import Context
from feuristic.apps.fido2.ctap2 import Authenticator
from feuristic.apps.fido2.largeblobs import MAX_SERIALIZED, serialize
from feuristic.apps.fido2.provider import Fido2BackupProvider
from feuristic.apps.importer.session import DEVICE_MAX_BACKUPS, DEVICE_MAX_BYTES, ImportSession
from feuristic.apps.otp.accounts import OtpAccounts
from feuristic.apps.otp.provider import OtpBackupProvider
from feuristic.apps.otp.uri import OtpParams
from feuristic.platform import crypto

from ..aio import run


def openpgp():
    store = pgp_storage.IdentityStore()
    store.load()
    run(pgp_mgmt.generate_keys(store, pgp_mgmt.PROFILE_RSA2048, 0xFFFFFFFF))
    ident = store.ident
    ident.name = b"N" * pgp.MAX_NAME
    ident.lang = b"enfrdeen"
    ident.sex = b"9"
    ident.url = b"u" * pgp.MAX_SPECIAL_DO
    ident.login = b"l" * pgp.MAX_SPECIAL_DO
    ident.private = [bytes((i,)) * pgp.MAX_SPECIAL_DO for i in range(4)]
    ident.cert = b"c" * pgp.MAX_CERT
    ident.pins = [pgp_storage.PinRef(1_000_000, b"s" * 16, b"h" * 32, pgp.PW_MAX) for _ in range(3)]
    for key in ident.keys:
        key.ca_fpr = b"f" * 20
    store.dsc.advance_to(0xFFFFFF)
    store.save(aux_changed=True)
    return OpenPgpBackupProvider(store), UID


def piv():
    store = piv_storage.PivStore()
    store.load()
    prov = PivBackupProvider(store)
    numbers = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_numbers()
    uid = prov.restore_identity(
        {
            "type": "piv",
            "v": 1,
            "slot": pc.SLOT_SIGN,
            "alg": pc.ALG_RSA2048,
            "p": numbers.p.to_bytes(128, "big"),
            "q": numbers.q.to_bytes(128, "big"),
            "e": 65537,
            "pin_policy": pc.PIN_POLICY_ALWAYS,
            "cert": b"c" * pc.MAX_CERT_LEN,
            "certinfo": 1,
        },
        False,
    )
    return prov, uid


def fido2(blob_count=1):
    auth = Authenticator(Context(b"m" * 32, None))
    cred = auth.store.create_resident(
        "a" * 128, b"u" * 64, "n" * 64, "d" * 64, -7, (1).to_bytes(32, "big"), 3, True, True
    )
    # Valid raw-DEFLATE data, deliberately incompressible, with authentic
    # AES-GCM binding to this credential's largeBlobKey.
    data = b"".join(hashlib.sha256(i.to_bytes(2, "big")).digest() for i in range(128))

    def entry(value, index):
        plaintext = zlib.compress(value, wbits=-15)
        nonce = index.to_bytes(12, "big")
        ct, tag = crypto.aes256_gcm_encrypt(
            cred.large_blob_key(), nonce, plaintext, b"blob" + len(value).to_bytes(8, "little")
        )
        return {1: ct + tag, 2: nonce, 3: len(value)}

    prefix = [entry(b"", i) for i in range(blob_count - 1)]
    remaining = MAX_SERIALIZED - len(serialize(prefix))
    for size in range(remaining, 0, -1):
        entries = prefix + [entry(data[:size], blob_count)]
        if len(serialize(entries)) <= MAX_SERIALIZED:
            break
    assert 4090 <= len(serialize(entries)) <= MAX_SERIALIZED
    auth.large_blobs.write_entries(entries)
    auth.state.raise_signature_counter(0xFFFFFFFF)
    prov = Fido2BackupProvider(auth)
    assert prov.export_identity(cred.uid)["large_blobs"]
    return prov, cred.uid


def fido2_many_blobs():
    # Each associated entry gets its own byte-string wrapper in the backup.
    # A full array of small entries has more overhead than one large entry.
    return fido2(blob_count=64)


def otp():
    accounts = OtpAccounts()
    accounts.load()
    uid = accounts.add(OtpParams("hotp", "i" * 32, "a" * 64, b"s" * 64, "SHA512", 8, counter=2**64 - 1))
    return OtpBackupProvider(accounts), uid


def aes():
    store = aes_keys.AesKeyStore()
    store.load()
    store.put_restored(16, b"k" * 32, "n" * aes_keys.NAME_MAX, True, aes_keys.POLICY_SESSION)
    store.raise_nonce_floor(2**64 - 1)
    return AesBackupProvider(store), b"AESkey\x00\x10"


@pytest.mark.parametrize(
    "make_identity", [openpgp, piv, fido2, fido2_many_blobs, otp, aes], ids=lambda fn: fn.__name__
)
def test_maximum_native_identity_round_trips_with_hardware_collector(
    make_identity, record_testsuite_property
):
    prov, uid = make_identity()
    item = prov.export_identity(uid)
    prov.validate(item)
    key, salt = b"k" * 32, b"s" * 16
    raw = envelope.seal(key, salt, envelope.KIND_FULL, [item], seq=192, count=192, created=0xFFFFFFFF)
    record_testsuite_property("envelope_bytes_" + make_identity.__name__, len(raw))
    assert len(raw) <= DEVICE_MAX_BYTES
    for profile in ("large", "dense"):
        collector = ImportSession(max_backups=DEVICE_MAX_BACKUPS, max_bytes=DEVICE_MAX_BYTES, compact=True)
        texts = frames.split(raw, envelope.parse_header(raw).backup_id, profile)
        for text in reversed(texts):
            assert collector.add_payload(text.encode()).accepted
        restored = collector.take_complete()
        assert restored == raw and collector.bytes_used() == 0
        assert envelope.open_with_key(restored, key).items == [item]
