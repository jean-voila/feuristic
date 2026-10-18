# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""R04: exercise the shared 64 KiB budget through real application stores.

Use unmodified python-fido2 over CTAPHID, maximum-length metadata, live HOTP
counters and both A/B copies of a full largeBlob array. Rewriting data at
capacity matters: counting only the first writes hides copy-on-write costs.
The host KV model is conservative; the emulator test covers real norcow.
"""

import pytest
from ctap_harness import CDH, make, open_hid
from fido2.ctap import CtapError
from fido2.ctap2 import CredentialManagement, Ctap2
from fido2.ctap2.blob import LargeBlobs
from fido2.ctap2.pin import ClientPin, PinProtocolV2

from feuristic.apps.fido2 import credentials, largeblobs
from feuristic.apps.otp.accounts import OtpAccounts
from feuristic.apps.otp.uri import OtpParams
from feuristic.core.errors import StorageFull
from feuristic.core.interaction import ScriptedInteraction
from feuristic.platform import crypto

from ..aio import run

PERM = ClientPin.PERMISSION


@pytest.mark.parametrize("max_fields", [False, True], ids=["typical", "maximum-fields"])
def test_r04_shared_capacity(ctap2, device, kv, max_fields, record_property):
    proto = PinProtocolV2()
    client = ClientPin(ctap2, proto)
    client.set_pin("123456")
    rp = "capacity.example"
    if max_fields:
        rp = "a" * 63 + "." + "b" * 56 + ".example"
        assert len(rp) == credentials.MAX_RP_ID_LEN
    ids = []
    for i in range(100):
        token = client.get_pin_token("123456", PERM.MAKE_CREDENTIAL, rp)
        user_id = i.to_bytes(64 if max_fields else 8, "big")
        name = f"user-{i:03}".ljust(64 if max_fields else 16, "x")
        att = make(
            ctap2,
            rp={"id": rp},
            user={"id": user_id, "name": name, "displayName": name},
            rk=True,
            extensions={"hmac-secret": True, "largeBlobKey": True, "credProtect": 3},
            pin_uv_param=proto.authenticate(token, CDH),
            pin_uv_protocol=proto.VERSION,
        )
        ids.append(att.auth_data.credential_data.credential_id)
    assert device.auth.store.count() == 100

    otp = OtpAccounts()
    for i in range(32):
        issuer = "Issuer".ljust(32, "x") if max_fields else "Example"
        account = f"account-{i:02}".ljust(64, "x") if max_fields else f"user-{i}"
        uid = otp.add(OtpParams("hotp", issuer, account, b"s" * 64, "SHA512", 8, counter=1000))
        run(otp.generate_hotp(uid, ScriptedInteraction()))
    assert len(otp) == 32

    entries = [{1: b"x" * 4074}]
    assert len(largeblobs.serialize(entries)) == largeblobs.MAX_SERIALIZED
    token = client.get_pin_token("123456", PERM.LARGE_BLOB_WRITE)
    blobs = LargeBlobs(ctap2, proto, token)
    for value in (b"x", b"y", b"z"):
        entries = [{1: value * 4074}]
        blobs.write_blob_array(entries)
        assert blobs.read_blob_array() == entries

    # An update requires a new record before the old one can be deleted.
    first = device.auth.store.lookup_resident(ids[0])
    device.auth.store.update_user(first, first.user_name, first.display_name)
    old_otp = otp.accounts()[0]
    otp.rename(old_otp.uid, old_otp.issuer, old_otp.account)
    record_property("live_bytes", kv.used_bytes())
    record_property("sector_bytes", kv.SECTOR_BYTES)
    assert kv.used_bytes() + 1024 <= kv.SECTOR_BYTES  # reserve upstream/PIN/system metadata

    # Refusal at each advertised count limit must preserve all existing data.
    with pytest.raises(CtapError) as exc:
        make(
            ctap2,
            rp={"id": rp},
            user={"id": b"overflow", "name": "overflow"},
            rk=True,
            pin_uv_param=proto.authenticate(client.get_pin_token("123456", PERM.MAKE_CREDENTIAL, rp), CDH),
            pin_uv_protocol=proto.VERSION,
        )
    assert exc.value.code == CtapError.ERR.KEY_STORE_FULL
    with pytest.raises(StorageFull):
        otp.add(OtpParams("totp", "Extra", "extra", b"s" * 20))

    device.power_cycle()
    rebooted = Ctap2(open_hid(device))
    client = ClientPin(rebooted, proto)
    cm = CredentialManagement(rebooted, proto, client.get_pin_token("123456", PERM.CREDENTIAL_MGMT))
    assert cm.get_metadata() == {1: 100, 2: 0}
    assert len(cm.enumerate_creds(crypto.sha256(rp.encode()))) == 100
    assert LargeBlobs(rebooted).read_blob_array() == entries
    reloaded = OtpAccounts()
    assert len(reloaded.accounts()) == 32
    assert reloaded.hotp_counter(old_otp.uid) == 1001
