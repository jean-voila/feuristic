# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""authenticatorReset, on-device management (localmgmt) and the backup provider."""

import pytest
from ctap_harness import CDH, MS, USER, Device, SimUI, aio_run, descriptor, make, open_hid, sha256
from fido2.ctap import CtapError
from fido2.ctap1 import ApduError, Ctap1
from fido2.ctap2 import Ctap2
from fido2.ctap2.blob import LargeBlobs
from fido2.ctap2.pin import ClientPin
from fido2.webauthn import AuthenticatorData

from feuristic.apps.backup import provider as bp
from feuristic.apps.fido2 import localmgmt, strings
from feuristic.apps.fido2.provider import Fido2BackupProvider
from feuristic.core import i18n
from feuristic.core.errors import InvalidInput, NotFound, PolicyDenied, StorageFull
from feuristic.core.interaction import DANGER

ERR = CtapError.ERR
F = AuthenticatorData.FLAG
RP_HASH = sha256(b"example.com")


# ---------------------------------------------------------------------------
# authenticatorReset
# ---------------------------------------------------------------------------


def test_reset_erases_everything(ctap2, device, ui, hid):
    rk = make(ctap2, rk=True, extensions={"largeBlobKey": True})
    nonrk = make(ctap2)
    LargeBlobs(ctap2).put_blob(rk.large_blob_key, b"data")
    u2f = Ctap1(hid)
    for _ in range(3):
        try:
            reg = u2f.register(CDH, RP_HASH)
            break
        except ApduError:
            pass
    ClientPin(ctap2).set_pin("1234")
    counter = nonrk.auth_data.counter
    ctap2.reset()
    assert ui.prompts[-1].kind == "fido2.reset" and ui.prompts[-1].severity == DANGER
    info = ctap2.get_info()
    assert info.options["clientPin"] is False and info.remaining_disc_creds == 100
    with pytest.raises(CtapError) as e:
        ctap2.get_assertion("example.com", CDH)
    assert e.value.code == ERR.NO_CREDENTIALS
    for att in (rk, nonrk):
        with pytest.raises(CtapError):
            ctap2.get_assertion("example.com", CDH, [descriptor(att)])
    with pytest.raises(ApduError) as e2:
        u2f.authenticate(CDH, RP_HASH, reg.key_handle, check_only=True)
    assert e2.value.code == 0x6A80
    assert LargeBlobs(ctap2).read_blob_array() == []
    assert make(ctap2).auth_data.counter > counter  # counter never goes back


def test_reset_window_and_denial(device, ui):
    ctap2 = Ctap2(open_hid(device))
    ui.push(False)
    with pytest.raises(CtapError) as e:
        ctap2.reset()
    assert e.value.code == ERR.OPERATION_DENIED
    ui.push("timeout")
    with pytest.raises(CtapError) as e:
        ctap2.reset()
    assert e.value.code == ERR.USER_ACTION_TIMEOUT
    device.advance(10_001)
    with pytest.raises(CtapError) as e:
        ctap2.reset()
    assert e.value.code == ERR.NOT_ALLOWED
    device.power_cycle()
    Ctap2(open_hid(device)).reset()


# ---------------------------------------------------------------------------
# localmgmt
# ---------------------------------------------------------------------------


def populate(ctap2):
    make(ctap2, rk=True, user={"id": b"1", "name": "zoe"}, extensions={"credProtect": 2})
    make(ctap2, rk=True, user={"id": b"2", "name": "adam"}, extensions={"largeBlobKey": True})
    make(ctap2, rk=True, rp={"id": "b.org"}, user={"id": b"3", "displayName": "Bob"})


def test_lists_and_info(ctap2, device):
    populate(ctap2)
    auth = device.auth
    rps = localmgmt.list_rps(auth)
    assert [(r[1], r[2]) for r in rps] == [("b.org", 1), ("example.com", 2)]
    creds = localmgmt.list_credentials(auth, RP_HASH)
    assert [c[1] for c in creds] == ["adam", "zoe"]
    info = localmgmt.credential_info(auth, creds[1][0])
    assert info["cred_protect"] == 2 and info["protect_key"] == "fido2.protect.2"
    assert info["backup_eligible"] and not info["backup_state"]
    assert info["algorithm"] == "ES256" and len(info["fingerprint"]) == 16
    fields = localmgmt.info_fields(auth, creds[0][0])
    assert fields[0] == ("fido2.rp", "example.com") and fields[1] == ("fido2.user", "adam")
    with pytest.raises(NotFound):
        localmgmt.credential_info(auth, b"\x00" * 8)
    page, pages = localmgmt.paginate(list(range(10)), 5)
    assert page == [8, 9] and pages == 3
    assert localmgmt.paginate([], 0) == ([], 1)


def test_delete_credential_purges_large_blob(ctap2, device, ui):
    att = make(ctap2, rk=True, extensions={"largeBlobKey": True})
    other = make(ctap2, rk=True, user={"id": b"o", "name": "o"}, extensions={"largeBlobKey": True})
    lbs = LargeBlobs(ctap2)
    lbs.put_blob(att.large_blob_key, b"mine")
    lbs.put_blob(other.large_blob_key, b"other")
    uid = descriptor(att)["id"][1:9]
    ui.push(False)
    assert aio_run(localmgmt.delete_credential(device.auth, ui, uid)) is False
    assert device.auth.store.count() == 2
    assert aio_run(localmgmt.delete_credential(device.auth, ui, uid)) is True
    assert ui.prompts[-1].kind == "fido2.local.delete" and ui.prompts[-1].severity == DANGER
    assert ui.prompts[-1].fingerprint
    assert device.auth.store.count() == 1
    assert lbs.get_blob(att.large_blob_key) is None
    assert lbs.get_blob(other.large_blob_key) == b"other"
    with pytest.raises(NotFound):
        aio_run(localmgmt.delete_credential(device.auth, ui, uid))


def test_wipe_all(ctap2, device, ui):
    populate(ctap2)
    ClientPin(ctap2).set_pin("1234")
    ui.push(False)
    assert aio_run(localmgmt.wipe_all(device.auth, ui)) is False
    device.advance(60_000)  # no 10 s window for the local wipe
    assert aio_run(localmgmt.wipe_all(device.auth, ui)) is True
    assert device.auth.store.count() == 0 and not device.auth.state.pin_is_set()


# ---------------------------------------------------------------------------
# backup provider
# ---------------------------------------------------------------------------


@pytest.fixture
def provider(device):
    bp.clear()
    p = Fido2BackupProvider(device.auth)
    bp.register(p)
    yield p
    bp.clear()


def test_export_restore_roundtrip_to_other_device(ctap2, device, provider):
    att = make(ctap2, rk=True, extensions={"largeBlobKey": True, "hmac-secret": True, "credProtect": 2})
    make(ctap2, rk=True, user={"id": b"z", "name": "zed"})
    LargeBlobs(ctap2).put_blob(att.large_blob_key, b"secret blob")
    ids = provider.list_identities()
    assert sorted(i[1] for i in ids) == ["example.com — alice", "example.com — zed"]
    uid = descriptor(att)["id"][1:9]
    obj = provider.export_identity(uid)
    provider.validate(obj)
    assert obj["type"] == "fido2" and obj["v"] == 1 and len(obj["large_blobs"]) == 1
    from feuristic.core import cbor

    cbor.encode(obj)  # canonical-CBOR-able
    provider.on_exported(uid)
    a = ctap2.get_assertion("example.com", CDH, [descriptor(att)])
    assert a.auth_data.flags & F.BE and a.auth_data.flags & F.BS

    # restore on a different device (different master secret, empty storage)
    from feuristic.platform import testing

    snapshot_counter = obj["sign_count"]
    testing.KV.reset()
    other = Device(SimUI(), ms=bytes(32 - i for i in range(32)))
    p2 = Fido2BackupProvider(other.auth)
    assert not p2.exists(obj)
    label, fp = p2.describe(obj)
    assert label == "example.com — alice" and len(fp) == 16
    assert p2.restore_identity(obj, overwrite=False) == uid
    assert p2.exists(obj)
    ctap2b = Ctap2(open_hid(other))
    a = ctap2b.get_assertion("example.com", CDH, [descriptor(att)], extensions={"largeBlobKey": True})
    a.verify(CDH, att.auth_data.credential_data.public_key)
    assert a.auth_data.flags & F.BE and a.auth_data.flags & F.BS
    assert a.auth_data.counter > snapshot_counter
    assert a.large_blob_key == att.large_blob_key
    assert LargeBlobs(ctap2b).get_blob(a.large_blob_key) == b"secret blob"
    with pytest.raises(PolicyDenied):
        p2.restore_identity(obj, overwrite=False)
    p2.restore_identity(obj, overwrite=True)  # idempotent, blob not duplicated
    assert len(other.auth.large_blobs.entries()) == 1


@pytest.mark.parametrize("operation", ["export", "purge"])
def test_large_blob_ownership_oom_aborts_before_any_mutation(
    ctap2, device, provider, ui, kv, monkeypatch, operation
):
    from feuristic.apps.backup.export import begin_identity_export
    from feuristic.apps.fido2 import largeblobs

    att = make(ctap2, rk=True, extensions={"largeBlobKey": True})
    LargeBlobs(ctap2).put_blob(att.large_blob_key, b"must survive")
    uid = descriptor(att)["id"][1:9]

    async def passphrase(request):
        return bytearray(b"FeuristicPassphrase2026")

    export = aio_run(begin_identity_export(ui, "fido2", uid, passphrase))
    before = dict(kv.data)

    def no_memory(*args):
        raise MemoryError

    monkeypatch.setattr(largeblobs.crypto, "aes256_gcm_decrypt", no_memory)
    try:
        with pytest.raises(MemoryError):
            if operation == "export":
                export.build(0)
            else:
                aio_run(localmgmt.delete_credential(device.auth, ui, uid))
        assert kv.data == before
        assert device.auth.store.count() == 1
        assert not device.auth.store.get(uid).backup_state
    finally:
        export.close()


def test_restore_replaces_same_rp_user(ctap2, device, provider):
    att = make(ctap2, rk=True)
    obj = provider.export_identity(descriptor(att)["id"][1:9])
    make(ctap2, rk=True, rp={"id": "x.com"})  # unrelated
    ctap2.reset()
    make(ctap2, rk=True)  # new credential for the same rp + user, other uid
    assert provider.exists(obj)
    provider.restore_identity(obj, overwrite=True)
    creds = device.auth.store.for_rp(RP_HASH)
    assert len(creds) == 1 and creds[0].cred_id == descriptor(att)["id"]


def test_restore_when_full(ctap2, device, provider):
    att = make(ctap2, rk=True)
    obj = provider.export_identity(descriptor(att)["id"][1:9])
    ctap2.reset()
    for i in range(99):
        make(ctap2, rk=True, user={"id": i.to_bytes(2, "big")})
    make(ctap2, rk=True)  # same rp+user as the backup: 100 credentials
    provider.restore_identity(obj, overwrite=True)  # replacement still possible
    assert device.auth.store.count() == 100
    obj2 = dict(obj, cred_id=b"\x01" + b"\x99" * 12, user_id=b"newuser")
    with pytest.raises(StorageFull):
        provider.restore_identity(obj2, overwrite=False)


def test_restore_large_blob_overflow(ctap2, device, provider):
    att = make(ctap2, rk=True, extensions={"largeBlobKey": True})
    LargeBlobs(ctap2).put_blob(att.large_blob_key, b"x")
    obj = provider.export_identity(descriptor(att)["id"][1:9])
    device.auth.large_blobs.write_entries([{1: b"f" * 4070}])
    with pytest.raises(StorageFull):
        provider.restore_identity(obj, overwrite=True)


@pytest.mark.parametrize(
    "mutation",
    [
        {"v": 2},
        {"type": "otp"},
        {"cred_id": b"\x02" + bytes(12)},
        {"cred_id": b"\x01" + bytes(11)},
        {"rp_id": ""},
        {"rp_id": "a" * 129},
        {"user_id": b"u" * 65},
        {"user_name": ""},
        {"user_name": 5},
        {"alg": -257},
        {"alg": True},
        {"key": b"k" * 31},
        {"key": b"\xff" * 32},
        {"cred_protect": 0},
        {"hmac_secret": 1},
        {"sign_count": -1},
        {"sign_count": 1 << 33},
        {"large_blobs": [b"\x00"]},
        {"large_blobs": ["x"]},
        {"large_blobs": [b"\xa1\x01\x01"]},
        {"large_blobs": "x"},
        {"unknown": 1},
    ],
)
def test_validate_rejects(ctap2, provider, mutation):
    att = make(ctap2, rk=True)
    obj = dict(provider.export_identity(descriptor(att)["id"][1:9]), **mutation)
    with pytest.raises(InvalidInput):
        provider.validate(obj)


def test_validate_missing_field_and_blobs_without_key(ctap2, provider):
    att = make(ctap2, rk=True)
    obj = provider.export_identity(descriptor(att)["id"][1:9])
    bad = dict(obj)
    del bad["key"]
    with pytest.raises(InvalidInput):
        provider.validate(bad)
    from feuristic.core import cbor

    with pytest.raises(InvalidInput):
        provider.validate(dict(obj, large_blobs=[cbor.encode({1: b"c", 2: b"n" * 12, 3: 1})]))
    with pytest.raises(NotFound):
        provider.export_identity(b"\x00" * 8)


def test_eddsa_identity_and_long_label(ctap2, device, provider):
    from ctap_harness import EDDSA

    make(ctap2, rk=True, algs=(EDDSA,), user={"id": b"e", "name": "é" * 64}, rp={"id": "r" * 100 + ".com"})
    uid, label = provider.list_identities()[0]
    assert len(label.encode()) <= 128
    obj = provider.export_identity(uid)
    assert obj["alg"] == -8
    provider.validate(obj)


def test_strings_complete_and_registered():
    strings.register()
    keys = [k for k in i18n.keys() if k.startswith("fido2.")]  # noqa: SIM118 - i18n API
    assert len(keys) == len(strings.STRINGS)
    for k, (en, fr) in strings.STRINGS.items():
        assert en and fr, k
    used = [
        "fido2.title.register",
        "fido2.title.sign_in",
        "fido2.title.choose_account",
        "fido2.title.already_registered",
        "fido2.title.not_registered",
        "fido2.title.select",
        "fido2.title.reset",
        "fido2.title.u2f_register",
        "fido2.title.u2f_sign_in",
        "fido2.title.delete",
        "fido2.title.wipe",
        "fido2.rp",
        "fido2.user",
        "fido2.accounts",
        "fido2.type",
        "fido2.type.passkey",
        "fido2.protect.1",
        "fido2.protect.2",
        "fido2.protect.3",
        "fido2.backup.done",
        "fido2.backup.eligible",
        "fido2.warning",
        "fido2.wipe.warning",
        "fido2.delete.warning",
        "fido2.app",
    ]
    for k in used:
        assert k in strings.STRINGS, k
    i18n.set_language(i18n.FR)
    try:
        assert i18n.t("fido2.title.register") == "Créer une passkey ?"
    finally:
        i18n.set_language(i18n.EN)


def test_user_constant():
    assert USER["id"] == b"user-1" and len(MS) == 32
