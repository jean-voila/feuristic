# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""authenticatorMakeCredential / GetAssertion / GetNextAssertion / GetInfo /
Selection through python-fido2's unmodified Ctap2 client."""

import pytest
from ctap_harness import CDH, EDDSA, ES256, RP, USER, descriptor, make, sha256, verify_attestation
from fido2.cose import CoseKey
from fido2.ctap import CtapError
from fido2.webauthn import AuthenticatorData

from feuristic.apps.fido2 import credentials as cr
from feuristic.apps.fido2 import ctap2 as c2

ERR = CtapError.ERR
F = AuthenticatorData.FLAG


def test_get_info(ctap2):
    info = ctap2.info
    assert info.versions == ["U2F_V2", "FIDO_2_0", "FIDO_2_1"]
    assert info.extensions == ["credProtect", "hmac-secret", "largeBlobKey"]
    assert bytes(info.aaguid) == bytes.fromhex("e90e59a42c044252ae49d69eff27585f")
    assert info.options == {
        "rk": True,
        "up": True,
        "plat": False,
        "clientPin": False,
        "credMgmt": True,
        "largeBlobs": True,
        "pinUvAuthToken": True,
        "makeCredUvNotRqd": True,
    }
    assert "uv" not in info.options
    assert info.max_msg_size == 7609
    assert info.pin_uv_protocols == [2, 1]
    assert info.max_creds_in_list == 16
    assert info.max_cred_id_length == 64
    assert info.transports == ["usb"]
    assert info.algorithms == [{"alg": -7, "type": "public-key"}, {"alg": -8, "type": "public-key"}]
    assert info.max_large_blob == 4096
    assert info.min_pin_length == 4
    assert info.firmware_version == 0x000100
    assert info.remaining_disc_creds == 100
    assert info.attestation_formats == ["packed", "none"]


@pytest.mark.parametrize("alg", [ES256, EDDSA])
@pytest.mark.parametrize("rk", [False, True])
def test_make_credential_and_assert(ctap2, ui, alg, rk):
    att = make(ctap2, algs=(alg,), rk=rk)
    verify_attestation(att)
    ad = att.auth_data
    assert ad.rp_id_hash == sha256(b"example.com")
    assert ad.flags & F.UP and ad.flags & F.AT
    assert not ad.flags & F.UV
    assert bool(ad.flags & F.BE) == rk
    assert not ad.flags & F.BS
    assert bytes(ad.credential_data.aaguid) == c2.AAGUID
    cid = ad.credential_data.credential_id
    assert len(cid) == (13 if rk else 62)
    pk = ad.credential_data.public_key
    assert alg["alg"] == pk.ALGORITHM
    assert ui.kinds() == ["fido2.make_credential"]

    cdh2 = sha256(b"assert")
    allow = None if rk else [descriptor(att)]
    a = ctap2.get_assertion("example.com", cdh2, allow)
    a.verify(cdh2, pk)
    assert a.credential["id"] == cid
    assert a.auth_data.flags & F.UP
    assert bool(a.auth_data.flags & F.BE) == rk
    assert a.auth_data.counter > ad.counter
    if rk:
        assert a.user == {"id": USER["id"]}  # no PII without UV
    else:
        assert a.user is None
    assert a.number_of_credentials is None
    assert ui.kinds()[-1] == "fido2.get_assertion"


def test_rp_id_binding(ctap2):
    att = make(ctap2)
    with pytest.raises(CtapError) as e:
        ctap2.get_assertion("evil.com", CDH, [descriptor(att)])
    assert e.value.code == ERR.NO_CREDENTIALS


def test_tampered_credential_id_rejected(ctap2):
    att = make(ctap2)
    cid = bytearray(descriptor(att)["id"])
    for pos in (0, 5, 20, 61):
        bad = bytearray(cid)
        bad[pos] ^= 1
        with pytest.raises(CtapError) as e:
            ctap2.get_assertion("example.com", CDH, [{"type": "public-key", "id": bytes(bad)}])
        assert e.value.code == ERR.NO_CREDENTIALS
    with pytest.raises(CtapError):
        ctap2.get_assertion("example.com", CDH, [{"type": "public-key", "id": bytes(cid[:-1])}])


def test_allow_list_skips_foreign_and_other_types(ctap2):
    att = make(ctap2)
    allow = [
        {"type": "secret-key", "id": descriptor(att)["id"]},
        {"type": "public-key", "id": b"\x00" * 70},
        {"type": "public-key", "id": b"foreign"},
        descriptor(att),
    ]
    a = ctap2.get_assertion("example.com", CDH, allow)
    assert a.credential["id"] == descriptor(att)["id"]


def test_exclude_list(ctap2, ui):
    att = make(ctap2)
    with pytest.raises(CtapError) as e:
        make(ctap2, exclude_list=[descriptor(att)])
    assert e.value.code == ERR.CREDENTIAL_EXCLUDED
    assert ui.kinds()[-1] == "fido2.excluded"
    # declined confirmation of the "already registered" screen
    ui.push(False)
    with pytest.raises(CtapError) as e:
        make(ctap2, exclude_list=[descriptor(att)])
    assert e.value.code == ERR.OPERATION_DENIED
    # an unrelated exclude list does not prevent creation
    make(ctap2, exclude_list=[{"type": "public-key", "id": b"zz"}])


def test_user_denies_and_timeout(ctap2, ui):
    ui.push(False)
    with pytest.raises(CtapError) as e:
        make(ctap2)
    assert e.value.code == ERR.OPERATION_DENIED
    ui.push("timeout")
    with pytest.raises(CtapError) as e:
        make(ctap2)
    assert e.value.code == ERR.USER_ACTION_TIMEOUT
    ui.push("slow-false")
    with pytest.raises(CtapError) as e:
        make(ctap2)
    assert e.value.code == ERR.USER_ACTION_TIMEOUT


def test_attestation_none_preference(ctap2):
    att = ctap2.make_credential(CDH, RP, USER, [ES256])
    assert att.fmt == "packed"
    resp = ctap2.send_cbor(0x01, {1: CDH, 2: RP, 3: USER, 4: [ES256], 0x0B: ["tpm", "none", "packed"]})
    assert resp[1] == "none" and resp[3] == {}
    resp = ctap2.send_cbor(0x01, {1: CDH, 2: RP, 3: USER, 4: [ES256], 0x0B: ["tpm"]})
    assert resp[1] == "packed"
    with pytest.raises(CtapError) as e:
        ctap2.send_cbor(0x01, {1: CDH, 2: RP, 3: USER, 4: [ES256], 0x0B: [1]})
    assert e.value.code == ERR.CBOR_UNEXPECTED_TYPE


def test_algorithm_selection_follows_rp_preference(ctap2):
    att = make(ctap2, algs=({"type": "public-key", "alg": -257}, EDDSA, ES256))
    assert att.auth_data.credential_data.public_key.ALGORITHM == -8
    with pytest.raises(CtapError) as e:
        make(ctap2, algs=({"type": "public-key", "alg": -257},))
    assert e.value.code == ERR.UNSUPPORTED_ALGORITHM
    with pytest.raises(CtapError) as e:
        make(ctap2, algs=({"type": "other", "alg": -7},))
    assert e.value.code == ERR.UNSUPPORTED_ALGORITHM
    with pytest.raises(CtapError) as e:
        make(ctap2, algs=({"type": "public-key"},))
    assert e.value.code == ERR.MISSING_PARAMETER
    with pytest.raises(CtapError) as e:
        make(ctap2, algs=({"type": "public-key", "alg": "x"},))
    assert e.value.code == ERR.CBOR_UNEXPECTED_TYPE
    with pytest.raises(CtapError) as e:
        make(ctap2, algs=(7,))
    assert e.value.code == ERR.CBOR_UNEXPECTED_TYPE


@pytest.mark.parametrize(
    ("params", "code"),
    [
        ({}, ERR.MISSING_PARAMETER),
        ({1: CDH, 2: RP, 3: USER}, ERR.MISSING_PARAMETER),
        ({1: CDH, 2: {"name": "x"}, 3: USER, 4: [ES256]}, ERR.MISSING_PARAMETER),
        ({1: CDH, 2: RP, 3: {"name": "x"}, 4: [ES256]}, ERR.MISSING_PARAMETER),
        ({1: "cdh", 2: RP, 3: USER, 4: [ES256]}, ERR.CBOR_UNEXPECTED_TYPE),
        ({1: CDH, 2: "rp", 3: USER, 4: [ES256]}, ERR.CBOR_UNEXPECTED_TYPE),
        ({1: CDH, 2: {"id": 1}, 3: USER, 4: [ES256]}, ERR.CBOR_UNEXPECTED_TYPE),
        ({1: CDH, 2: RP, 3: {"id": "text"}, 4: [ES256]}, ERR.CBOR_UNEXPECTED_TYPE),
        ({1: CDH, 2: RP, 3: {"id": b"u", "name": 5}, 4: [ES256]}, ERR.CBOR_UNEXPECTED_TYPE),
        ({1: CDH, 2: RP, 3: USER, 4: {}}, ERR.CBOR_UNEXPECTED_TYPE),
        ({1: CDH[:31], 2: RP, 3: USER, 4: [ES256]}, ERR.INVALID_LENGTH),
        ({1: CDH, 2: RP, 3: {"id": b"u" * 65}, 4: [ES256]}, ERR.INVALID_LENGTH),
        ({1: CDH, 2: RP, 3: USER, 4: [ES256], 5: "x"}, ERR.CBOR_UNEXPECTED_TYPE),
        ({1: CDH, 2: RP, 3: USER, 4: [ES256], 5: ["x"]}, ERR.CBOR_UNEXPECTED_TYPE),
        ({1: CDH, 2: RP, 3: USER, 4: [ES256], 5: [{"id": b"x"}]}, ERR.MISSING_PARAMETER),
        ({1: CDH, 2: RP, 3: USER, 4: [ES256], 5: [{}] * 65}, ERR.LIMIT_EXCEEDED),
        ({1: CDH, 2: RP, 3: USER, 4: [ES256], 6: []}, ERR.CBOR_UNEXPECTED_TYPE),
        ({1: CDH, 2: RP, 3: USER, 4: [ES256], 7: {"up": False}}, ERR.INVALID_OPTION),
        ({1: CDH, 2: RP, 3: USER, 4: [ES256], 7: {"uv": True}}, ERR.INVALID_OPTION),
        ({1: CDH, 2: RP, 3: USER, 4: [ES256], 7: {"rk": 1}}, ERR.CBOR_UNEXPECTED_TYPE),
        ({1: CDH, 2: RP, 3: USER, 4: [ES256], 8: b"x" * 16}, ERR.MISSING_PARAMETER),
        ({1: CDH, 2: RP, 3: USER, 4: [ES256], 8: b"x" * 16, 9: 3}, ERR.INVALID_PARAMETER),
        ({1: CDH, 2: RP, 3: USER, 4: [ES256], 8: b"x" * 16, 9: 1}, ERR.PIN_AUTH_INVALID),
        ({1: CDH, 2: RP, 3: USER, 4: [ES256], 0x0A: 1}, ERR.INVALID_PARAMETER),
        ({1: CDH, 2: RP, 3: USER, 4: [ES256], 6: {"credProtect": 4}}, ERR.INVALID_OPTION),
        ({1: CDH, 2: RP, 3: USER, 4: [ES256], 6: {"credProtect": "x"}}, ERR.CBOR_UNEXPECTED_TYPE),
        ({1: CDH, 2: RP, 3: USER, 4: [ES256], 6: {"hmac-secret": 1}}, ERR.CBOR_UNEXPECTED_TYPE),
        ({1: CDH, 2: RP, 3: USER, 4: [ES256], 6: {"largeBlobKey": True}}, ERR.INVALID_OPTION),
        (
            {1: CDH, 2: RP, 3: USER, 4: [ES256], 6: {"largeBlobKey": False}, 7: {"rk": True}},
            ERR.INVALID_OPTION,
        ),
    ],
)
def test_make_credential_parameter_validation(ctap2, params, code):
    with pytest.raises(CtapError) as e:
        ctap2.send_cbor(0x01, params)
    assert e.value.code == code


def test_unknown_keys_and_options_ignored(ctap2):
    resp = ctap2.send_cbor(
        0x01,
        {1: CDH, 2: dict(RP, icon="x"), 3: USER, 4: [ES256], 7: {"foo": True}, 6: {"unknown": 1}, 0x20: "x"},
    )
    assert resp[1] == "packed"


@pytest.mark.parametrize(
    ("params", "code"),
    [
        ({}, ERR.MISSING_PARAMETER),
        ({1: "example.com"}, ERR.MISSING_PARAMETER),
        ({1: 5, 2: CDH}, ERR.CBOR_UNEXPECTED_TYPE),
        ({1: "example.com", 2: CDH[:5]}, ERR.INVALID_LENGTH),
        ({1: "example.com", 2: CDH, 3: {}}, ERR.CBOR_UNEXPECTED_TYPE),
        ({1: "example.com", 2: CDH, 5: {"rk": True}}, ERR.UNSUPPORTED_OPTION),
        ({1: "example.com", 2: CDH, 5: {"uv": True}}, ERR.INVALID_OPTION),
        ({1: "example.com", 2: CDH, 5: {"up": "no"}}, ERR.CBOR_UNEXPECTED_TYPE),
        ({1: "example.com", 2: CDH, 6: b"x" * 16}, ERR.MISSING_PARAMETER),
        ({1: "example.com", 2: CDH, 6: b"x" * 16, 7: 9}, ERR.INVALID_PARAMETER),
        ({1: "example.com", 2: CDH, 4: {"largeBlobKey": False}}, ERR.INVALID_OPTION),
        ({1: "example.com", 2: CDH, 4: {"hmac-secret": 1}}, ERR.CBOR_UNEXPECTED_TYPE),
        ({1: "example.com", 2: CDH}, ERR.NO_CREDENTIALS),
    ],
)
def test_get_assertion_parameter_validation(ctap2, params, code):
    with pytest.raises(CtapError) as e:
        ctap2.send_cbor(0x02, params)
    assert e.value.code == code


def test_silent_assertion_and_get_next(ctap2, ui):
    for i in range(3):
        make(ctap2, user={"id": bytes([i]) * 4, "name": f"user{i}"}, rk=True)
    ui.prompts.clear()
    first = ctap2.get_assertion("example.com", CDH, options={"up": False})
    assert first.number_of_credentials == 3
    assert not first.auth_data.flags & F.UP
    assert ui.prompts == []
    rest = [ctap2.get_next_assertion() for _ in range(2)]
    names = [first.user["id"]] + [r.user["id"] for r in rest]
    assert names == [b"\x02" * 4, b"\x01" * 4, b"\x00" * 4]  # most recent first
    for r in rest:
        assert r.number_of_credentials is None
        assert r.auth_data.counter > first.auth_data.counter
    with pytest.raises(CtapError) as e:
        ctap2.get_next_assertion()
    assert e.value.code == ERR.NOT_ALLOWED


def test_get_next_assertion_state_rules(ctap2, device):
    for i in range(3):
        make(ctap2, user={"id": bytes([i]) * 4, "name": f"user{i}"}, rk=True)
    with pytest.raises(CtapError) as e:
        ctap2.get_next_assertion()
    assert e.value.code == ERR.NOT_ALLOWED
    ctap2.get_assertion("example.com", CDH, options={"up": False})
    ctap2.get_info()  # any other command invalidates the state
    with pytest.raises(CtapError):
        ctap2.get_next_assertion()
    ctap2.get_assertion("example.com", CDH, options={"up": False})
    device.advance(31_000)
    with pytest.raises(CtapError):
        ctap2.get_next_assertion()


def test_user_selects_account_on_device(ctap2, ui):
    for i in range(3):
        make(ctap2, user={"id": bytes([i]) * 4, "name": f"user{i}"}, rk=True)
    ui.push(True, 2)
    a = ctap2.get_assertion("example.com", CDH)
    assert a.user == {"id": b"\x00" * 4}
    assert a.user_selected is True
    assert a.number_of_credentials is None
    assert ui.selects[-1] == ("fido2.title.choose_account", ["user2", "user1", "user0"])
    ui.push(True, None)
    with pytest.raises(CtapError) as e:
        ctap2.get_assertion("example.com", CDH)
    assert e.value.code == ERR.OPERATION_DENIED
    ui.push(True, "timeout")
    with pytest.raises(CtapError) as e:
        ctap2.get_assertion("example.com", CDH)
    assert e.value.code == ERR.USER_ACTION_TIMEOUT


def test_resident_overwrite_same_user(ctap2, device):
    a1 = make(ctap2, rk=True)
    a2 = make(ctap2, rk=True, user=dict(USER, name="alice2"))
    id1 = descriptor(a1)["id"]
    id2 = descriptor(a2)["id"]
    assert id1 != id2 and id1[:9] == id2[:9]  # same record uid, new seq
    assert device.auth.store.count() == 1
    with pytest.raises(CtapError):
        ctap2.get_assertion("example.com", CDH, [descriptor(a1)])
    a = ctap2.get_assertion("example.com", CDH, [descriptor(a2)])
    assert a.user == {"id": USER["id"]}


def test_names_truncated_to_64_bytes(ctap2, device):
    long_name = "é" * 40  # 80 bytes
    make(ctap2, rk=True, user={"id": b"u", "name": long_name, "displayName": "x" * 100})
    cred = device.auth.store.for_rp(sha256(b"example.com"))[0]
    assert cred.user_name == "é" * 32
    assert len(cred.display_name) == 64


def test_rp_id_too_long_for_resident(ctap2):
    rp = {"id": "a" * 129 + ".com"}
    with pytest.raises(CtapError) as e:
        make(ctap2, rp=rp, rk=True)
    assert e.value.code == ERR.INVALID_LENGTH
    make(ctap2, rp=rp)  # non-discoverable is fine


def test_key_store_full_after_100(ctap2, device, ui):
    for i in range(100):
        make(ctap2, user={"id": i.to_bytes(2, "big"), "name": f"u{i}"}, rk=True)
    assert ctap2.get_info().remaining_disc_creds == 0
    n = len(ui.prompts)
    with pytest.raises(CtapError) as e:
        make(ctap2, user={"id": b"new"}, rk=True)
    assert e.value.code == ERR.KEY_STORE_FULL
    assert len(ui.prompts) == n  # fails before asking the user
    # replacing an existing user still works when full
    make(ctap2, user={"id": (5).to_bytes(2, "big"), "name": "u5-bis"}, rk=True)
    # non-discoverable credentials are unaffected
    make(ctap2)
    # all 100 survive a power cycle
    device.power_cycle()
    assert device.auth.store.count() == 100


def test_bogus_rp_id_selection_prompt(ctap2, ui):
    make(ctap2, rp={"id": ".dummy"})
    assert ui.kinds()[-1] == "fido2.selection"


def test_selection_command(ctap2, ui):
    ctap2.selection()
    assert ui.kinds() == ["fido2.selection"]
    ui.push(False)
    with pytest.raises(CtapError) as e:
        ctap2.selection()
    assert e.value.code == ERR.OPERATION_DENIED


def test_invalid_command_and_cbor(ctap2, hid):
    with pytest.raises(CtapError) as e:
        ctap2.send_cbor(0x0D, {1: 1})
    assert e.value.code == ERR.INVALID_COMMAND
    with pytest.raises(CtapError) as e:
        ctap2.send_cbor(0x55)
    assert e.value.code == ERR.INVALID_COMMAND
    resp = hid.call(0x10, b"\x01\xff")
    assert resp == bytes([ERR.INVALID_CBOR])
    resp = hid.call(0x10, b"\x01\x80")  # array instead of map
    assert resp == bytes([ERR.CBOR_UNEXPECTED_TYPE])
    resp = hid.call(0x10, b"\x02\xa1\x01\xa1\x01\xa1\x01\xa1\x01\xa1\x01\xa1\x01\x01")
    assert resp[0] in (ERR.INVALID_CBOR, ERR.CBOR_UNEXPECTED_TYPE)


def test_signature_counter_monotonic_across_power_cycles(ctap2, device, hid):
    att = make(ctap2)
    c0 = att.auth_data.counter
    a = ctap2.get_assertion("example.com", CDH, [descriptor(att)])
    assert a.auth_data.counter == c0 + 1
    device.power_cycle()
    from ctap_harness import open_hid
    from fido2.ctap2 import Ctap2

    ctap2b = Ctap2(open_hid(device))
    b = ctap2b.get_assertion("example.com", CDH, [descriptor(att)])
    assert b.auth_data.counter > a.auth_data.counter


def test_cose_keys_parse(ctap2):
    for alg in (ES256, EDDSA):
        att = make(ctap2, algs=(alg,))
        pk = att.auth_data.credential_data.public_key
        assert isinstance(pk, CoseKey)
        cred_key = dict(pk)
        if alg is ES256:
            assert cred_key[1] == 2 and cred_key[-1] == 1 and len(cred_key[-2]) == 32
        else:
            assert cred_key[1] == 1 and cred_key[-1] == 6 and len(cred_key[-2]) == 32


def test_u2f_key_handle_usable_with_ctap2():
    # covered in test_ctap1; here: lookup format sanity
    assert cr.U2F_KH_LEN == 61 and cr.WRAPPED_ID_LEN == 62 and cr.RESIDENT_ID_LEN == 13
