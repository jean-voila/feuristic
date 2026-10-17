# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""credProtect (CTAP 2.1 §12.1), hmac-secret (§12.5) and largeBlobKey (§12.3)."""

import hashlib
import hmac
import os

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from ctap_harness import CDH, RP, USER, descriptor, make, sha256
from fido2.ctap import CtapError
from fido2.ctap2.pin import ClientPin, PinProtocolV1, PinProtocolV2

ERR = CtapError.ERR
PERM = ClientPin.PERMISSION
RP_HASH = sha256(b"example.com")


def token(ctap2, perms, rp="example.com", proto=None):
    c = ClientPin(ctap2, proto or PinProtocolV2())
    return c.protocol, c.get_pin_token("1234", perms, rp)


def mc_uv(ctap2, rk=True, **kw):
    proto, tok = token(ctap2, PERM.MAKE_CREDENTIAL)
    return make(ctap2, rk=rk, pin_uv_param=proto.authenticate(tok, CDH), pin_uv_protocol=proto.VERSION, **kw)


def ga(ctap2, allow=None, uv=False, **kw):
    if uv:
        proto, tok = token(ctap2, PERM.GET_ASSERTION)
        kw.update(pin_uv_param=proto.authenticate(tok, CDH), pin_uv_protocol=proto.VERSION)
    return ctap2.get_assertion("example.com", CDH, allow, **kw)


def expect(code, fn, *a, **kw):
    with pytest.raises(CtapError) as e:
        fn(*a, **kw)
    assert e.value.code == code


# ---------------------------------------------------------------------------
# credProtect
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("level", [1, 2, 3])
def test_cred_protect_output(ctap2, level):
    att = make(ctap2, rk=True, extensions={"credProtect": level})
    assert att.auth_data.extensions == {"credProtect": level}


def test_cred_protect_matrix(ctap2, device):
    ClientPin(ctap2).set_pin("1234")
    creds = {}
    for level in (1, 2, 3):
        att = mc_uv(
            ctap2, user={"id": bytes([level]), "name": f"l{level}"}, extensions={"credProtect": level}
        )
        creds[level] = descriptor(att)
    # discoverable, no allowList, no UV: only level 1
    a = ga(ctap2)
    assert a.credential["id"] == creds[1]["id"] and a.number_of_credentials is None
    # with allowList, no UV: levels 1 and 2
    for level in (1, 2):
        assert ga(ctap2, [creds[level]]).credential["id"] == creds[level]["id"]
    expect(ERR.NO_CREDENTIALS, ga, ctap2, [creds[3]])
    # with UV: everything
    device.ui.push(True, 0)
    a = ga(ctap2, uv=True)
    assert a.user_selected
    assert len(device.ui.selects[-1][1]) == 3
    assert ga(ctap2, [creds[3]], uv=True).credential["id"] == creds[3]["id"]
    # silent enumeration without UV only lists level 1
    a = ga(ctap2, options={"up": False})
    assert a.number_of_credentials is None


def test_cred_protect_non_discoverable(ctap2):
    att = make(ctap2, extensions={"credProtect": 3})
    assert att.auth_data.extensions == {"credProtect": 3}
    expect(ERR.NO_CREDENTIALS, ga, ctap2, [descriptor(att)])
    att2 = make(ctap2, extensions={"credProtect": 2})
    assert ga(ctap2, [descriptor(att2)]).credential["id"] == descriptor(att2)["id"]


def test_cred_protect_exclude_list(ctap2):
    ClientPin(ctap2).set_pin("1234")
    att = make(ctap2, extensions={"credProtect": 3})
    # without UV the level-3 credential is invisible: creation proceeds
    make(ctap2, exclude_list=[descriptor(att)])
    # with UV it is excluded
    expect(ERR.CREDENTIAL_EXCLUDED, mc_uv, ctap2, rk=False, exclude_list=[descriptor(att)])


def test_cred_protect_blocks_u2f(ctap2, hid):
    from fido2.ctap1 import ApduError, Ctap1

    att = make(ctap2, extensions={"credProtect": 2})
    with pytest.raises(ApduError) as e:
        Ctap1(hid).authenticate(CDH, RP_HASH, descriptor(att)["id"], check_only=True)
    assert e.value.code == 0x6A80


# ---------------------------------------------------------------------------
# hmac-secret
# ---------------------------------------------------------------------------


def cred_random(key: bytes, uv: bool) -> bytes:
    info = b"fido2/cred-random\x00" + (b"uv" if uv else b"no-uv")
    return HKDF(hashes.SHA256(), 32, b"feuristic/v1", info).derive(key)


def hs_input(ctap2, proto, salts, send_version=True):
    c = ClientPin(ctap2, proto)
    ka, shared = c._get_shared_secret()
    salt_enc = proto.encrypt(shared, salts)
    inp = {1: ka, 2: salt_enc, 3: proto.authenticate(shared, salt_enc)}
    if send_version:
        inp[4] = proto.VERSION
    return inp, shared


@pytest.mark.parametrize("proto_cls", [PinProtocolV1, PinProtocolV2])
@pytest.mark.parametrize("rk", [False, True])
@pytest.mark.parametrize("nsalts", [1, 2])
def test_hmac_secret_outputs(ctap2, device, proto_cls, rk, nsalts):
    proto = proto_cls()
    att = make(ctap2, rk=rk, extensions={"hmac-secret": True})
    assert att.auth_data.extensions == {"hmac-secret": True}
    cred = device.auth.store.lookup(descriptor(att)["id"], RP_HASH)
    salts = os.urandom(32 * nsalts)
    inp, shared = hs_input(ctap2, proto, salts)
    a = ga(ctap2, [descriptor(att)], extensions={"hmac-secret": inp})
    out = proto.decrypt(shared, a.auth_data.extensions["hmac-secret"])
    cr = cred_random(cred.key, False)
    expected = hmac.new(cr, salts[:32], hashlib.sha256).digest()
    if nsalts == 2:
        expected += hmac.new(cr, salts[32:], hashlib.sha256).digest()
    assert out == expected
    # deterministic: same salts give the same output
    inp, shared = hs_input(ctap2, proto, salts)
    a2 = ga(ctap2, [descriptor(att)], extensions={"hmac-secret": inp})
    assert proto.decrypt(shared, a2.auth_data.extensions["hmac-secret"]) == expected


def test_hmac_secret_with_uv_uses_other_cred_random(ctap2, device):
    ClientPin(ctap2).set_pin("1234")
    att = mc_uv(ctap2, extensions={"hmac-secret": True})
    key = device.auth.store.lookup(descriptor(att)["id"], RP_HASH).key
    proto = PinProtocolV2()
    salts = os.urandom(32)
    inp, shared = hs_input(ctap2, proto, salts)
    no_uv = proto.decrypt(
        shared,
        ga(ctap2, [descriptor(att)], extensions={"hmac-secret": inp}).auth_data.extensions["hmac-secret"],
    )
    inp, shared = hs_input(ctap2, proto, salts)
    with_uv = proto.decrypt(
        shared,
        ga(ctap2, [descriptor(att)], uv=True, extensions={"hmac-secret": inp}).auth_data.extensions[
            "hmac-secret"
        ],
    )
    assert no_uv == hmac.new(cred_random(key, False), salts, hashlib.sha256).digest()
    assert with_uv == hmac.new(cred_random(key, True), salts, hashlib.sha256).digest()
    assert no_uv != with_uv


def test_hmac_secret_default_protocol_1(ctap2):
    att = make(ctap2, extensions={"hmac-secret": True})
    proto = PinProtocolV1()
    inp, shared = hs_input(ctap2, proto, os.urandom(32), send_version=False)
    a = ga(ctap2, [descriptor(att)], extensions={"hmac-secret": inp})
    assert len(proto.decrypt(shared, a.auth_data.extensions["hmac-secret"])) == 32


def test_hmac_secret_not_enabled_no_output(ctap2):
    att = make(ctap2)
    inp, _ = hs_input(ctap2, PinProtocolV2(), os.urandom(32))
    a = ga(ctap2, [descriptor(att)], extensions={"hmac-secret": inp})
    assert a.auth_data.extensions is None


def test_hmac_secret_input_errors(ctap2):
    att = make(ctap2, extensions={"hmac-secret": True})
    allow = [descriptor(att)]
    proto = PinProtocolV2()
    inp, shared = hs_input(ctap2, proto, os.urandom(32))
    expect(ERR.PIN_AUTH_INVALID, ga, ctap2, allow, extensions={"hmac-secret": {**inp, 3: b"\0" * 32}})
    expect(ERR.INVALID_PARAMETER, ga, ctap2, allow, extensions={"hmac-secret": {**inp, 4: 7}})
    expect(ERR.INVALID_PARAMETER, ga, ctap2, allow, extensions={"hmac-secret": {**inp, 1: {1: 2, -1: 1}}})
    expect(ERR.MISSING_PARAMETER, ga, ctap2, allow, extensions={"hmac-secret": {1: inp[1], 2: inp[2]}})
    expect(ERR.CBOR_UNEXPECTED_TYPE, ga, ctap2, allow, extensions={"hmac-secret": {**inp, 2: "x"}})
    bad = proto.encrypt(shared, os.urandom(48))
    expect(
        ERR.INVALID_LENGTH,
        ga,
        ctap2,
        allow,
        extensions={"hmac-secret": {**inp, 2: bad, 3: proto.authenticate(shared, bad)}},
    )


def test_hmac_secret_survives_power_cycle_and_get_next(ctap2, device):
    for i in range(2):
        make(ctap2, rk=True, user={"id": bytes([i]), "name": str(i)}, extensions={"hmac-secret": True})
    proto = PinProtocolV2()
    salts = os.urandom(32)
    inp, shared = hs_input(ctap2, proto, salts)
    first = ga(ctap2, options={"up": False}, extensions={"hmac-secret": inp})
    nxt = ctap2.get_next_assertion()
    o1 = proto.decrypt(shared, first.auth_data.extensions["hmac-secret"])
    o2 = proto.decrypt(shared, nxt.auth_data.extensions["hmac-secret"])
    assert o1 != o2
    creds = {c.user_id: c for c in device.auth.store.for_rp(RP_HASH)}
    assert o2 == hmac.new(cred_random(creds[nxt.user["id"]].key, False), salts, hashlib.sha256).digest()


# ---------------------------------------------------------------------------
# largeBlobKey
# ---------------------------------------------------------------------------


def test_large_blob_key(ctap2, device):
    att = make(ctap2, rk=True, extensions={"largeBlobKey": True})
    key = att.large_blob_key
    assert isinstance(key, bytes) and len(key) == 32
    a = ga(ctap2, extensions={"largeBlobKey": True})
    assert a.large_blob_key == key
    a = ga(ctap2)
    assert a.large_blob_key is None
    other = make(ctap2, rk=True, user={"id": b"o", "name": "o"}, rp={"id": "other.com"})
    assert other.large_blob_key is None
    a = ctap2.get_assertion("other.com", CDH, extensions={"largeBlobKey": True})
    assert a.large_blob_key is None
    cred = device.auth.store.for_rp(RP_HASH)[0]
    expected = HKDF(hashes.SHA256(), 32, b"feuristic/v1", b"fido2/largeblob-key\x00").derive(cred.key)
    assert key == expected


def test_large_blob_key_requires_rk(ctap2):
    expect(ERR.INVALID_OPTION, make, ctap2, extensions={"largeBlobKey": True})


def test_rp_and_user_constants():
    assert RP["id"] == "example.com" and USER["name"] == "alice"
