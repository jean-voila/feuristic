# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""authenticatorCredentialManagement (CTAP 2.1 §6.8)."""

import pytest
from ctap_harness import CDH, make, sha256
from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap2 import CredentialManagement
from fido2.ctap2.pin import ClientPin, PinProtocolV1, PinProtocolV2

ERR = CtapError.ERR
PERM = ClientPin.PERMISSION
CM = CredentialManagement


def expect(code, fn, *a, **kw):
    with pytest.raises(CtapError) as e:
        fn(*a, **kw)
    assert e.value.code == code


@pytest.fixture(params=[PinProtocolV1, PinProtocolV2], ids=["v1", "v2"])
def setup(request, ctap2):
    proto = request.param()
    c = ClientPin(ctap2, proto)
    c.set_pin("1234")

    def mc(rp, uid, name, **kw):
        tok = c.get_pin_token("1234", PERM.MAKE_CREDENTIAL, rp)
        return make(
            ctap2,
            rp={"id": rp, "name": rp.upper()},
            user={"id": uid, "name": name, "displayName": name.title()},
            rk=True,
            pin_uv_param=proto.authenticate(tok, CDH),
            pin_uv_protocol=proto.VERSION,
            **kw,
        )

    def cm(perms=PERM.CREDENTIAL_MGMT, rp=None):
        return CredentialManagement(ctap2, proto, c.get_pin_token("1234", perms, rp))

    return proto, c, mc, cm


def test_metadata_and_enumeration(ctap2, setup):
    proto, c, mc, cm = setup
    m = cm()
    assert m.enumerate_rps() == []  # python-fido2 maps NO_CREDENTIALS to []
    expect(ERR.NO_CREDENTIALS, m.enumerate_rps_begin)
    assert m.get_metadata() == {1: 0, 2: 100}
    mc("a.com", b"1", "alice", extensions={"largeBlobKey": True, "credProtect": 2})
    mc("a.com", b"2", "bob")
    mc("b.org", b"3", "carol")
    m = cm()  # mc() obtained new tokens, invalidating the previous one
    assert m.get_metadata() == {1: 3, 2: 97}
    rps = m.enumerate_rps()
    assert [r[3]["id"] for r in rps] == ["a.com", "b.org"]
    assert rps[0][4] == sha256(b"a.com") and rps[0][5] == 2
    creds = m.enumerate_creds(sha256(b"a.com"))
    assert len(creds) == 2 and creds[0][9] == 2
    by_name = {cr[6]["name"]: cr for cr in creds}
    assert by_name["alice"][6] == {"id": b"1", "name": "alice", "displayName": "Alice"}
    assert by_name["alice"][10] == 2 and len(by_name["alice"][11]) == 32
    assert by_name["bob"][10] == 1 and 11 not in by_name["bob"]
    assert by_name["bob"][7]["type"] == "public-key"
    assert by_name["bob"][8][3] == -7
    expect(ERR.NO_CREDENTIALS, m.enumerate_creds_begin, sha256(b"none.com"))


def test_delete_and_update(ctap2, setup):
    proto, c, mc, cm = setup
    att = mc("a.com", b"1", "alice")
    mc("a.com", b"2", "bob")
    cid = {"type": "public-key", "id": att.auth_data.credential_data.credential_id}
    m = cm()
    m.update_user_info(cid, {"id": b"1", "name": "alice2"})
    creds = {cr[6]["id"]: cr for cr in m.enumerate_creds(sha256(b"a.com"))}
    assert creds[b"1"][6] == {"id": b"1", "name": "alice2"}
    expect(ERR.INVALID_PARAMETER, m.update_user_info, cid, {"id": b"other", "name": "x"})
    m.delete_cred(cid)
    expect(ERR.NO_CREDENTIALS, m.delete_cred, cid)
    expect(ERR.NO_CREDENTIALS, m.update_user_info, cid, {"id": b"1"})
    assert m.get_metadata()[1] == 1
    expect(ERR.NO_CREDENTIALS, ctap2.get_assertion, "a.com", CDH, [cid])


def test_permissions_and_rp_binding(ctap2, setup):
    proto, c, mc, cm = setup
    att = mc("a.com", b"1", "alice")
    mc("b.org", b"2", "bob")
    cid = {"type": "public-key", "id": att.auth_data.credential_data.credential_id}
    expect(ERR.PIN_AUTH_INVALID, cm(PERM.GET_ASSERTION, "a.com").get_metadata)
    bound = cm(PERM.CREDENTIAL_MGMT, "a.com")
    expect(ERR.PIN_AUTH_INVALID, bound.get_metadata)
    expect(ERR.PIN_AUTH_INVALID, bound.enumerate_rps)
    assert len(bound.enumerate_creds(sha256(b"a.com"))) == 1
    expect(ERR.PIN_AUTH_INVALID, bound.enumerate_creds, sha256(b"b.org"))
    other = cm(PERM.CREDENTIAL_MGMT, "b.org")
    expect(ERR.PIN_AUTH_INVALID, other.delete_cred, cid)
    cm(PERM.CREDENTIAL_MGMT, "a.com").delete_cred(cid)  # a new token replaces the previous one


def test_auth_errors(ctap2, setup):
    proto, c, mc, cm = setup
    v = proto.VERSION
    expect(ERR.PUAT_REQUIRED, ctap2.credential_mgmt, 1)
    expect(ERR.MISSING_PARAMETER, ctap2.credential_mgmt, 1, pin_uv_param=b"x" * 16)
    expect(ERR.INVALID_PARAMETER, ctap2.credential_mgmt, 1, pin_uv_protocol=9, pin_uv_param=b"x" * 16)
    expect(ERR.PIN_AUTH_INVALID, ctap2.credential_mgmt, 1, pin_uv_protocol=v, pin_uv_param=b"x" * 32)
    expect(ERR.INVALID_SUBCOMMAND, ctap2.credential_mgmt, 0x20, pin_uv_protocol=v, pin_uv_param=b"x" * 32)
    expect(ERR.MISSING_PARAMETER, ctap2.send_cbor, 0x0A, {})
    tok = c.get_pin_token("1234", PERM.CREDENTIAL_MGMT)
    params = {1: b"\x00" * 31}
    expect(
        ERR.INVALID_PARAMETER,
        ctap2.credential_mgmt,
        4,
        params,
        v,
        proto.authenticate(tok, b"\x04" + cbor.encode(params)),
    )
    expect(
        ERR.MISSING_PARAMETER,
        ctap2.credential_mgmt,
        4,
        {},
        v,
        proto.authenticate(tok, b"\x04" + cbor.encode({})),
    )
    expect(
        ERR.MISSING_PARAMETER,
        ctap2.credential_mgmt,
        6,
        {},
        v,
        proto.authenticate(tok, b"\x06" + cbor.encode({})),
    )
    p = {2: "notamap"}
    expect(
        ERR.CBOR_UNEXPECTED_TYPE,
        ctap2.credential_mgmt,
        6,
        p,
        v,
        proto.authenticate(tok, b"\x06" + cbor.encode(p)),
    )


def test_mac_covers_exact_platform_encoding(ctap2, setup):
    """Non-canonical but valid subCommandParams encodings are authenticated
    over the bytes actually sent (CTAP 2.1 §6.8.1)."""
    proto, c, mc, cm = setup
    mc("a.com", b"1", "alice")
    tok = c.get_pin_token("1234", PERM.CREDENTIAL_MGMT)
    h = sha256(b"a.com")
    sub_params = b"\xa1\x01\x58\x20" + h  # map{1: bytes(32)} canonical
    req = b"\xa4\x01\x04\x02" + sub_params + b"\x03" + bytes([proto.VERSION]) + b"\x04"
    mac = proto.authenticate(tok, b"\x04" + sub_params)
    req += bytes([0x50 if len(mac) == 16 else 0x58]) + (b"" if len(mac) == 16 else b"\x20") + mac
    resp = ctap2.device.call(0x10, b"\x0a" + req)
    assert resp[0] == 0
    # same params encoded with a non-minimal length (bytes head 0x59 0x0020)
    sub_params2 = b"\xa1\x01\x59\x00\x20" + h
    tok = c.get_pin_token("1234", PERM.CREDENTIAL_MGMT)
    mac = proto.authenticate(tok, b"\x04" + sub_params2)
    req = b"\xa4\x01\x04\x02" + sub_params2 + b"\x03" + bytes([proto.VERSION]) + b"\x04"
    req += bytes([0x50 if len(mac) == 16 else 0x58]) + (b"" if len(mac) == 16 else b"\x20") + mac
    assert ctap2.device.call(0x10, b"\x0a" + req)[0] == 0


def test_enumeration_state_invalidated(ctap2, setup):
    proto, c, mc, cm = setup
    mc("a.com", b"1", "alice")
    mc("b.org", b"2", "bob")
    mc("b.org", b"3", "carol")
    m = cm()
    expect(ERR.NOT_ALLOWED, m.enumerate_rps_next)
    expect(ERR.NOT_ALLOWED, m.enumerate_creds_next)
    first = m.enumerate_rps_begin()
    assert first[5] == 2
    ctap2.get_info()
    expect(ERR.NOT_ALLOWED, m.enumerate_rps_next)
    m.enumerate_rps_begin()
    m.enumerate_rps_next()
    expect(ERR.NOT_ALLOWED, m.enumerate_rps_next)
    m.enumerate_creds_begin(sha256(b"b.org"))
    expect(ERR.NOT_ALLOWED, m.enumerate_rps_next)  # other enumeration kind
    m.enumerate_creds_begin(sha256(b"b.org"))
    m.enumerate_creds_next()
    expect(ERR.NOT_ALLOWED, m.enumerate_creds_next)


def test_prototype_command_alias(ctap2, setup):
    proto, c, mc, cm = setup
    tok = c.get_pin_token("1234", PERM.CREDENTIAL_MGMT)
    resp = ctap2.send_cbor(0x41, {1: 1, 3: proto.VERSION, 4: proto.authenticate(tok, b"\x01")})
    assert resp == {1: 0, 2: 100}


def test_update_storage_full_maps(ctap2, setup, device, kv):
    proto, c, mc, cm = setup
    att = mc("a.com", b"1", "alice")
    cid = {"type": "public-key", "id": att.auth_data.credential_data.credential_id}
    m = cm()
    kv.capacity = kv.used_bytes()
    expect(ERR.KEY_STORE_FULL, m.update_user_info, cid, {"id": b"1", "name": "x" * 64})
