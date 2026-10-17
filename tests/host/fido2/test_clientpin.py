# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""authenticatorClientPIN (protocols 1 and 2), pinUvAuthToken permissions,
retry counters and their interaction with makeCredential / getAssertion."""

import pytest
from ctap_harness import CDH, USER, descriptor, make, open_hid, sha256
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin, PinProtocolV1, PinProtocolV2
from fido2.webauthn import AuthenticatorData

ERR = CtapError.ERR
F = AuthenticatorData.FLAG
PERM = ClientPin.PERMISSION
PROTOCOLS = [PinProtocolV1, PinProtocolV2]


@pytest.fixture(params=PROTOCOLS, ids=["v1", "v2"])
def proto(request):
    return request.param()


def cp(ctap2, proto):
    return ClientPin(ctap2, proto)


def test_set_pin_and_retries(ctap2, proto, device):
    c = cp(ctap2, proto)
    assert c.get_pin_retries() == (8, False)
    c.set_pin("1234")
    assert ctap2.get_info().options["clientPin"] is True
    with pytest.raises(CtapError) as e:
        c.set_pin("5678")
    assert e.value.code == ERR.NOT_ALLOWED
    assert device.auth.state.pin_hash == sha256(b"1234")[:16]


def test_change_pin(ctap2, proto):
    c = cp(ctap2, proto)
    with pytest.raises(CtapError) as e:
        c.change_pin("1234", "5678")
    assert e.value.code == ERR.PIN_NOT_SET
    c.set_pin("1234")
    c.change_pin("1234", "abcdé")
    c.get_pin_token("abcdé", PERM.GET_ASSERTION, "example.com")
    with pytest.raises(CtapError) as e:
        c.change_pin("1234", "9999")
    assert e.value.code == ERR.PIN_INVALID


@pytest.mark.parametrize("pin", ["123", "", "x" * 64, "ééé"])
def test_pin_policy(ctap2, proto, pin):
    c = cp(ctap2, proto)
    with pytest.raises((CtapError, ValueError)) as e:
        c.set_pin(pin)
    if isinstance(e.value, CtapError):
        assert e.value.code == ERR.PIN_POLICY_VIOLATION


def test_pin_policy_unicode_code_points(ctap2, proto):
    c = cp(ctap2, proto)
    c.set_pin("éééé")  # 4 code points, 8 bytes
    c.get_pin_token("éééé")


def test_wrong_pin_counts_and_power_cycle(ctap2, proto, device):
    c = cp(ctap2, proto)
    c.set_pin("1234")
    for expected in (7, 6):
        with pytest.raises(CtapError) as e:
            c.get_pin_token("0000")
        assert e.value.code == ERR.PIN_INVALID
        assert c.get_pin_retries() == (expected, False)
    with pytest.raises(CtapError) as e:
        c.get_pin_token("0000")
    assert e.value.code == ERR.PIN_AUTH_BLOCKED
    assert c.get_pin_retries() == (5, True)
    # even the right PIN is refused until power cycle
    with pytest.raises(CtapError) as e:
        c.get_pin_token("1234")
    assert e.value.code == ERR.PIN_AUTH_BLOCKED
    assert c.get_pin_retries()[0] == 5
    device.power_cycle()
    c2 = cp(Ctap2(open_hid(device)), proto)
    assert c2.get_pin_retries() == (5, False)  # pinRetries persisted
    c2.get_pin_token("1234")
    assert c2.get_pin_retries() == (8, False)


def test_pin_blocked_after_8(ctap2, proto, device):
    c = cp(ctap2, proto)
    c.set_pin("1234")
    codes = []
    for _ in range(3):
        for _ in range(3):
            try:
                c.get_pin_token("0000")
            except CtapError as e:
                codes.append(e.code)
            if c.get_pin_retries()[0] == 0:
                break
        device.power_cycle()
        c = cp(Ctap2(open_hid(device)), proto)
    assert codes[-1] == ERR.PIN_BLOCKED
    assert c.get_pin_retries()[0] == 0
    with pytest.raises(CtapError) as e:
        c.get_pin_token("1234")
    assert e.value.code == ERR.PIN_BLOCKED
    with pytest.raises(CtapError) as e:
        c.change_pin("1234", "5678")
    assert e.value.code == ERR.PIN_BLOCKED


def test_retry_decremented_before_verification_power_loss(ctap2, proto, device, kv):
    """A power cut right after the decrement must not give the attempt back."""
    c = cp(ctap2, proto)
    c.set_pin("1234")
    from feuristic.platform.testing import PowerLoss

    ka, shared = c._get_shared_secret()
    pin_hash_enc = proto.encrypt(shared, sha256(b"1234")[:16])  # correct PIN
    kv.crash_after_ops = kv.ops + 2  # the decrement (delete + write), then crash
    with pytest.raises(PowerLoss):
        device.auth.pin.handle({1: proto.VERSION, 2: 5, 3: ka, 6: pin_hash_enc})
    device.power_cycle()
    assert device.auth.state.pin_retries == 7


def test_mismatch_regenerates_key_agreement(ctap2, proto):
    c = cp(ctap2, proto)
    c.set_pin("1234")
    ka1 = ctap2.client_pin(proto.VERSION, 2)[1]
    with pytest.raises(CtapError):
        c.get_pin_token("0000")
    ka2 = ctap2.client_pin(proto.VERSION, 2)[1]
    assert ka1 != ka2
    assert ka2[1] == 2 and ka2[3] == -25 and ka2[-1] == 1


def test_get_token_errors(ctap2, proto):
    c = cp(ctap2, proto)
    with pytest.raises(CtapError) as e:
        c.get_pin_token("1234")
    assert e.value.code == ERR.PIN_NOT_SET
    c.set_pin("1234")
    ka, shared = c._get_shared_secret()
    phe = proto.encrypt(shared, sha256(b"1234")[:16])
    v = proto.VERSION
    for params, code in [
        ({1: v, 2: 9, 3: ka, 6: phe}, ERR.MISSING_PARAMETER),
        ({1: v, 2: 9, 3: ka, 6: phe, 9: 0}, ERR.INVALID_PARAMETER),
        ({1: v, 2: 9, 3: ka, 6: phe, 9: PERM.BIO_ENROLL}, ERR.UNAUTHORIZED_PERMISSION),
        ({1: v, 2: 9, 3: ka, 6: phe, 9: PERM.AUTHENTICATOR_CFG}, ERR.UNAUTHORIZED_PERMISSION),
        ({1: v, 2: 9, 3: ka, 6: phe, 9: 0x80}, ERR.UNAUTHORIZED_PERMISSION),
        ({1: v, 2: 5, 3: ka, 6: phe, 9: 1}, ERR.INVALID_PARAMETER),
        ({1: v, 2: 5, 3: {1: 2}, 6: phe}, ERR.INVALID_PARAMETER),
        ({1: v, 2: 5, 3: {**ka, -2: b"\x01" * 32}, 6: phe}, ERR.INVALID_PARAMETER),
        ({1: v, 2: 5, 3: ka}, ERR.MISSING_PARAMETER),
        ({1: v, 2: 6, 3: ka}, ERR.INVALID_SUBCOMMAND),
        ({1: v, 2: 7}, ERR.INVALID_SUBCOMMAND),
        ({1: v, 2: 0x42}, ERR.INVALID_SUBCOMMAND),
        ({2: 2}, ERR.MISSING_PARAMETER),
        ({1: 3, 2: 2}, ERR.INVALID_PARAMETER),
        ({1: 3, 2: 1}, ERR.INVALID_PARAMETER),
        ({1: v}, ERR.MISSING_PARAMETER),
        ({1: v, 2: "x"}, ERR.CBOR_UNEXPECTED_TYPE),
        ({1: v, 2: 5, 3: "ka", 6: phe}, ERR.CBOR_UNEXPECTED_TYPE),
    ]:
        with pytest.raises(CtapError) as e:
            ctap2.send_cbor(0x06, params)
        assert e.value.code == code, params


def test_get_retries_without_protocol(ctap2):
    assert ctap2.send_cbor(0x06, {2: 1}) == {3: 8, 4: False}


def test_set_pin_bad_auth_and_lengths(ctap2, proto):
    c = cp(ctap2, proto)
    ka, shared = c._get_shared_secret()
    pin_enc = proto.encrypt(shared, b"1234".ljust(64, b"\0"))
    v = proto.VERSION
    with pytest.raises(CtapError) as e:
        ctap2.client_pin(v, 3, key_agreement=ka, new_pin_enc=pin_enc, pin_uv_param=b"\0" * 16)
    assert e.value.code == ERR.PIN_AUTH_INVALID
    short = proto.encrypt(shared, b"1234".ljust(32, b"\0"))
    with pytest.raises(CtapError) as e:
        ctap2.client_pin(
            v, 3, key_agreement=ka, new_pin_enc=short, pin_uv_param=proto.authenticate(shared, short)
        )
    assert e.value.code == ERR.INVALID_PARAMETER
    full = proto.encrypt(shared, b"1" * 64)  # no zero terminator: 64-byte PIN
    with pytest.raises(CtapError) as e:
        ctap2.client_pin(
            v, 3, key_agreement=ka, new_pin_enc=full, pin_uv_param=proto.authenticate(shared, full)
        )
    assert e.value.code == ERR.PIN_POLICY_VIOLATION
    bad_utf8 = proto.encrypt(shared, b"\xff\xfe\xfd\xfc".ljust(64, b"\0"))
    with pytest.raises(CtapError) as e:
        ctap2.client_pin(
            v, 3, key_agreement=ka, new_pin_enc=bad_utf8, pin_uv_param=proto.authenticate(shared, bad_utf8)
        )
    assert e.value.code == ERR.PIN_POLICY_VIOLATION
    with pytest.raises(CtapError) as e:
        ctap2.client_pin(v, 3, key_agreement=ka, new_pin_enc=pin_enc)
    assert e.value.code == ERR.MISSING_PARAMETER


def test_make_credential_with_token(ctap2, proto):
    c = cp(ctap2, proto)
    c.set_pin("1234")
    token = c.get_pin_token("1234", PERM.MAKE_CREDENTIAL, "example.com")
    att = make(ctap2, rk=True, pin_uv_param=proto.authenticate(token, CDH), pin_uv_protocol=proto.VERSION)
    assert att.auth_data.flags & F.UV
    # the mc permission was consumed by the first use (clear*Flags)
    with pytest.raises(CtapError) as e:
        make(ctap2, rk=True, pin_uv_param=proto.authenticate(token, CDH), pin_uv_protocol=proto.VERSION)
    assert e.value.code == ERR.PIN_AUTH_INVALID


def test_rk_requires_token_when_pin_set(ctap2, proto):
    c = cp(ctap2, proto)
    c.set_pin("1234")
    with pytest.raises(CtapError) as e:
        make(ctap2, rk=True)
    assert e.value.code == ERR.PUAT_REQUIRED
    att = make(ctap2)  # makeCredUvNotRqd: non-discoverable without PIN
    assert not att.auth_data.flags & F.UV


def test_token_rp_binding_and_permissions(ctap2, proto):
    c = cp(ctap2, proto)
    c.set_pin("1234")
    v = proto.VERSION
    token = c.get_pin_token("1234", PERM.MAKE_CREDENTIAL, "other.com")
    with pytest.raises(CtapError) as e:
        make(ctap2, pin_uv_param=proto.authenticate(token, CDH), pin_uv_protocol=v)
    assert e.value.code == ERR.PIN_AUTH_INVALID
    token = c.get_pin_token("1234", PERM.GET_ASSERTION, "example.com")
    with pytest.raises(CtapError) as e:  # ga token used for mc
        make(ctap2, pin_uv_param=proto.authenticate(token, CDH), pin_uv_protocol=v)
    assert e.value.code == ERR.PIN_AUTH_INVALID
    # token without RP ID gets bound by its first use
    token = c.get_pin_token("1234", PERM.MAKE_CREDENTIAL | PERM.GET_ASSERTION)
    att = make(ctap2, options={"up": True}, pin_uv_param=proto.authenticate(token, CDH), pin_uv_protocol=v)
    assert ctap2.get_assertion("example.com", CDH, [descriptor(att)]).auth_data.flags & F.UP


def test_token_wrong_protocol_or_mac(ctap2, proto):
    c = cp(ctap2, proto)
    c.set_pin("1234")
    token = c.get_pin_token("1234", PERM.MAKE_CREDENTIAL, "example.com")
    other = 1 if proto.VERSION == 2 else 2
    other_proto = PinProtocolV1() if other == 1 else PinProtocolV2()
    with pytest.raises(CtapError) as e:
        make(ctap2, pin_uv_param=other_proto.authenticate(token, CDH), pin_uv_protocol=other)
    assert e.value.code == ERR.PIN_AUTH_INVALID
    with pytest.raises(CtapError) as e:
        make(ctap2, pin_uv_param=proto.authenticate(token, b"x" * 32), pin_uv_protocol=proto.VERSION)
    assert e.value.code == ERR.PIN_AUTH_INVALID


def test_token_lifetime(ctap2, proto, device):
    c = cp(ctap2, proto)
    c.set_pin("1234")
    token = c.get_pin_token("1234", PERM.GET_ASSERTION, "example.com")
    att = make(ctap2)
    device.advance(31_000)  # initial usage time limit expired (unused token)
    with pytest.raises(CtapError) as e:
        ctap2.get_assertion(
            "example.com",
            CDH,
            [descriptor(att)],
            options={"up": False},
            pin_uv_param=proto.authenticate(token, CDH),
            pin_uv_protocol=proto.VERSION,
        )
    assert e.value.code == ERR.PIN_AUTH_INVALID
    # a token in use stays valid (silent up=false keeps permissions) until 10 min
    token = c.get_pin_token("1234", PERM.GET_ASSERTION, "example.com")
    kw = {
        "options": {"up": False},
        "pin_uv_param": proto.authenticate(token, CDH),
        "pin_uv_protocol": proto.VERSION,
    }
    a = ctap2.get_assertion("example.com", CDH, [descriptor(att)], **kw)
    assert a.auth_data.flags & F.UV and not a.auth_data.flags & F.UP
    device.advance(300_000)
    ctap2.get_assertion("example.com", CDH, [descriptor(att)], **kw)
    device.advance(301_000)
    with pytest.raises(CtapError):
        ctap2.get_assertion("example.com", CDH, [descriptor(att)], **kw)


def test_legacy_get_pin_token(ctap2, proto):
    c = cp(ctap2, proto)
    c.set_pin("1234")
    token = c.get_pin_token("1234")  # subcommand 0x05: mc | ga
    make(ctap2, rk=True, pin_uv_param=proto.authenticate(token, CDH), pin_uv_protocol=proto.VERSION)


def test_change_pin_invalidates_token(ctap2, proto):
    c = cp(ctap2, proto)
    c.set_pin("1234")
    token = c.get_pin_token("1234", PERM.MAKE_CREDENTIAL, "example.com")
    c.change_pin("1234", "4321")
    with pytest.raises(CtapError) as e:
        make(ctap2, pin_uv_param=proto.authenticate(token, CDH), pin_uv_protocol=proto.VERSION)
    assert e.value.code == ERR.PIN_AUTH_INVALID


def test_change_pin_bad_mac_does_not_consume_retry(ctap2, proto):
    c = cp(ctap2, proto)
    c.set_pin("1234")
    ka, shared = c._get_shared_secret()
    phe = proto.encrypt(shared, sha256(b"1234")[:16])
    npe = proto.encrypt(shared, b"5678".ljust(64, b"\0"))
    with pytest.raises(CtapError) as e:
        ctap2.client_pin(
            proto.VERSION,
            4,
            key_agreement=ka,
            pin_hash_enc=phe,
            new_pin_enc=npe,
            pin_uv_param=b"\0" * proto_len(proto),
        )
    assert e.value.code == ERR.PIN_AUTH_INVALID
    assert c.get_pin_retries()[0] == 8


def proto_len(proto):
    return 16 if proto.VERSION == 1 else 32


def test_zero_length_pin_uv_auth_param(ctap2, ui):
    with pytest.raises(CtapError) as e:
        make(ctap2, pin_uv_param=b"", pin_uv_protocol=1)
    assert e.value.code == ERR.PIN_NOT_SET
    assert ui.kinds()[-1] == "fido2.selection"
    ClientPin(ctap2).set_pin("1234")
    with pytest.raises(CtapError) as e:
        ctap2.get_assertion("example.com", CDH, pin_uv_param=b"", pin_uv_protocol=2)
    assert e.value.code == ERR.PIN_INVALID
    ui.push(False)
    with pytest.raises(CtapError) as e:
        make(ctap2, pin_uv_param=b"")
    assert e.value.code == ERR.OPERATION_DENIED


def test_user_entity_pii_only_with_uv(ctap2, proto):
    c = cp(ctap2, proto)
    c.set_pin("1234")
    token = c.get_pin_token("1234", PERM.MAKE_CREDENTIAL, "example.com")
    make(ctap2, rk=True, pin_uv_param=proto.authenticate(token, CDH), pin_uv_protocol=proto.VERSION)
    token = c.get_pin_token("1234", PERM.GET_ASSERTION, "example.com")
    a = ctap2.get_assertion(
        "example.com", CDH, pin_uv_param=proto.authenticate(token, CDH), pin_uv_protocol=proto.VERSION
    )
    assert a.user == USER
    assert a.auth_data.flags & F.UV


def test_local_pin_management(device):
    from feuristic.apps.fido2 import localmgmt
    from feuristic.core.errors import InvalidInput, PinBlocked, PinInvalid, PolicyDenied

    auth = device.auth
    assert localmgmt.pin_status(auth) == (False, 8)
    with pytest.raises(InvalidInput):
        localmgmt.set_pin(auth, "12")
    with pytest.raises(PolicyDenied):
        localmgmt.change_pin(auth, "1234", "5678")
    localmgmt.set_pin(auth, "1234")
    with pytest.raises(PolicyDenied):
        localmgmt.set_pin(auth, "9999")
    with pytest.raises(PinInvalid) as e:
        localmgmt.change_pin(auth, "0000", "5678")
    assert e.value.retries == 7
    localmgmt.change_pin(auth, "1234", "5678")
    assert localmgmt.pin_status(auth) == (True, 8)
    with pytest.raises(InvalidInput):
        localmgmt.change_pin(auth, "5678", "1")
    for _ in range(7):
        with pytest.raises(PinInvalid):
            localmgmt.change_pin(auth, "0000", "1111")
    with pytest.raises(PinBlocked):
        localmgmt.change_pin(auth, "0000", "1111")
    with pytest.raises(PinBlocked):
        localmgmt.change_pin(auth, "5678", "1111")
    with pytest.raises(InvalidInput):
        auth.pin.local_set_pin(5)
