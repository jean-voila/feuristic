# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""FIDO U2F (CTAP1) over CTAPHID_MSG, verified with python-fido2's Ctap1 and
the ``cryptography`` package."""

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from ctap_harness import (
    CDH,
    EDDSA,
    aio_run,
    allocate_channel,
    descriptor,
    frames,
    make,
    parse_response,
    sha256,
)
from fido2.cose import ES256 as COSE_ES256
from fido2.ctap import CtapError
from fido2.ctap1 import ApduError, Ctap1, RegistrationData, SignatureData
from fido2.ctap2 import AssertionResponse

from feuristic.apps.fido2 import ctap1 as u2fmod
from feuristic.apps.fido2 import x509 as fx

APP = sha256(b"https://example.com")
CHAL = sha256(b"challenge")


def poll(fn, attempts=5):
    """Browsers re-send U2F requests while the device answers 6985."""
    for _ in range(attempts):
        try:
            return fn()
        except ApduError as e:
            if e.code != 0x6985:
                raise
    raise AssertionError("user presence never granted")


@pytest.fixture
def u2f(hid):
    return Ctap1(hid)


def register(u2f, app=APP):
    return poll(lambda: u2f.register(CHAL, app))


def test_version(u2f):
    assert u2f.get_version() == "U2F_V2"


def test_register_and_authenticate(u2f, ui):
    reg = register(u2f)
    assert isinstance(reg, RegistrationData)
    reg.verify(APP, CHAL)  # signature by the attestation certificate key
    assert len(reg.key_handle) == 61
    assert ui.kinds() == ["fido2.u2f_register"]
    sig = poll(lambda: u2f.authenticate(CHAL, APP, reg.key_handle))
    sig.verify(APP, CHAL, reg.public_key)
    assert sig.user_presence == 1
    sig2 = poll(lambda: u2f.authenticate(CHAL, APP, reg.key_handle))
    assert sig2.counter > sig.counter
    assert ui.kinds()[-1] == "fido2.u2f_authenticate"


def test_attestation_certificate_is_self_signed_credential_key(u2f):
    reg = register(u2f)
    cert = x509.load_der_x509_certificate(reg.certificate)
    assert cert.version == x509.Version.v3
    assert cert.subject == cert.issuer
    cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    assert cn == "feuristic self attestation"
    assert (
        "Trezor" not in cert.subject.rfc4514_string() and "SatoshiLabs" not in cert.subject.rfc4514_string()
    )
    pub = cert.public_key()
    assert isinstance(pub, ec.EllipticCurvePublicKey)
    raw = pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    assert raw == reg.public_key  # self attestation: no cross-RP identifier
    pub.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.critical and bc.value.ca is False
    assert cert.serial_number > 0
    # two registrations: different keys, different certificates
    reg2 = register(u2f)
    assert reg2.certificate != reg.certificate


def test_check_only_and_wrong_app(u2f):
    reg = register(u2f)
    with pytest.raises(ApduError) as e:
        u2f.authenticate(CHAL, APP, reg.key_handle, check_only=True)
    assert e.value.code == 0x6985
    with pytest.raises(ApduError) as e:
        u2f.authenticate(CHAL, sha256(b"other"), reg.key_handle, check_only=True)
    assert e.value.code == 0x6A80
    bad = bytearray(reg.key_handle)
    bad[30] ^= 1
    with pytest.raises(ApduError) as e:
        u2f.authenticate(CHAL, APP, bytes(bad))
    assert e.value.code == 0x6A80


def test_dont_enforce_user_presence(u2f, ui):
    reg = register(u2f)
    n = len(ui.prompts)
    data = CHAL + APP + bytes((len(reg.key_handle),)) + reg.key_handle
    resp = u2f.send_apdu(ins=0x02, p1=0x08, data=data)
    assert resp[0] == 0
    SignatureData(resp).verify(APP, CHAL, reg.public_key)
    assert len(ui.prompts) == n
    with pytest.raises(ApduError) as e:
        u2f.send_apdu(ins=0x02, p1=0x05, data=data)
    assert e.value.code == 0x6A80


def test_apdu_errors(u2f):
    for kw, sw in [
        ({"cla": 1, "ins": 3}, 0x6E00),
        ({"ins": 0x10}, 0x6D00),
        ({"ins": 3, "data": b"x"}, 0x6700),
        ({"ins": 1, "data": b"x" * 63}, 0x6700),
        ({"ins": 2, "data": b"x" * 64}, 0x6700),
        ({"ins": 2, "data": b"x" * 64 + b"\x05" + b"k" * 4}, 0x6700),
    ]:
        with pytest.raises(ApduError) as e:
            u2f.send_apdu(**kw)
        assert e.value.code == sw, kw


def test_apdu_parsing_forms():
    assert u2fmod.parse_apdu(b"\x00\x03\x00\x00") == (0, 3, 0, 0, b"")
    assert u2fmod.parse_apdu(b"\x00\x03\x00\x00\x00") == (0, 3, 0, 0, b"")  # short Le
    assert u2fmod.parse_apdu(b"\x00\x03\x00\x00\x00\x00\x00") == (0, 3, 0, 0, b"")  # extended Le
    assert u2fmod.parse_apdu(b"\x00\x01\x00\x00\x02ab") == (0, 1, 0, 0, b"ab")  # short Lc
    assert u2fmod.parse_apdu(b"\x00\x01\x00\x00\x02ab\x00") == (0, 1, 0, 0, b"ab")
    assert u2fmod.parse_apdu(b"\x00\x01\x00\x00\x00\x00\x02ab\x00\x00") == (0, 1, 0, 0, b"ab")
    for bad in (
        b"\x00\x01",
        b"\x00\x01\x00\x00\x05ab",
        b"\x00\x01\x00\x00\x00\x00\x05ab",
        b"\x00\x01\x00\x00\x02abcd",
    ):
        with pytest.raises(u2fmod.ApduError) as e:
            u2fmod.parse_apdu(bad)
        assert e.value.sw == 0x6700


def raw_msg(device, cid, apdu):
    for p in frames(cid, 0x03, apdu):
        device.write(p)
    out = []
    while not out or len(parse_response(out)[2]) < ((out[0][5] << 8) | out[0][6]):
        out.append(device.read())
    return parse_response(out)


def test_declined_registration_stops_polling(device, ui):
    cid = allocate_channel(device)
    apdu = b"\x00\x01\x03\x00\x00\x00\x40" + CHAL + APP + b"\x00\x00"
    ui.push(False)
    assert raw_msg(device, cid, apdu)[2] == b"\x69\x85"
    device.run_until_idle()  # the glue runs the dialog: refused
    rcid, cmd, data = raw_msg(device, cid, apdu)
    assert (cmd, data) == (0x3F, b"\x06")  # CTAPHID ERROR CHANNEL_BUSY
    # a different request starts a new dialog
    other = b"\x00\x01\x03\x00\x00\x00\x40" + sha256(b"c2") + APP + b"\x00\x00"
    assert raw_msg(device, cid, other)[2] == b"\x69\x85"
    device.run_until_idle()


def test_dialog_pending_blocks_other_requests_and_goes_stale(device, ui):
    u2f = device.app.u2f
    cmd, payload = u2f.handle(b"\x00\x01\x03\x00\x00\x00\x40" + CHAL + APP)
    assert payload == b"\x69\x85" and u2f.dialog_pending()
    cmd, payload = u2f.handle(b"\x00\x01\x03\x00\x00\x00\x40" + sha256(b"x") + APP)
    assert payload == b"\x69\x85"
    job = u2f.dialog_job()
    assert u2f.dialog_job() is None
    assert not u2f.dialog_stale()
    device.advance(3_000)
    assert u2f.dialog_stale()
    job.close()
    # once stale, a new request replaces the dialog
    u2f.handle(b"\x00\x01\x03\x00\x00\x00\x40" + sha256(b"y") + APP)
    assert u2f.dialog_pending()


def test_ctap2_command_resets_u2f_latch(device, u2f, ctap2):
    with pytest.raises(ApduError):
        u2f.register(CHAL, APP)
    ctap2.get_info()
    assert not device.app.u2f.dialog_pending()


@pytest.mark.parametrize("bogus", u2fmod.BOGUS_APPIDS)
def test_bogus_register(u2f, ui, bogus, device):
    device.auth.last_auth_valid = bogus == u2fmod.BOGUS_APPIDS[0]
    reg = register(u2f, bogus)
    reg.verify(bogus, CHAL)
    assert ui.kinds() == ["fido2.u2f_bogus"]
    expected = (
        "fido2.title.already_registered" if device.auth.last_auth_valid else "fido2.title.not_registered"
    )
    assert ui.prompts[0].title == expected


def test_u2f_dialog_timeout_and_cancel(device, ui):
    u2f = device.app.u2f
    for answer in ("timeout",):
        ui.push(answer)
        u2f.handle(b"\x00\x01\x03\x00\x00\x00\x40" + CHAL + APP)
        aio_run(u2f.dialog_job())
        assert u2f.handle(b"\x00\x01\x03\x00\x00\x00\x40" + CHAL + APP) == (0x3F, b"\x06")


def test_ctap2_credential_via_u2f(ctap2, u2f):
    app = sha256(b"example.com")
    att = make(ctap2)
    cid = descriptor(att)["id"]
    sig = poll(lambda: u2f.authenticate(CHAL, app, cid))
    pk = att.auth_data.credential_data.public_key
    raw = b"\x04" + pk[-2] + pk[-3]
    sig.verify(app, CHAL, raw)
    assert isinstance(pk, COSE_ES256)
    eddsa = make(ctap2, algs=(EDDSA,))
    with pytest.raises(ApduError) as e:
        u2f.authenticate(CHAL, app, descriptor(eddsa)["id"], check_only=True)
    assert e.value.code == 0x6A80
    rk = make(ctap2, rk=True)
    with pytest.raises(ApduError) as e:
        u2f.authenticate(CHAL, app, descriptor(rk)["id"], check_only=True)
    assert e.value.code == 0x6985


def test_u2f_key_handle_via_ctap2(ctap2, u2f):
    app_id = "https://legacy.example.com/appid.json"
    reg = register(u2f, sha256(app_id.encode()))
    a = ctap2.get_assertion(app_id, CDH, [{"type": "public-key", "id": reg.key_handle}])
    assert a.credential["id"] == reg.key_handle
    assert not a.auth_data.flags & 0x08  # not backup eligible
    AssertionResponse.verify(a, CDH, COSE_ES256.from_ctap1(reg.public_key))
    # U2F key handles are bound to their application parameter
    with pytest.raises(CtapError):
        ctap2.get_assertion("example.com", CDH, [{"type": "public-key", "id": reg.key_handle}])


def test_x509_builder_bounds():
    with pytest.raises(ValueError):
        fx.tbs_certificate(b"\x04" + b"\x00" * 10)
    with pytest.raises(ValueError):
        fx._len(70000)
    assert fx._len(5) == b"\x05" and fx._len(200) == b"\x81\xc8" and fx._len(300) == b"\x82\x01\x2c"
    assert fx.der_uint(b"\x00\x00") == b"\x02\x01\x00"
    assert fx.der_uint(b"\x80") == b"\x02\x02\x00\x80"
