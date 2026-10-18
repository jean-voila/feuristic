# SPDX-License-Identifier: GPL-3.0-only
"""R02/R03 (emulated): FIDO2 over the emulated USB HID interface."""

import threading

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2.cose import ES256
from fido2.ctap2 import Ctap2
from harness.emulator import PORT_FIDO
from harness.fido import open_device

RP = {"id": "example.com", "name": "Example"}
USER = {"id": b"user-1", "name": "alice", "displayName": "Alice"}
CDH = b"\x11" * 32


def _confirm_when_shown(debug, stop, presses=1):
    """Approve on-device confirmation screens while a CTAP call is pending."""
    done = 0
    while not stop.is_set() and done < presses:
        s = debug.screen()
        if s.title not in ("", "feuristic") and s.component != "PinKeyboard":
            debug.approve()
            done += 1
        stop.wait(0.3)


def _run_with_approval(debug, fn, presses=1):
    stop = threading.Event()
    t = threading.Thread(target=_confirm_when_shown, args=(debug, stop, presses), daemon=True)
    t.start()
    try:
        return fn()
    finally:
        stop.set()
        t.join(5)


@pytest.fixture
def ctap(ready, emu):
    dev = open_device(emu.port(PORT_FIDO))
    yield Ctap2(dev)
    dev.close()


def test_get_info(ctap):
    info = ctap.info
    assert "FIDO_2_1" in info.versions
    assert "U2F_V2" in info.versions
    assert set(info.extensions) >= {"credProtect", "hmac-secret", "largeBlobKey"}
    assert info.options["rk"] is True
    assert info.options.get("credMgmt") is True
    assert "uv" not in info.options


def test_make_credential_and_assert(ctap, ready):
    att = _run_with_approval(
        ready,
        lambda: ctap.make_credential(CDH, RP, USER, [{"type": "public-key", "alg": ES256.ALGORITHM}]),
    )
    cred = att.auth_data.credential_data
    assert cred is not None
    pub = ES256(cred.public_key)
    assert att.fmt in ("packed", "none")

    assertion = _run_with_approval(
        ready,
        lambda: ctap.get_assertion(RP["id"], CDH, [{"type": "public-key", "id": cred.credential_id}]),
    )
    pub.verify(assertion.auth_data + CDH, assertion.signature)


def test_user_refusal_is_operation_denied(ctap, ready):
    from fido2.ctap import CtapError

    def refuse():
        stop = threading.Event()

        def run():
            while not stop.is_set():
                s = ready.screen()
                if s.title not in ("", "feuristic"):
                    ready.hold_left()  # long press left = back/refuse
                    return
                stop.wait(0.3)

        t = threading.Thread(target=run, daemon=True)
        t.start()
        try:
            ctap.make_credential(CDH, RP, USER, [{"type": "public-key", "alg": ES256.ALGORITHM}])
        finally:
            stop.set()

    with pytest.raises(CtapError) as e:
        refuse()
    assert e.value.code in (CtapError.ERR.OPERATION_DENIED, CtapError.ERR.USER_ACTION_TIMEOUT)


def test_signature_with_cryptography_verification(ctap, ready):
    att = _run_with_approval(
        ready,
        lambda: ctap.make_credential(
            CDH, RP, USER, [{"type": "public-key", "alg": ES256.ALGORITHM}], options={"rk": True}
        ),
    )
    cpk = att.auth_data.credential_data.public_key
    key = ec.EllipticCurvePublicNumbers(
        int.from_bytes(cpk[-2], "big"), int.from_bytes(cpk[-3], "big"), ec.SECP256R1()
    ).public_key()
    a = _run_with_approval(ready, lambda: ctap.get_assertion(RP["id"], CDH))
    key.verify(a.signature, a.auth_data + CDH, ec.ECDSA(hashes.SHA256()))
