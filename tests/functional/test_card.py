# SPDX-License-Identifier: GPL-3.0-only
"""R09/R10/R11 (emulated): CCID reader with OpenPGP, PIV and GET CHALLENGE."""

import threading

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from harness.ccid import CcidClient
from harness.emulator import PORT_CCID

OPENPGP_AID = bytes.fromhex("D27600012401")
PIV_AID = bytes.fromhex("A000000308")


def apdu(cla, ins, p1, p2, data=b"", le=None):
    out = bytes([cla, ins, p1, p2])
    if data:
        out += bytes([len(data)]) + data
    if le is not None:
        out += bytes([le & 0xFF])
    return out


def _approver(debug, stop):
    while not stop.is_set():
        s = debug.screen()
        if s.title not in ("", "feuristic") and s.component != "PinKeyboard":
            debug.approve()
        stop.wait(0.3)


@pytest.fixture
def card(ready, emu):
    c = CcidClient(emu.port(PORT_CCID))
    yield c
    c.close()


@pytest.fixture
def approving(ready):
    stop = threading.Event()
    t = threading.Thread(target=_approver, args=(ready, stop), daemon=True)
    t.start()
    yield
    stop.set()
    t.join(5)


def test_power_on_atr(card):
    atr = card.power_on()
    assert atr[0] == 0x3B
    assert len(atr) >= 10


def test_get_challenge_without_selection(card):
    card.power_on()
    data, sw = card.transmit(apdu(0x00, 0x84, 0, 0, le=32))
    assert sw == 0x9000 and len(data) == 32
    data2, _ = card.transmit(apdu(0x00, 0x84, 0, 0, le=32))
    assert data != data2
    _, sw = card.transmit(apdu(0x00, 0x84, 0, 0, le=33))
    assert sw in (0x6C20, 0x6700)


def test_openpgp_select_and_get_data(card):
    card.power_on()
    _, sw = card.transmit(apdu(0x00, 0xA4, 0x04, 0x00, OPENPGP_AID))
    assert sw == 0x9000
    aid, sw = card.transmit(apdu(0x00, 0xCA, 0x00, 0x4F, le=0))
    assert sw == 0x9000 and aid.startswith(OPENPGP_AID + b"\x03\x04")
    ard, sw = card.transmit(apdu(0x00, 0xCA, 0x00, 0x6E, le=0))
    assert sw == 0x9000 and len(ard) > 50


def test_openpgp_generate_and_sign_ed25519(card, approving):
    card.power_on()
    card.transmit(apdu(0x00, 0xA4, 0x04, 0x00, OPENPGP_AID))
    _, sw = card.transmit(apdu(0x00, 0x20, 0x00, 0x83, b"12345678"))  # admin PIN
    assert sw == 0x9000
    pub, sw = card.transmit(apdu(0x00, 0x47, 0x80, 0x00, bytes.fromhex("B600"), le=0))
    assert sw == 0x9000, hex(sw)
    # 7F49 { 86 <32-byte Ed25519 key> }
    i = pub.index(b"\x86")
    key = pub[i + 2 : i + 2 + pub[i + 1]]
    assert len(key) == 32
    _, sw = card.transmit(apdu(0x00, 0x20, 0x00, 0x81, b"123456"))  # PW1 for signing
    assert sw == 0x9000
    digest = bytes(range(32))
    sig, sw = card.transmit(apdu(0x00, 0x2A, 0x9E, 0x9A, digest, le=0))
    assert sw == 0x9000, hex(sw)
    Ed25519PublicKey.from_public_bytes(key).verify(sig, digest)


def test_piv_select(card):
    card.power_on()
    data, sw = card.transmit(apdu(0x00, 0xA4, 0x04, 0x00, PIV_AID))
    assert sw == 0x9000
    assert data[:1] == b"\x61"
