# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""OpenSC- and yubico-piv-tool-like APDU sequences through the card dispatcher."""

import hashlib
import os

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from feuristic.apps.card.piv import consts
from feuristic.core import tlv

from ...aio import run
from .pivutil import DEFAULT_KEY, block_cipher, ec_public, verify_ecdsa
from .test_keys import pkcs1_v15_sha256, restore_rsa

dispatcher_mod = pytest.importorskip("feuristic.apps.card.dispatcher")
H = bytes.fromhex


class Reader:
    """Minimal PC/SC-like client: short APDUs, chaining and GET RESPONSE."""

    def __init__(self, applets):
        self.d = dispatcher_mod.Dispatcher(applets)
        self.d.raise_unexpected = True

    def raw(self, apdu_bytes: bytes):
        rsp = run(self.d.transmit(apdu_bytes))
        return rsp[:-2], int.from_bytes(rsp[-2:], "big")

    def send(self, cla, ins, p1, p2, data=b"", le=0x00, use_le=True):
        """Send with command chaining (255-byte parts) and collect 61xx."""
        parts = [data[i : i + 255] for i in range(0, len(data), 255)] or [b""]
        for i, part in enumerate(parts):
            last = i == len(parts) - 1
            c = cla | (0 if last else 0x10)
            apdu = bytes((c, ins, p1, p2))
            if part:
                apdu += bytes((len(part),)) + part
            if last and use_le:
                apdu += bytes((le,))
            out, sw = self.raw(apdu)
            if not last:
                assert sw == 0x9000, hex(sw)
        buf = out
        while sw >> 8 == 0x61:
            out, sw = self.raw(bytes((0x00, 0xC0, 0, 0, sw & 0xFF)))
            buf += out
        return buf, sw


@pytest.fixture
def reader(piv):
    return Reader([piv])


def ga_admin(reader, key=DEFAULT_KEY, alg=consts.ALG_AES192):
    enc, dec, bs = block_cipher(alg, key)
    data, sw = reader.send(0, 0x87, alg, 0x9B, H("7C028000"))
    assert sw == 0x9000
    witness = dec(tlv.find(tlv.find(data, 0x7C), 0x80))
    chal = os.urandom(bs)
    body = tlv.build(0x80, witness) + tlv.build(0x81, chal)
    data, sw = reader.send(0, 0x87, alg, 0x9B, tlv.build(0x7C, body))
    assert sw == 0x9000
    assert tlv.find(tlv.find(data, 0x7C), 0x82) == enc(chal)


def test_opensc_detection_sequence(reader):
    """What `pkcs15-tool --list-certificates` / `opensc-tool -n` roughly send."""
    data, sw = reader.send(0, 0xA4, 0x04, 0x00, H("A000000308"))
    assert sw == 0x9000 and data[0] == 0x61
    data, sw = reader.send(0, 0xCB, 0x3F, 0xFF, H("5C017E"))
    assert sw == 0x9000 and data.startswith(H("7E12"))
    data, sw = reader.send(0, 0xCB, 0x3F, 0xFF, H("5C035FC102"))
    assert sw == 0x9000 and data[0] == 0x53
    for obj in ("5FC105", "5FC10A", "5FC10B", "5FC101"):
        _, sw = reader.send(0, 0xCB, 0x3F, 0xFF, H("5C03" + obj))
        assert sw == 0x6A82
    _, sw = reader.send(0, 0x20, 0x00, 0x80, b"", use_le=False)
    assert sw == 0x63C3


def test_yubico_piv_tool_generate_certify_sign(reader, piv, ui):
    # ykpiv_connect: SELECT, GET VERSION, GET SERIAL
    reader.send(0, 0xA4, 0x04, 0x00, consts.AID)
    assert reader.send(0, 0xFD, 0, 0) == (H("050700"), 0x9000)
    serial, sw = reader.send(0, 0xF8, 0, 0)
    assert sw == 0x9000 and len(serial) == 4
    # newer tools ask for the management key algorithm
    md, sw = reader.send(0, 0xF7, 0, 0x9B)
    assert tlv.find(md, 0x01) == b"\x0a"
    ga_admin(reader)
    # -a generate -s 9a -A ECCP256
    data, sw = reader.send(0, 0x47, 0x00, 0x9A, H("AC03800111"))
    assert sw == 0x9000

    class R:
        pass

    resp = R()
    resp.data = data
    pub = ec_public(resp)
    # -a import-certificate (2 KiB certificate: needs command chaining)
    cert = os.urandom(2000)
    body = tlv.build(0x5C, H("5FC105")) + tlv.build(0x53, tlv.build(0x70, cert) + H("710100FE00"))
    _, sw = reader.send(0, 0xDB, 0x3F, 0xFF, body, use_le=False)
    assert sw == 0x9000
    # read it back (response chaining)
    data, sw = reader.send(0, 0xCB, 0x3F, 0xFF, H("5C035FC105"))
    assert sw == 0x9000 and tlv.find(tlv.find(data, 0x53), 0x70) == cert
    # -a verify-pin -a sign
    _, sw = reader.send(0, 0x20, 0x00, 0x80, b"123456\xff\xff", use_le=False)
    assert sw == 0x9000
    digest = hashlib.sha256(b"yubico").digest()
    data, sw = reader.send(0, 0x87, 0x11, 0x9A, H("7C24 8200 8120".replace(" ", "")) + digest)
    assert sw == 0x9000
    verify_ecdsa(pub, tlv.find(tlv.find(data, 0x7C), 0x82), digest)
    assert ui.kinds()[-1] == "piv.sign"


def test_rsa_signature_response_chaining(reader, piv, store, rsa_private_key):
    restore_rsa(store, rsa_private_key)
    reader.send(0, 0xA4, 0x04, 0x00, consts.AID)
    reader.send(0, 0x20, 0x00, 0x80, b"123456\xff\xff", use_le=False)
    block = pkcs1_v15_sha256(b"chained")
    body = tlv.build(0x7C, H("8200") + tlv.build(0x81, block))
    assert len(body) > 255  # needs command chaining with short APDUs
    data, sw = reader.send(0, 0x87, 0x07, 0x9A, body)
    assert sw == 0x9000
    sig = tlv.find(tlv.find(data, 0x7C), 0x82)
    rsa_private_key.public_key().verify(sig, b"chained", padding.PKCS1v15(), hashes.SHA256())


def test_extended_apdu_rsa(reader, piv, store, rsa_private_key):
    restore_rsa(store, rsa_private_key)
    reader.send(0, 0xA4, 0x04, 0x00, consts.AID)
    reader.send(0, 0x20, 0x00, 0x80, b"123456\xff\xff", use_le=False)
    from feuristic.apps.card import apdu

    body = tlv.build(0x7C, H("8200") + tlv.build(0x81, pkcs1_v15_sha256(b"ext")))
    out, sw = reader.raw(apdu.build(0, 0x87, 0x07, 0x9A, body, 65536))
    assert sw == 0x9000 and len(tlv.find(tlv.find(out, 0x7C), 0x82)) == 256


def test_selecting_another_applet_drops_pin(reader, piv):
    from feuristic.apps.card.aes.applet import AesApplet

    r = Reader([piv, AesApplet(piv.ui, master_secret=bytes(32))])
    r.send(0, 0xA4, 0x04, 0x00, consts.AID)
    r.send(0, 0x20, 0x00, 0x80, b"123456\xff\xff", use_le=False)
    assert piv.pin_verified
    r.send(0, 0xA4, 0x04, 0x00, H("F066657572697374696301"))
    assert not piv.pin_verified


def test_card_reset_drops_state(reader, piv):
    reader.send(0, 0xA4, 0x04, 0x00, consts.AID)
    ga_admin(reader)
    reader.d.reset()
    assert not piv.mgmt_authenticated
