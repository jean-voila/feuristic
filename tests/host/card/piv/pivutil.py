# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Helpers for driving the PIV applet like a host tool would."""

import os

from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from feuristic.apps.card import apdu
from feuristic.apps.card.piv import consts
from feuristic.core import tlv

from ...aio import run

DEFAULT_KEY = consts.DEFAULT_MGMT_KEY
OK = 0x9000


def tx(applet, ins, p1=0, p2=0, data=b"", ne=0, cla=0):
    """Send one (already de-chained) command APDU; return the Response."""
    return run(applet.process(apdu.parse(apdu.build(cla, ins, p1, p2, data, ne))))


def select(applet, aid=consts.AID, p2=0):
    return run(applet.select(apdu.parse(apdu.build(0, 0xA4, 4, p2, aid, 256))))


def pad(pin: bytes) -> bytes:
    return pin + b"\xff" * (8 - len(pin))


def verify(applet, pin=b"123456"):
    return tx(applet, 0x20, 0, 0x80, pad(pin))


def dyn(*items) -> bytes:
    return tlv.build(0x7C, tlv.build_many(items))


def dyn_value(resp, tag=0x82) -> bytes:
    inner = tlv.find(resp.data, 0x7C)
    assert inner is not None, resp
    v = tlv.find(inner, tag)
    assert v is not None
    return v


def block_cipher(alg, key):
    if alg == consts.ALG_3DES:
        c = Cipher(TripleDES(key), modes.ECB())
        bs = 8
    else:
        c = Cipher(algorithms.AES(key), modes.ECB())
        bs = 16

    def enc(b):
        e = c.encryptor()
        return e.update(b) + e.finalize()

    def dec(b):
        d = c.decryptor()
        return d.update(b) + d.finalize()

    return enc, dec, bs


def mgmt_auth(applet, key=DEFAULT_KEY, alg=consts.ALG_AES192):
    """Mutual authentication with the administration key (yubico-piv-tool style)."""
    enc, dec, bs = block_cipher(alg, key)
    r = tx(applet, 0x87, alg, 0x9B, dyn((0x80, b"")))
    assert r.sw == OK, hex(r.sw)
    witness = dec(dyn_value(r, 0x80))
    challenge = os.urandom(bs)
    r = tx(applet, 0x87, alg, 0x9B, dyn((0x80, witness), (0x81, challenge)))
    assert r.sw == OK, hex(r.sw)
    assert dyn_value(r, 0x82) == enc(challenge)


def generate(applet, slot, alg=consts.ALG_P256, extra=b""):
    return tx(applet, 0x47, 0, slot, tlv.build(0xAC, tlv.build(0x80, bytes((alg,))) + extra), 256)


def ec_public(resp):
    """cryptography public key from a ``7F49 { 86 point }`` response."""
    point = tlv.find(tlv.find(resp.data, 0x7F49), 0x86)
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)


def sign(applet, slot, digest, alg=consts.ALG_P256):
    return tx(applet, 0x87, alg, slot, dyn((0x82, b""), (0x81, digest)), 256)


def verify_ecdsa(pub, der_sig, digest):
    pub.verify(der_sig, digest, ec.ECDSA(Prehashed(hashes.SHA256())))


def put_data(applet, tag: int, value: bytes):
    tag_b = tag.to_bytes(1 if tag <= 0xFF else 3, "big")
    return tx(applet, 0xDB, 0x3F, 0xFF, tlv.build(0x5C, tag_b) + tlv.build(0x53, value))


def get_data(applet, tag: int):
    tag_b = tag.to_bytes(1 if tag <= 0xFF else 3, "big")
    return tx(applet, 0xCB, 0x3F, 0xFF, tlv.build(0x5C, tag_b), 256)


def cert_object(der: bytes, info: int = 0) -> bytes:
    return tlv.build(0x70, der) + tlv.build(0x71, bytes((info,))) + tlv.build(0xFE, b"")
