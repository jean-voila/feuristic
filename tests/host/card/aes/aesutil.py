# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Helpers for driving the AES profile like the documented host client."""

from feuristic.apps.card import apdu
from feuristic.core import tlv

from ...aio import run

AID = bytes.fromhex("F066657572697374696301")


def tx(applet, ins, p1=0, p2=0, data=b"", ne=0, cla=0):
    return run(applet.process(apdu.parse(apdu.build(cla, ins, p1, p2, data, ne))))


def select(applet, p2=0):
    return run(applet.select(apdu.parse(apdu.build(0, 0xA4, 4, p2, AID, 256))))


def mse(applet, kid, p1=0x81, alg=True, ref_tag=0x83):
    data = (tlv.build(0x80, b"\x47") if alg else b"") + tlv.build(ref_tag, bytes((kid,)))
    return tx(applet, 0x22, p1, 0xB8, data)


def encipher(applet, pt, aad=None):
    data = (tlv.build(0x81, aad) if aad is not None else b"") + tlv.build(0x80, pt)
    return tx(applet, 0x2A, 0x84, 0x80, data, 256 if len(pt) < 200 else 65536)


def decipher_data(nonce, ct, tag, aad=None):
    return (
        (tlv.build(0x81, aad) if aad is not None else b"")
        + tlv.build(0x82, nonce)
        + tlv.build(0x80, ct)
        + tlv.build(0x83, tag)
    )


def decipher(applet, nonce, ct, tag, aad=None):
    return tx(applet, 0x2A, 0x80, 0x84, decipher_data(nonce, ct, tag, aad), 65536)


def split(resp):
    """``(nonce, ciphertext, tag)`` of an ENCIPHER response (strict order 82, 80, 83)."""
    items = tlv.parse(resp.data)
    assert [t for t, _ in items] == [0x82, 0x80, 0x83]
    return items[0][1], items[1][1], items[2][1]


def challenge(applet, le):
    return tx(applet, 0x84, 0, 0, b"", le)
