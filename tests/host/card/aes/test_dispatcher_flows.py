# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""The annex's host client flow through the card dispatcher (chaining, GET RESPONSE)."""

import os

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from feuristic.apps.card.aes import applet as aes_mod
from feuristic.apps.card.aes import rng
from feuristic.core import tlv

from ...aio import run
from .aesutil import AID

dispatcher_mod = pytest.importorskip("feuristic.apps.card.dispatcher")


class Client:
    """Short-APDU client implementing docs/protocols/aes-gcm-iso7816-v1.md §9."""

    def __init__(self, d):
        self.d = d

    def raw(self, a):
        r = run(self.d.transmit(a))
        return r[:-2], int.from_bytes(r[-2:], "big")

    def send(self, ins, p1, p2, data=b""):
        parts = [data[i : i + 255] for i in range(0, len(data), 255)] or [b""]
        for i, part in enumerate(parts):
            last = i == len(parts) - 1
            a = bytes((0x00 if last else 0x10, ins, p1, p2))
            if part:
                a += bytes((len(part),)) + part
            if last:
                a += b"\x00"
            out, sw = self.raw(a)
            if not last:
                assert sw == 0x9000
        buf = out
        while sw >> 8 == 0x61:
            out, sw = self.raw(bytes((0x00, 0xC0, 0, 0, sw & 0xFF)))
            buf += out
        return buf, sw


@pytest.fixture
def client(aes, service):
    d = dispatcher_mod.Dispatcher([aes], fallback=rng.RngApplet(service=service))
    d.raise_unexpected = True
    return Client(d)


def test_full_flow_fragmented_up_to_the_limit(client, key1):
    assert client.send(0xA4, 0x04, 0x00, AID)[1] == 0x9000
    assert client.send(0x22, 0xF1, 0xB8, bytes.fromhex("800147830101"))[1] == 0x9000
    aad = os.urandom(aes_mod.MAX_AAD)
    pt = os.urandom(aes_mod.MAX_MESSAGE)
    out, sw = client.send(0x2A, 0x84, 0x80, tlv.build(0x81, aad) + tlv.build(0x80, pt))
    assert sw == 0x9000
    items = dict(tlv.parse(out))
    nonce, ct, tag = items[0x82], items[0x80], items[0x83]
    assert AESGCM(key1.key).decrypt(nonce, ct + tag, aad) == pt
    back, sw = client.send(0x2A, 0x80, 0x84, tlv.build(0x81, aad) + out)
    assert (back, sw) == (pt, 0x9000)


def test_beyond_the_limit(client, key1):
    client.send(0xA4, 0x04, 0x00, AID)
    client.send(0x22, 0xF1, 0xB8, bytes.fromhex("830101"))
    _, sw = client.send(0x2A, 0x84, 0x80, tlv.build(0x80, bytes(aes_mod.MAX_MESSAGE + 1)))
    assert sw == 0x6700
    # beyond the dispatcher's de-chained data limit: the overflowing chain
    # part is refused with 6700
    data = tlv.build(0x80, bytes(5000))
    sws = []
    for i in range(0, len(data), 255):
        part = data[i : i + 255]
        last = i + 255 >= len(data)
        _, sw = client.raw(bytes((0x00 if last else 0x10, 0x2A, 0x84, 0x80, len(part))) + part)
        sws.append(sw)
        if sw != 0x9000:
            break
    assert sws[-1] == 0x6700 and set(sws[:-1]) == {0x9000}


def test_tamper_through_dispatcher(client, key1):
    client.send(0xA4, 0x04, 0x00, AID)
    client.send(0x22, 0xF1, 0xB8, bytes.fromhex("830101"))
    out, _ = client.send(0x2A, 0x84, 0x80, tlv.build(0x80, os.urandom(1000)))
    bad = bytearray(out)
    bad[-1] ^= 0x80  # last tag byte
    back, sw = client.send(0x2A, 0x80, 0x84, bytes(bad))
    assert (back, sw) == (b"", 0x6988)


def test_get_challenge_with_and_without_selection(client):
    out, sw = client.raw(bytes.fromhex("0084000020"))
    assert sw == 0x9000 and len(out) == 32
    client.send(0xA4, 0x04, 0x00, AID)
    out, sw = client.raw(bytes.fromhex("0084000010"))
    assert sw == 0x9000 and len(out) == 16
    assert client.raw(bytes.fromhex("0084000021"))[1] == 0x6C20


def test_documented_worked_example_shapes(client, key1, monkeypatch, store):
    """The byte layout of the annex §6 worked example (nonce counter 0)."""
    client.send(0xA4, 0x04, 0x00, AID)
    client.send(0x22, 0x81, 0xB8, bytes.fromhex("800147830101"))
    out, sw = client.send(0x2A, 0x84, 0x80, bytes.fromhex("8103686472") + bytes.fromhex("800568656c6c6f"))
    assert sw == 0x9000
    assert out[:2] == b"\x82\x0c" and out[14:16] == b"\x80\x05" and out[21:23] == b"\x83\x10"
    assert len(out) == 39
    assert out[10:14] == bytes(4)  # first index in the fresh namespace
