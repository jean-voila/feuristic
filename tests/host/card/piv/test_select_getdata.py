# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""SELECT (APT), GET DATA and generic command handling of the PIV applet."""

import pytest

from feuristic.apps.card.piv import applet as piv_applet
from feuristic.apps.card.piv import consts
from feuristic.core import kdf, tlv

from .conftest import MS
from .pivutil import get_data, select, tx, verify


def test_aid_partial_and_full_match(piv):
    assert piv.matches(bytes.fromhex("A000000308"))
    assert piv.matches(consts.AID)
    assert not piv.matches(bytes.fromhex("A000000309"))
    assert not piv.matches(b"")


def test_select_returns_apt_exact(piv):
    r = select(piv)
    assert r.sw == 0x9000
    expected = bytes.fromhex(
        "6137"
        "4f06000010000100"
        "79074f05a000000308"
        "500d" + b"feuristic PIV".hex() + "ac15"
        "80010380010880010a80010c800107800111"
        "060100"
    )
    assert r.data == expected
    apt = tlv.find(r.data, 0x61)
    assert tlv.find(apt, 0x4F) == consts.PIX
    algs = [v[0] for t, v in tlv.parse(tlv.find(apt, 0xAC)) if t == 0x80]
    assert algs == [0x03, 0x08, 0x0A, 0x0C, 0x07, 0x11]


def test_select_no_fci(piv):
    r = select(piv, p2=0x0C)
    assert (r.data, r.sw) == (b"", 0x9000)


def test_chuid_generated(piv):
    r = get_data(piv, consts.OBJ_CHUID)
    assert r.sw == 0x9000
    body = tlv.find(r.data, 0x53)
    items = dict(tlv.parse(body))
    assert items[0x30] == piv_applet.FASCN_NONFEDERAL
    assert len(items[0x30]) == 25
    assert items[0x34] == kdf.derive(MS, b"card/serial", 16, b"piv-guid")
    assert items[0x35] == b"20301231"
    assert items[0x3E] == b""
    assert items[0xFE] == b""
    # stable across calls / instances
    assert get_data(piv, consts.OBJ_CHUID).data == r.data


def test_guid_differs_per_device(ui, store):
    a = piv_applet.PivApplet(ui, store=store, master_secret=MS)
    b = piv_applet.PivApplet(ui, store=store, master_secret=bytes(32))
    assert get_data(a, consts.OBJ_CHUID).data != get_data(b, consts.OBJ_CHUID).data


def test_master_secret_callable(ui, store):
    a = piv_applet.PivApplet(ui, store=store, master_secret=lambda: MS)
    assert get_data(a, consts.OBJ_CHUID).sw == 0x9000


def test_missing_master_secret_is_an_error(ui, store):
    a = piv_applet.PivApplet(ui, store=store)
    assert get_data(a, consts.OBJ_CHUID).sw == 0x6F00


def test_ccc_generated(piv):
    r = get_data(piv, consts.OBJ_CCC)
    body = tlv.find(r.data, 0x53)
    card_id = tlv.find(body, 0xF0)
    assert len(card_id) == 21
    assert card_id.startswith(bytes.fromhex("A000000116FF02"))
    assert tlv.find(body, 0xF1) == b"\x21"
    assert tlv.find(body, 0xFE) == b""


def test_discovery_object(piv):
    r = get_data(piv, consts.OBJ_DISCOVERY)
    assert r.sw == 0x9000
    assert r.data == bytes.fromhex("7e124f0ba0000003080000100001005f2f024000")


def test_key_history_generated(piv):
    r = get_data(piv, consts.OBJ_KEY_HISTORY)
    assert r.data == bytes.fromhex("5308c10100c20100fe00")


@pytest.mark.parametrize(
    "tag",
    [consts.OBJ_CERT_9A, consts.OBJ_CERT_9C, consts.OBJ_CERT_9D, consts.OBJ_CERT_9E, consts.OBJ_SECURITY],
)
def test_absent_objects_not_found(piv, tag):
    assert get_data(piv, tag).sw == 0x6A82


@pytest.mark.parametrize("tag", [0x5FC103, 0x5FC108, 0x5FC10D, 0x5FC120, 0x5FFF00, 0x7F61, 0x01])
def test_unsupported_objects(piv, tag):
    tag_b = tag.to_bytes((tag.bit_length() + 7) // 8, "big")
    r = tx(piv, 0xCB, 0x3F, 0xFF, tlv.build(0x5C, tag_b))
    assert r.sw == 0x6A82


def test_printed_info_requires_pin(piv):
    assert get_data(piv, consts.OBJ_PRINTED).sw == 0x6982
    assert verify(piv).sw == 0x9000
    assert get_data(piv, consts.OBJ_PRINTED).sw == 0x6A82  # PIN ok, object absent


@pytest.mark.parametrize(
    "data",
    [
        b"",
        bytes.fromhex("5C00"),
        bytes.fromhex("5C045FC10200"),
        bytes.fromhex("5D035FC102"),
        bytes.fromhex("5C035FC1025C035FC102"),
        bytes.fromhex("5C035FC1"),  # truncated
    ],
)
def test_get_data_malformed(piv, data):
    assert tx(piv, 0xCB, 0x3F, 0xFF, data).sw == 0x6A80


def test_get_data_wrong_p1p2(piv):
    assert tx(piv, 0xCB, 0x3F, 0xFE, bytes.fromhex("5C035FC102")).sw == 0x6A86


@pytest.mark.parametrize(
    ("cla", "sw"), [(0x80, 0x6E00), (0x04, 0x6882), (0x08, 0x6882), (0x01, 0x6881), (0x03, 0x6881)]
)
def test_class_byte(piv, cla, sw):
    assert tx(piv, 0xCB, 0x3F, 0xFF, bytes.fromhex("5C035FC102"), cla=cla).sw == sw


def test_chained_class_bit_is_tolerated(piv):
    # the dispatcher resolves chaining; a residual b5 must not be rejected
    assert tx(piv, 0xCB, 0x3F, 0xFF, bytes.fromhex("5C017E"), cla=0x10).sw == 0x9000


@pytest.mark.parametrize("ins", [0xFE, 0xF9, 0xFA, 0xF6, 0x2A, 0x22, 0xB0, 0x84, 0x00])
def test_unsupported_instructions(piv, ins):
    assert tx(piv, ins, 0, 0, b"\x00" * 4).sw == 0x6D00


def test_import_asymmetric_key_refused_even_when_authenticated(piv):
    from .pivutil import mgmt_auth

    mgmt_auth(piv)
    # YubiKey IMPORT ASYMMETRIC KEY: 00 FE 11 9A { 06 <sk> }
    r = tx(piv, 0xFE, 0x11, 0x9A, tlv.build(0x06, bytes(31) + b"\x01"))
    assert r.sw == 0x6D00
    assert get_data(piv, consts.OBJ_CERT_9A).sw == 0x6A82


def test_version_and_serial(piv):
    r = tx(piv, 0xFD, 0, 0)
    assert (r.data, r.sw) == (b"\x05\x07\x00", 0x9000)
    r = tx(piv, 0xF8, 0, 0)
    assert r.sw == 0x9000
    assert r.data == kdf.derive(MS, b"card/serial", 4, b"piv-serial")
