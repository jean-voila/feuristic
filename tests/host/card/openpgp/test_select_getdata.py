# SPDX-License-Identifier: GPL-3.0-only
"""OpenPGP: SELECT, AID, GET DATA (the sequence scdaemon sends for --card-status)."""

import pytest

from feuristic.apps.card import ccid
from feuristic.apps.card.openpgp import const as pgp
from feuristic.apps.card.openpgp.applet import card_serial
from feuristic.core import kdf, tlv

from .conftest import MS, Env, find_do


def test_aid_layout(env):
    aid, sw = env.get(0x4F)
    assert sw == 0x9000 and len(aid) == 16
    assert aid[:6] == bytes.fromhex("D27600012401")
    assert aid[6:8] == b"\x03\x04"  # version 3.4
    assert aid[8:10] == b"\xff\x7e"  # unmanaged S/N range FF00..FFFE
    assert 0xFF00 <= int.from_bytes(aid[8:10], "big") <= 0xFFFE
    assert aid[10:14] == kdf.derive(MS, b"card/serial", 4, b"openpgp")
    assert aid[14:] == b"\x00\x00"
    assert aid == env.applet.AID


def test_serial_differs_per_master_secret():
    assert card_serial(MS) != card_serial(bytes(32))
    a = Env(ms=b"\x01" * 32)
    assert a.applet.AID[10:14] == card_serial(b"\x01" * 32)


def test_select_variants():
    e = Env()
    assert e.raw(bytes.fromhex("00A4040006D27600012401")) == (b"", 0x9000)
    assert e.raw(bytes.fromhex("00A4040C06D27600012401")) == (b"", 0x9000)
    assert e.raw(bytes.fromhex("00A4040010") + e.applet.AID) == (b"", 0x9000)
    # wrong serial: no match
    assert e.raw(bytes.fromhex("00A4040010") + e.applet.AID[:10] + b"\x00\x00\x00\x01\x00\x00")[1] == 0x6A82


def test_historical_bytes(env):
    data, sw = env.get(0x5F52)
    assert sw == 0x9000 and data == ccid.HISTORICAL_BYTES


def test_application_related_data(env):
    data, sw = env.get(0x6E)
    assert sw == 0x9000
    (top,) = tlv.parse(data)
    assert top[0] == 0x6E
    body = dict(tlv.parse(top[1]))
    assert body[0x4F] == env.applet.AID
    assert body[0x5F52] == ccid.HISTORICAL_BYTES
    assert body[0x7F66] == bytes.fromhex("0202100002021000")
    assert body[0x7F74] == b"\x81\x01\xa0"
    disc = dict(tlv.parse(body[0x73]))
    assert disc[0xC0] == bytes.fromhex("5C000020080000FE0000")
    assert disc[0xC1] == bytes.fromhex("162B06010401DA470F01")
    assert disc[0xC2] == bytes.fromhex("122B060104019755010501")
    assert disc[0xC3] == bytes.fromhex("162B06010401DA470F01")
    assert disc[0xC4] == bytes.fromhex("017F7F7F030003")
    assert disc[0xC5] == bytes(60)
    assert disc[0xC6] == bytes(60)
    assert disc[0xCD] == bytes(12)
    assert disc[0xDE] == bytes.fromhex("010002000300")
    for t in (0xD6, 0xD7, 0xD8):
        assert disc[t] == b"\x02\x20"
    assert len(data) > 256  # exercised GET RESPONSE chaining in env.tx


def test_application_related_data_extended_le(env):
    first, sw = env.raw(bytes.fromhex("00CA006E000000"))
    assert sw == 0x9000 and first[0] == 0x6E


def test_short_le_gets_61xx():
    e = Env()
    e.select()
    data, sw = e.raw(bytes.fromhex("00CA006E00"))
    assert len(data) == 256 and sw >> 8 == 0x61


@pytest.mark.parametrize(
    ("tag", "expected"),
    [
        (0x65, bytes.fromhex("65085B005F2D005F3500")),
        (0x7A, bytes.fromhex("7A059303000000")),
        (0x93, bytes.fromhex("000000")),
        (0xC4, bytes.fromhex("017F7F7F030003")),
        (0x5E, b""),
        (0x5F50, b""),
        (0x5B, b""),
        (0x5F2D, b""),
        (0x5F35, b""),
        (0x7F21, b""),
        (0xC0, pgp.EXTENDED_CAPABILITIES),
        (0xC5, bytes(60)),
        (0xC6, bytes(60)),
        (0xCD, bytes(12)),
        (0xDE, bytes.fromhex("010002000300")),
        (0xD6, b"\x02\x20"),
        (0x7F66, bytes.fromhex("0202100002021000")),
        (0x7F74, b"\x81\x01\xa0"),
        (0x0101, b""),
        (0x0102, b""),
    ],
)
def test_get_data_objects(env, tag, expected):
    assert env.get(tag) == (expected, 0x9000)


def test_algorithm_information(env):
    data, sw = env.get(0xFA)
    assert sw == 0x9000
    ((tag, value),) = tlv.parse(data)
    assert tag == 0xFA
    items = tlv.parse(value)
    assert (0xC1, pgp.ATTR_ED25519) in items
    assert (0xC2, pgp.ATTR_X25519) in items
    assert (0xC3, pgp.ATTR_ED25519) in items
    assert (0xC2, pgp.ATTR_ED25519) not in items


@pytest.mark.parametrize("tag", [0xF9, 0x1234, 0x00, 0x73, 0x0105, 0xD5])
def test_get_data_unknown(env, tag):
    assert env.get(tag)[1] == 0x6A88


def test_get_data_with_command_data(env):
    assert env.tx(0xCA, 0x00, 0x4F, b"\x00")[1] == 0x6700


def test_private_do_access(env):
    assert env.get(0x0103)[1] == 0x6982
    assert env.get(0x0104)[1] == 0x6982
    assert env.verify(0x82, b"123456") == 0x9000
    assert env.get(0x0103) == (b"", 0x9000)
    assert env.get(0x0104)[1] == 0x6982
    env.admin()
    assert env.get(0x0104) == (b"", 0x9000)


def test_cla_and_unknown_ins(env):
    assert env.tx(0xCA, 0x00, 0x4F, cla=0x80)[1] == 0x6E00
    assert env.tx(0x22, 0x41, 0xA4)[1] == 0x6D00  # MSE not supported
    assert env.tx(0xCC, 0x7F, 0x21)[1] == 0x6D00  # GET NEXT DATA
    assert env.tx(0x99)[1] == 0x6D00


def test_key_import_refused(env):
    env.admin()
    template = bytes.fromhex("4D 0A B6 00 7F48 02 92 20 5F48 00".replace(" ", ""))
    assert env.tx(0xDB, 0x3F, 0xFF, template)[1] == 0x6A81
    assert Env().tx(0xDB, 0x3F, 0xFF, template)[1] == 0x6D00  # not selected


def test_get_challenge(env):
    a, sw = env.tx(0x84, ne=32)
    b, _ = env.tx(0x84, ne=32)
    assert sw == 0x9000 and len(a) == 32 and a != b
    assert len(env.ok(0x84, ne=1)) == 1
    assert env.tx(0x84, ne=33)[1] == 0x6700
    assert env.raw(b"\x00\x84\x00\x00")[1] == 0x6700  # Le absent
    assert env.raw(b"\x00\x84\x00\x00\x00")[1] == 0x6700  # Le = 256
    assert env.tx(0x84, 1, 0, ne=8)[1] == 0x6A86


def test_select_data(env):
    assert env.tx(0xA5, 0x00, 0x04, bytes.fromhex("6004 5C02 7F21".replace(" ", "")))[1] == 0x9000
    assert env.tx(0xA5, 0x01, 0x04, bytes.fromhex("60045C027F21"))[1] == 0x6A88
    assert env.tx(0xA5, 0x00, 0x04, bytes.fromhex("60045C025F50"))[1] == 0x6A88
    assert env.tx(0xA5, 0x00, 0x04, bytes.fromhex("5C027F21"))[1] == 0x6A80
    assert env.tx(0xA5, 0x00, 0x04, bytes.fromhex("6005"))[1] == 0x6A80
    assert env.tx(0xA5, 0x00, 0x00, bytes.fromhex("60045C027F21"))[1] == 0x6A86


def test_scdaemon_card_status_sequence(env):
    """Replay of the APDUs GnuPG 2.4 sends for `gpg --card-status`."""
    seq = [
        "00A4040006D27600012401",
        "00CA004F00",
        "00CA5F5200",
        "00CA006E000000",
        "00CA006500",
        "00CA5F5000",
        "00CA005E00",
        "00CA007A00",
        "00CA00C400",
        "00CA7F2100",
        "00CA00FA000000",
    ]
    for h in seq:
        data, sw = env.raw(bytes.fromhex(h))
        assert sw == 0x9000, (h, hex(sw))
    data, sw = env.raw(bytes.fromhex("00CA006E000000"))
    assert find_do(data, 0xC5) == bytes(60)
