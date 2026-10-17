# SPDX-License-Identifier: GPL-3.0-only
"""OpenPGP PUT DATA: access conditions, lengths, algorithm attributes, UIF."""

import pytest

from feuristic.apps.card.openpgp import const as pgp
from feuristic.apps.card.openpgp import keys as alg
from feuristic.core.interaction import DANGER

from .conftest import Env, find_do


def test_put_requires_admin(env):
    assert env.put(0x5B, b"Doe<<John") == 0x6982
    env.verify(0x82, b"123456")
    assert env.put(0x5B, b"Doe<<John") == 0x6982
    env.admin()
    assert env.put(0x5B, b"Doe<<John") == 0x9000
    data, _ = env.get(0x65)
    assert find_do(data, 0x5B) == b"Doe<<John"


@pytest.mark.parametrize(
    ("tag", "value", "get_tag"),
    [
        (0x5B, b"x" * 39, 0x5B),
        (0x5F2D, b"frende", 0x5F2D),
        (0x5F35, b"9", 0x5F35),
        (0x5F35, b"", 0x5F35),
        (0x5F50, b"https://example.org/key.asc", 0x5F50),
        (0x5F50, b"u" * 254, 0x5F50),
        (0x5E, b"jdoe", 0x5E),
        (0x0102, b"p" * 254, 0x0102),
        (0x0104, b"admin-only", 0x0104),
        (0x7F21, b"\x30\x82" + bytes(2046), 0x7F21),
    ],
)
def test_put_get_roundtrip(env, tag, value, get_tag):
    env.admin()
    assert env.put(tag, value) == 0x9000
    data, sw = env.tx(0xCA, get_tag >> 8, get_tag & 0xFF, ne=65536)
    assert sw == 0x9000 and data == value


@pytest.mark.parametrize(
    ("tag", "value", "sw"),
    [
        (0x5B, b"x" * 40, 0x6700),
        (0x5F2D, b"x" * 9, 0x6700),
        (0x5F35, b"7", 0x6A80),
        (0x5F35, b"12", 0x6700),
        (0x5F50, b"u" * 255, 0x6700),
        (0x5E, b"u" * 255, 0x6700),
        (0x0101, b"u" * 255, 0x6982),  # PW1 (82) required first
        (0x7F21, bytes(2049), 0x6700),
        (0xC4, b"\x02", 0x6A80),
        (0xC4, b"\x01\x7f", 0x6700),
        (0xC7, bytes(19), 0x6700),
        (0xCA, bytes(21), 0x6700),
        (0xCE, bytes(3), 0x6700),
        (0xD6, b"\x00\x20", 0x6985),
        (0xD7, b"\x03\x20", 0x6A80),
        (0xD8, b"\x02", 0x6700),
        (0xF9, b"\x81\x01\x00", 0x6A81),
        (0xD5, bytes(32), 0x6A81),
        (0x4F, bytes(16), 0x6A88),
        (0x6E, b"", 0x6A88),
        (0xC5, bytes(60), 0x6A88),
        (0x1234, b"", 0x6A88),
    ],
)
def test_put_rejections(env, tag, value, sw):
    env.admin()
    assert env.put(tag, value) == sw


def test_private_do_access_rules(env):
    assert env.put(0x0101, b"one") == 0x6982
    env.verify(0x82, b"123456")
    assert env.put(0x0101, b"one") == 0x9000
    assert env.put(0x0103, b"three") == 0x9000
    assert env.put(0x0102, b"two") == 0x6982
    assert env.get(0x0101) == (b"one", 0x9000)
    assert env.get(0x0103) == (b"three", 0x9000)
    env.admin()
    assert env.put(0x0102, b"two") == 0x9000
    assert env.put(0x0104, b"four") == 0x9000


def test_fingerprints_dates_ca(env):
    env.admin()
    for i, (f, c, d) in enumerate(zip(pgp.FPR_TAGS, pgp.CA_FPR_TAGS, pgp.DATE_TAGS)):
        assert env.put(f, bytes((i + 1,)) * 20) == 0x9000
        assert env.put(c, bytes((i + 0x10,)) * 20) == 0x9000
        assert env.put(d, (0x60000000 + i).to_bytes(4, "big")) == 0x9000
    assert env.get(0xC5)[0] == b"\x01" * 20 + b"\x02" * 20 + b"\x03" * 20
    assert env.get(0xC6)[0] == b"\x10" * 20 + b"\x11" * 20 + b"\x12" * 20
    assert env.get(0xCD)[0] == bytes.fromhex("600000006000000160000002")


def test_uif_cannot_be_disabled(env):
    env.admin()
    assert env.put(0xD6, b"\x01\x20") == 0x9000
    assert env.put(0xD7, b"\x02\x20") == 0x9000
    assert env.get(0xD6) == (b"\x02\x20", 0x9000)
    assert env.put(0xD8, b"\x00\x00") == 0x6985


def test_algorithm_attributes_validation(env):
    env.admin()
    assert env.put(0xC1, pgp.ATTR_ED25519) == 0x9000
    assert env.put(0xC1, pgp.ATTR_X25519) == 0x6A80
    assert env.put(0xC2, pgp.ATTR_ED25519) == 0x6A80
    assert env.put(0xC3, pgp.ATTR_X25519) == 0x6A80
    assert env.put(0xC2, pgp.ATTR_X25519 + b"\xff") == 0x9000
    assert env.get(0xC2)[0] == pgp.ATTR_X25519  # stored canonically
    assert env.put(0xC1, bytes.fromhex("132A8648CE3D030107")) == 0x6A80  # ECDSA P-256
    assert env.put(0xC1, b"\x01\x10\x00\x00\x20\x00") == 0x6A80  # RSA-4096
    assert env.put(0xC1, b"") == 0x6A80
    if not alg.rsa_available():
        assert env.put(0xC1, pgp.ATTR_RSA2048) == 0x6A80


def test_attribute_change_destroys_key_after_confirmation(monkeypatch):
    monkeypatch.setattr(alg, "rsa_available", lambda: True)
    e = Env(answers=[True, False, True])
    e.select()
    e.admin()
    assert e.generate(0xB6)[1] == 0x9000
    e.put(0xC7, b"\x22" * 20)
    # refused: nothing changes
    assert e.put(0xC1, b"\x01\x08\x00\x00\x11\x00") == 0x6985
    assert e.get(0xC1)[0] == pgp.ATTR_ED25519
    assert e.read_public(0xB6)[1] == 0x9000
    p = e.ui.prompts[-1]
    assert p.kind == "openpgp.attr_change" and p.severity == DANGER and p.fingerprint == "22" * 20
    # accepted: key, fingerprint and date destroyed, canonical RSA attributes
    assert e.put(0xC1, b"\x01\x08\x00\x00\x11\x00") == 0x9000
    assert e.get(0xC1)[0] == pgp.ATTR_RSA2048
    assert e.read_public(0xB6)[1] == 0x6A88
    assert e.get(0xC5)[0][:20] == bytes(20)
    # changing back without a key: no prompt
    n = len(e.ui.prompts)
    assert e.put(0xC1, pgp.ATTR_ED25519) == 0x9000
    assert len(e.ui.prompts) == n


def test_same_attributes_no_prompt(env):
    env.admin()
    env.generate(0xB6)
    n = len(env.ui.prompts)
    assert env.put(0xC1, pgp.ATTR_ED25519) == 0x9000
    assert len(env.ui.prompts) == n
    assert env.read_public(0xB6)[1] == 0x9000


def test_put_data_survives_reboot():
    e = Env()
    e.select()
    e.admin()
    e.put(0x5B, b"Doe<<Jane")
    e.put(0x5F50, b"https://example.org")
    e.put(0x7F21, b"\x30\x03\x02\x01\x01")
    e.put(0xC4, b"\x00")
    e.reboot().select()
    assert e.get(0x5B)[0] == b"Doe<<Jane"
    assert e.get(0x5F50)[0] == b"https://example.org"
    assert e.get(0x7F21)[0] == b"\x30\x03\x02\x01\x01"
    assert e.get(0xC4)[0][0] == 0
    e.admin()
    e.put(0x7F21, b"")
    e.put(0x5F50, b"")
    e.reboot().select()
    assert e.get(0x7F21)[0] == b""
