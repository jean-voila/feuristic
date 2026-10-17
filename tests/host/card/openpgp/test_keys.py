# SPDX-License-Identifier: GPL-3.0-only
"""OpenPGP: GENERATE, PSO:CDS (Ed25519), PSO:DECIPHER (X25519), INTERNAL
AUTHENTICATE, device confirmation, signature counter."""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from feuristic.apps.card.openpgp import const as pgp
from feuristic.core import i18n, tlv
from feuristic.core.interaction import DANGER, SENSITIVE

from .conftest import Env, find_do, public_from_7f49

SIG, DEC, AUT = 0xB6, 0xB8, 0xA4
DIGEST = bytes(range(32))


def gen(env, role):
    data, sw = env.generate(role)
    assert sw == 0x9000, hex(sw)
    return public_from_7f49(data)[0x86]


def counter(env):
    data, _ = env.get(0x7A)
    return int.from_bytes(find_do(data, 0x93), "big")


def sign(env, data=DIGEST):
    return env.tx(0x2A, 0x9E, 0x9A, data, ne=256)


def decipher_do(point):
    return tlv.build(0xA6, tlv.build(0x7F49, tlv.build(0x86, point)))


# --- generation --------------------------------------------------------------------


def test_generate_requires_admin(env):
    assert env.generate(SIG)[1] == 0x6982
    assert env.ui.prompts == []


def test_generate_and_read_public(env):
    env.admin()
    pub = gen(env, SIG)
    assert len(pub) == 32
    p = env.ui.prompts[-1]
    assert p.kind == "openpgp.generate" and p.severity == SENSITIVE
    data, sw = env.read_public(SIG)
    assert sw == 0x9000 and public_from_7f49(data)[0x86] == pub
    assert env.read_public(DEC)[1] == 0x6A88
    data, _ = env.get(0xDE)
    assert data == bytes.fromhex("010102000300")
    # the fingerprint/date are cleared: the host writes them afterwards
    assert env.get(0xC5)[0] == bytes(60)


def test_generate_refused_on_device():
    e = Env(answers=[False])
    e.select()
    e.admin()
    assert e.generate(SIG)[1] == 0x6985
    assert e.read_public(SIG)[1] == 0x6A88


def test_generate_replace_is_dangerous(env):
    env.admin()
    first = gen(env, AUT)
    assert env.put(0xC9, b"\x11" * 20) == 0x9000
    second = gen(env, AUT)
    assert first != second
    p = env.ui.prompts[-1]
    assert p.severity == DANGER and p.title == "openpgp.confirm.replace_key"
    assert p.fingerprint == "11" * 20
    assert env.get(0xC5)[0][40:] == bytes(20)


@pytest.mark.parametrize(
    ("p1", "p2", "data", "sw"),
    [
        (0x82, 0x00, b"\xb6\x00", 0x6A86),
        (0x80, 0x01, b"\xb6\x00", 0x6A86),
        (0x80, 0x00, b"\xb7\x00", 0x6A80),
        (0x80, 0x00, b"", 0x6A80),
        (0x80, 0x00, b"\xb6\x00\xb8\x00", 0x6A80),
        (0x80, 0x00, b"\xb6\x03\x84\x01\x02", 0x6A80),
        (0x80, 0x00, b"\xb6\x05", 0x6A80),
    ],
)
def test_generate_bad_parameters(env, p1, p2, data, sw):
    env.admin()
    assert env.tx(0x47, p1, p2, data, ne=256)[1] == sw


def test_generate_with_key_reference(env):
    env.admin()
    assert env.tx(0x47, 0x80, 0x00, b"\xb8\x03\x84\x01\x02", ne=256)[1] == 0x9000


# --- PSO:CDS --------------------------------------------------------------------------


def test_sign_ed25519_verifies(env):
    env.admin()
    pub = gen(env, SIG)
    fpr = bytes.fromhex("AB" * 20)
    env.put(0xC7, fpr)
    assert sign(env)[1] == 0x6982
    assert env.verify(0x82, b"123456") == 0x9000
    assert sign(env)[1] == 0x6982  # PW1 82 does not allow signing
    assert env.verify(0x81, b"123456") == 0x9000
    before = counter(env)
    sig, sw = sign(env)
    assert sw == 0x9000 and len(sig) == 64
    Ed25519PublicKey.from_public_bytes(pub).verify(sig, DIGEST)
    assert counter(env) == before + 1
    p = env.ui.prompts[-1]
    assert p.kind == "openpgp.sign" and p.severity == SENSITIVE
    assert p.fingerprint == fpr.hex().upper()
    fields = dict(p.fields)
    assert fields["openpgp.field.uninterpreted"] == DIGEST.hex().upper()
    assert fields["openpgp.field.role"] == "Signature"
    assert fields["openpgp.field.algorithm"] == "Ed25519"
    # several signatures allowed with PW1 status 01
    assert sign(env, b"\x01" * 64)[1] == 0x9000
    assert counter(env) == before + 2


def test_sign_prompt_strings_in_french(env):
    env.admin()
    gen(env, SIG)
    env.verify(0x81, b"123456")
    i18n.set_language(i18n.FR)
    try:
        sign(env)
        fields = dict(env.ui.prompts[-1].fields)
        assert fields["openpgp.field.role"] == "Signature"
        assert i18n.t("openpgp.field.uninterpreted") == "Signature d'empreinte non interprétée"
        assert fields["openpgp.field.type"] == "Signature EdDSA"
    finally:
        i18n.set_language(i18n.EN)


def test_sign_without_fingerprint_shows_pubkey_hash(env):
    env.admin()
    gen(env, SIG)
    env.verify(0x81, b"123456")
    sign(env)
    p = env.ui.prompts[-1]
    assert p.fingerprint is None
    assert len(dict(p.fields)["openpgp.field.pubkey_hash"]) == 40


def test_long_data_shows_sha256(env):
    env.admin()
    gen(env, SIG)
    env.verify(0x81, b"123456")
    assert sign(env, bytes(100))[1] == 0x9000
    import hashlib

    assert dict(env.ui.prompts[-1].fields)["openpgp.field.uninterpreted"] == (
        hashlib.sha256(bytes(100)).hexdigest().upper()
    )


def test_sign_refused_does_not_count():
    e = Env(answers=[True, False])
    e.select()
    e.admin()
    gen(e, SIG)
    e.verify(0x81, b"123456")
    assert sign(e)[1] == 0x6985
    assert counter(e) == 0


def test_sign_without_key_and_empty_data(env):
    env.verify(0x81, b"123456")
    assert sign(env)[1] == 0x6A88
    env.admin()
    gen(env, SIG)
    assert sign(env, b"")[1] == 0x6700


def test_pw1_status_00_single_signature(env):
    env.admin()
    gen(env, SIG)
    assert env.put(0xC4, b"\x00") == 0x9000
    assert env.get(0xC4)[0][0] == 0x00
    env.verify(0x81, b"123456")
    assert sign(env)[1] == 0x9000
    assert sign(env)[1] == 0x6982
    env.verify(0x81, b"123456")
    assert sign(env)[1] == 0x9000


def test_counter_reset_on_new_signature_key(env):
    env.admin()
    gen(env, SIG)
    env.verify(0x81, b"123456")
    sign(env)
    sign(env)
    assert counter(env) == 2
    gen(env, SIG)
    assert counter(env) == 0
    gen(env, AUT)
    sign(env)
    assert counter(env) == 1


def test_unknown_pso(env):
    assert env.tx(0x2A, 0x9E, 0x9B, DIGEST)[1] == 0x6A86
    assert env.tx(0x2A, 0x86, 0x80, DIGEST)[1] == 0x6A81


# --- PSO:DECIPHER ------------------------------------------------------------------------


def test_decipher_x25519(env):
    env.admin()
    card_pub = gen(env, DEC)
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    expected = eph.exchange(X25519PublicKey.from_public_bytes(card_pub))
    assert env.tx(0x2A, 0x80, 0x86, decipher_do(eph_pub), ne=256)[1] == 0x6982
    env.verify(0x82, b"123456")
    shared, sw = env.tx(0x2A, 0x80, 0x86, decipher_do(eph_pub), ne=256)
    assert sw == 0x9000 and shared == expected
    p = env.ui.prompts[-1]
    assert p.kind == "openpgp.decrypt"
    assert dict(p.fields)["openpgp.field.role"] == "Decryption"
    # 0x40-prefixed point tolerated
    shared2, sw = env.tx(0x2A, 0x80, 0x86, decipher_do(b"\x40" + eph_pub), ne=256)
    assert sw == 0x9000 and shared2 == expected


@pytest.mark.parametrize(
    "data",
    [
        b"",
        bytes(32),
        tlv.build(0xA6, tlv.build(0x7F49, tlv.build(0x86, bytes(31)))),
        tlv.build(0xA6, tlv.build(0x7F49, tlv.build(0x87, bytes(32)))),
        tlv.build(0xA7, tlv.build(0x7F49, tlv.build(0x86, bytes(32)))),
        tlv.build(0xA6, tlv.build(0x7F48, tlv.build(0x86, bytes(32)))),
        tlv.build(0xA6, tlv.build(0x7F49, tlv.build(0x86, b"\x41" + bytes(32)))),
        b"\xa6\x05\x7f\x49",
    ],
)
def test_decipher_malformed(env, data):
    env.admin()
    gen(env, DEC)
    env.verify(0x82, b"123456")
    n = len(env.ui.prompts)
    assert env.tx(0x2A, 0x80, 0x86, data, ne=256)[1] == 0x6A80
    assert len(env.ui.prompts) == n  # rejected before asking the user


def test_decipher_small_order_point(env):
    env.admin()
    gen(env, DEC)
    env.verify(0x82, b"123456")
    assert env.tx(0x2A, 0x80, 0x86, decipher_do(bytes(32)), ne=256)[1] == 0x6A80


def test_decipher_refused_and_no_key():
    e = Env(answers=[True, False])
    e.select()
    e.admin()
    e.verify(0x82, b"123456")
    assert e.tx(0x2A, 0x80, 0x86, decipher_do(b"\x09" + bytes(31)), ne=256)[1] == 0x6A88
    gen(e, DEC)
    assert e.tx(0x2A, 0x80, 0x86, decipher_do(b"\x09" + bytes(31)), ne=256)[1] == 0x6985


# --- INTERNAL AUTHENTICATE ------------------------------------------------------------------


def test_internal_authenticate_ed25519(env):
    env.admin()
    pub = gen(env, AUT)
    challenge = b"ssh-session-data" * 6
    assert env.tx(0x88, 0, 0, challenge, ne=256)[1] == 0x6982
    env.verify(0x82, b"123456")
    sig, sw = env.tx(0x88, 0, 0, challenge, ne=256)
    assert sw == 0x9000
    Ed25519PublicKey.from_public_bytes(pub).verify(sig, challenge)
    p = env.ui.prompts[-1]
    assert p.kind == "openpgp.auth"
    assert dict(p.fields)["openpgp.field.role"] == "Authentication"
    assert env.tx(0x88, 1, 0, challenge, ne=256)[1] == 0x6A86
    assert env.tx(0x88, 0, 0, b"", ne=256)[1] == 0x6700
    assert counter(env) == 0  # authentication does not count signatures


def test_keys_are_independent(env):
    env.admin()
    s = gen(env, SIG)
    d = gen(env, DEC)
    a = gen(env, AUT)
    assert len({s, d, a}) == 3


def test_extended_apdu_public_key_read(env):
    env.admin()
    gen(env, SIG)
    data, sw = env.raw(bytes.fromhex("00478100000002B6000000"))
    assert sw == 0x9000 and data[:2] == b"\x7f\x49"


def test_role_attributes_constant():
    assert pgp.CRT_TAGS == (SIG, DEC, AUT)
