# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""GENERATE ASYMMETRIC KEY PAIR and GENERAL AUTHENTICATE with slot keys."""

import hashlib
import importlib.util
import os

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding

from feuristic.apps.card.piv import consts, provider
from feuristic.core import i18n, tlv
from feuristic.core.interaction import DANGER, SENSITIVE

from .pivutil import (
    dyn,
    dyn_value,
    ec_public,
    generate,
    mgmt_auth,
    sign,
    tx,
    verify,
    verify_ecdsa,
)

HAS_CORE_RSA = importlib.util.find_spec("feuristic.core.rsa") is not None
DIGEST = hashlib.sha256(b"feuristic").digest()


@pytest.fixture
def admin(piv):
    mgmt_auth(piv)
    return piv


def gen_ec(piv, slot):
    r = generate(piv, slot)
    assert r.sw == 0x9000, hex(r.sw)
    return ec_public(r)


def spki_sha256(pub) -> str:
    der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).digest()[:8].hex().upper()


# -- generation ------------------------------------------------------------------


def test_generate_requires_management_key(piv):
    assert generate(piv, 0x9A).sw == 0x6982


def test_generate_p256_response_format(admin, ui):
    r = generate(admin, 0x9A)
    assert r.sw == 0x9000
    assert r.data[:5] == bytes.fromhex("7f49438641")
    assert r.data[5] == 0x04 and len(r.data) == 5 + 65
    p = ui.prompts[-1]
    assert (p.kind, p.title, p.severity) == ("piv.generate", "piv.prompt.generate", SENSITIVE)


@pytest.mark.parametrize("slot", consts.KEY_SLOTS)
def test_generate_all_slots(admin, slot):
    gen_ec(admin, slot)
    assert tx(admin, 0xF7, 0, slot).data.startswith(b"\x01\x01\x11")


def test_generate_refused_on_device(admin, ui, store):
    ui.answers = [False]
    assert generate(admin, 0x9C).sw == 0x6982
    assert store.get_slot(0x9C) is None


def test_regenerate_replaces_key_and_drops_certificate(admin, ui, store):
    from .pivutil import cert_object, put_data

    gen_ec(admin, 0x9A)
    assert put_data(admin, consts.OBJ_CERT_9A, cert_object(b"\x30\x03\x02\x01\x01")).sw == 0x9000
    first = store.get_slot(0x9A).pub
    gen_ec(admin, 0x9A)
    p = ui.prompts[-1]
    assert (p.title, p.severity) == ("piv.prompt.replace", DANGER)
    assert store.get_slot(0x9A).pub != first
    assert store.get_slot(0x9A).cert is None


@pytest.mark.parametrize(
    "data",
    [
        b"",
        tlv.build(0xAC, b""),
        tlv.build(0xAC, tlv.build(0x80, b"\x14")),  # P-384 unsupported
        tlv.build(0xAC, tlv.build(0x80, b"\x06")),  # RSA-1024 unsupported
        tlv.build(0xAC, tlv.build(0x80, b"\x11\x11")),
        tlv.build(0xAC, tlv.build(0x80, b"\x11") + tlv.build(0x80, b"\x11")),
        tlv.build(0xAC, tlv.build(0x80, b"\x11") + tlv.build(0x81, b"\x01\x00\x01")),
        tlv.build(0xAD, tlv.build(0x80, b"\x11")),
        tlv.build(0xAC, tlv.build(0x80, b"\x11")) + b"\x00",
    ],
)
def test_generate_malformed(admin, data):
    assert tx(admin, 0x47, 0, 0x9A, data).sw == 0x6A80


@pytest.mark.parametrize(("p1", "p2"), [(0x01, 0x9A), (0x00, 0x9B), (0x00, 0x82), (0x00, 0x80)])
def test_generate_bad_reference(admin, p1, p2):
    assert tx(admin, 0x47, p1, p2, tlv.build(0xAC, tlv.build(0x80, b"\x11"))).sw == 0x6A86


def test_pin_policy_can_only_be_stricter(admin, store):
    # 9E default "never": "always" accepted
    r = generate(admin, 0x9E, extra=tlv.build(0xAA, b"\x03"))
    assert r.sw == 0x9000
    assert store.get_slot(0x9E).pin_policy == consts.PIN_POLICY_ALWAYS
    # 9C default "always": "never" rejected
    assert generate(admin, 0x9C, extra=tlv.build(0xAA, b"\x01")).sw == 0x6A80
    assert generate(admin, 0x9C, extra=tlv.build(0xAA, b"\x05")).sw == 0x6A80
    assert generate(admin, 0x9C, extra=tlv.build(0xAA, b"\x00")).sw == 0x9000


@pytest.mark.parametrize(("touch", "sw"), [(0, 0x9000), (1, 0x6A80), (2, 0x9000), (3, 0x9000), (4, 0x6A80)])
def test_touch_policy(admin, touch, sw):
    assert generate(admin, 0x9A, extra=tlv.build(0xAB, bytes((touch,)))).sw == sw


@pytest.mark.skipif(
    not HAS_CORE_RSA, reason="feuristic.core.rsa not available yet (written by another agent)"
)
def test_generate_rsa2048(admin, store):
    r = generate(admin, 0x9A, consts.ALG_RSA2048)
    assert r.sw == 0x9000
    tmpl = tlv.find(r.data, 0x7F49)
    n = tlv.find(tmpl, 0x81)
    assert len(n) == 256 and tlv.find(tmpl, 0x82) == b"\x01\x00\x01"
    assert store.get_slot(0x9A).rsa_key().n == n


@pytest.mark.skipif(HAS_CORE_RSA, reason="only meaningful while feuristic.core.rsa is absent")
def test_generate_rsa_without_core_rsa_is_unsupported(admin):
    assert generate(admin, 0x9A, consts.ALG_RSA2048).sw == 0x6A81


# -- ECDSA ---------------------------------------------------------------------------


def test_ecdsa_sign_9a_verifies(admin):
    pub = gen_ec(admin, 0x9A)
    assert verify(admin).sw == 0x9000
    r = sign(admin, 0x9A, DIGEST)
    assert r.sw == 0x9000
    der = dyn_value(r)
    assert der[0] == 0x30
    verify_ecdsa(pub, der, DIGEST)


def test_ecdsa_response_template(admin):
    gen_ec(admin, 0x9A)
    verify(admin)
    r = sign(admin, 0x9A, DIGEST)
    assert r.data[0] == 0x7C
    assert tlv.parse(r.data)[0][0] == 0x7C
    assert [t for t, _ in tlv.parse(tlv.find(r.data, 0x7C))] == [0x82]


def test_ecdsa_tag_order_independent(admin):
    pub = gen_ec(admin, 0x9A)
    verify(admin)
    r = tx(admin, 0x87, 0x11, 0x9A, dyn((0x81, DIGEST), (0x82, b"")))
    verify_ecdsa(pub, dyn_value(r), DIGEST)


def test_ecdsa_long_input_truncated_short_padded(admin):
    pub = gen_ec(admin, 0x9A)
    verify(admin)
    h384 = hashlib.sha384(b"x").digest()
    verify_ecdsa(pub, dyn_value(sign(admin, 0x9A, h384)), h384[:32])
    h20 = hashlib.sha1(b"x").digest()
    verify_ecdsa(pub, dyn_value(sign(admin, 0x9A, h20)), bytes(12) + h20)


@pytest.mark.parametrize("n", [0, 65, 200])
def test_ecdsa_bad_input_length(admin, n):
    gen_ec(admin, 0x9A)
    verify(admin)
    assert sign(admin, 0x9A, bytes(n)).sw == 0x6A80


def test_sign_prompt_contents(admin, ui, french):
    pub = gen_ec(admin, 0x9C)
    verify(admin)
    assert sign(admin, 0x9C, DIGEST).sw == 0x9000
    p = ui.prompts[-1]
    assert (p.kind, p.title, p.severity) == ("piv.sign", "piv.prompt.sign", SENSITIVE)
    fields = dict(p.fields)
    assert fields["piv.field.operation"] == "Signature"
    assert fields["piv.field.slot"] == "Signature numérique (9C)"
    assert fields["piv.field.algorithm"] == "ECC P-256"
    assert fields["piv.field.fingerprint"] == spki_sha256(pub) == p.fingerprint
    assert fields["piv.field.data"] == "Signature d'empreinte non interprétée"
    assert p.slot == 0x9C


def test_english_uninterpreted_label(admin, ui):
    gen_ec(admin, 0x9A)
    verify(admin)
    sign(admin, 0x9A, DIGEST)
    assert dict(ui.prompts[-1].fields)["piv.field.data"] == "Uninterpreted digest signature"
    assert i18n.language() == i18n.EN


def test_refusal_on_device(admin, ui):
    gen_ec(admin, 0x9A)
    verify(admin)
    ui.answers = [False]
    r = sign(admin, 0x9A, DIGEST)
    assert (r.data, r.sw) == (b"", 0x6982)


def test_sign_empty_slot(piv):
    verify(piv)
    assert sign(piv, 0x9A, DIGEST).sw == 0x6A88


def test_sign_algorithm_mismatch(admin):
    gen_ec(admin, 0x9A)
    verify(admin)
    assert sign(admin, 0x9A, bytes(256), consts.ALG_RSA2048).sw == 0x6A86


@pytest.mark.parametrize("p2", [0x82, 0x95, 0x80, 0x00])
def test_general_authenticate_bad_slot(piv, p2):
    assert sign(piv, p2, DIGEST).sw == 0x6A86


@pytest.mark.parametrize(
    "items",
    [
        ((0x81, DIGEST),),
        ((0x82, b"\x00"), (0x81, DIGEST)),
        ((0x82, b""), (0x81, DIGEST), (0x80, b"")),
        ((0x80, b""), (0x81, DIGEST)),
    ],
)
def test_bad_dynamic_templates(admin, items):
    gen_ec(admin, 0x9A)
    verify(admin)
    assert tx(admin, 0x87, 0x11, 0x9A, dyn(*items)).sw == 0x6A80


# -- PIN policies ----------------------------------------------------------------------


def test_9a_pin_once_per_session(admin, ui):
    gen_ec(admin, 0x9A)
    assert sign(admin, 0x9A, DIGEST).sw == 0x6982
    verify(admin)
    for _ in range(3):
        assert sign(admin, 0x9A, DIGEST).sw == 0x9000
    admin.deselect()
    assert sign(admin, 0x9A, DIGEST).sw == 0x6982


def test_9c_pin_always(admin):
    gen_ec(admin, 0x9C)
    verify(admin)
    assert sign(admin, 0x9C, DIGEST).sw == 0x9000
    assert sign(admin, 0x9C, DIGEST).sw == 0x6982
    verify(admin)
    assert sign(admin, 0x9C, DIGEST).sw == 0x9000


def test_9c_refused_prompt_still_consumes_pin(admin, ui):
    gen_ec(admin, 0x9C)
    verify(admin)
    ui.answers = [False]
    assert sign(admin, 0x9C, DIGEST).sw == 0x6982
    assert sign(admin, 0x9C, DIGEST).sw == 0x6982  # PIN must be presented again


def test_9c_always_does_not_affect_9a(admin):
    gen_ec(admin, 0x9A)
    gen_ec(admin, 0x9C)
    verify(admin)
    assert sign(admin, 0x9C, DIGEST).sw == 0x9000
    assert sign(admin, 0x9A, DIGEST).sw == 0x9000  # session PIN still valid


def test_9e_no_pin_but_confirmation(admin, ui):
    pub = gen_ec(admin, 0x9E)
    challenge = os.urandom(32)
    r = sign(admin, 0x9E, challenge)
    assert r.sw == 0x9000
    verify_ecdsa(pub, dyn_value(r), challenge)
    p = ui.prompts[-1]
    assert (p.kind, p.title) == ("piv.card_auth", "piv.prompt.cardauth")
    assert dict(p.fields)["piv.field.operation"] == "Challenge-response"


def test_9e_refusal(admin, ui):
    gen_ec(admin, 0x9E)
    ui.answers = [False]
    assert sign(admin, 0x9E, os.urandom(32)).sw == 0x6982


def test_pin_verification_does_not_skip_confirmation(admin, ui):
    gen_ec(admin, 0x9A)
    verify(admin)
    before = len(ui.prompts)
    sign(admin, 0x9A, DIGEST)
    sign(admin, 0x9A, DIGEST)
    assert len(ui.prompts) == before + 2


def test_pin_checked_before_prompt(admin, ui):
    gen_ec(admin, 0x9A)
    before = len(ui.prompts)
    assert sign(admin, 0x9A, DIGEST).sw == 0x6982
    assert len(ui.prompts) == before


# -- ECDH (9D) ---------------------------------------------------------------------------


def test_ecdh_9d(admin, ui):
    pub = gen_ec(admin, 0x9D)
    verify(admin)
    peer = ec.generate_private_key(ec.SECP256R1())
    point = peer.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    r = tx(admin, 0x87, 0x11, 0x9D, dyn((0x82, b""), (0x85, point)), 256)
    assert r.sw == 0x9000
    assert dyn_value(r) == peer.exchange(ec.ECDH(), pub)
    p = ui.prompts[-1]
    assert p.kind == "piv.ecdh"
    assert "piv.field.data" not in dict(p.fields)


@pytest.mark.parametrize(
    "point",
    [
        b"\x04" + bytes(64),
        b"\x04" + b"\x01" * 64,
        b"\x02" + bytes(32),
        b"\x04" + b"\xff" * 64,
        bytes(65),
    ],
)
def test_ecdh_invalid_point(admin, ui, point):
    gen_ec(admin, 0x9D)
    verify(admin)
    before = len(ui.prompts)
    assert tx(admin, 0x87, 0x11, 0x9D, dyn((0x82, b""), (0x85, point))).sw == 0x6A80
    assert len(ui.prompts) == before  # rejected before asking the user


def test_ecdh_requires_pin(admin):
    gen_ec(admin, 0x9D)
    peer = ec.generate_private_key(ec.SECP256R1()).public_key()
    point = peer.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    assert tx(admin, 0x87, 0x11, 0x9D, dyn((0x82, b""), (0x85, point))).sw == 0x6982


def test_key_usage_separation(admin):
    gen_ec(admin, 0x9A)
    gen_ec(admin, 0x9D)
    verify(admin)
    peer = ec.generate_private_key(ec.SECP256R1()).public_key()
    point = peer.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    assert tx(admin, 0x87, 0x11, 0x9A, dyn((0x82, b""), (0x85, point))).sw == 0x6A80  # no ECDH on 9A
    assert sign(admin, 0x9D, DIGEST).sw == 0x6A80  # no ECDSA with the key management key


# -- RSA-2048 (key restored from a cryptography-generated key) -------------------------------


def restore_rsa(store, key, slot=0x9A):
    nums = key.private_numbers()
    obj = {
        "type": "piv",
        "v": 1,
        "slot": slot,
        "alg": consts.ALG_RSA2048,
        "p": nums.p.to_bytes(128, "big"),
        "q": nums.q.to_bytes(128, "big"),
        "e": 65537,
        "pin_policy": consts.DEFAULT_PIN_POLICY[slot],
    }
    provider.PivBackupProvider(store).restore_identity(obj, overwrite=True)


def pkcs1_v15_sha256(msg: bytes) -> bytes:
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(msg).digest()
    return b"\x00\x01" + b"\xff" * (256 - 3 - len(digest_info)) + b"\x00" + digest_info


def test_rsa_sign(piv, store, rsa_private_key, ui):
    restore_rsa(store, rsa_private_key)
    verify(piv)
    msg = b"hello PIV"
    r = sign(piv, 0x9A, pkcs1_v15_sha256(msg), consts.ALG_RSA2048)
    assert r.sw == 0x9000
    assert r.data[:4] == bytes.fromhex("7c820104")
    sig = dyn_value(r)
    assert len(sig) == 256
    rsa_private_key.public_key().verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
    p = ui.prompts[-1]
    assert p.kind == "piv.rsa"
    assert dict(p.fields)["piv.field.algorithm"] == "RSA 2048"
    assert p.fingerprint == spki_sha256(rsa_private_key.public_key())


def test_rsa_decrypt_9d(piv, store, rsa_private_key):
    restore_rsa(store, rsa_private_key, 0x9D)
    verify(piv)
    secret = os.urandom(32)
    ct = rsa_private_key.public_key().encrypt(secret, padding.PKCS1v15())
    r = sign(piv, 0x9D, ct, consts.ALG_RSA2048)
    block = dyn_value(r)
    assert block[:2] == b"\x00\x02" and block.endswith(b"\x00" + secret)


@pytest.mark.parametrize("bad", ["short", "long", "too_big"])
def test_rsa_bad_input(piv, store, rsa_private_key, bad):
    restore_rsa(store, rsa_private_key)
    verify(piv)
    n = rsa_private_key.public_key().public_numbers().n
    data = {"short": bytes(255), "long": bytes(257), "too_big": n.to_bytes(256, "big")}[bad]
    assert sign(piv, 0x9A, data, consts.ALG_RSA2048).sw == 0x6A80


def test_rsa_metadata_public_key(piv, store, rsa_private_key):
    restore_rsa(store, rsa_private_key)
    r = tx(piv, 0xF7, 0, 0x9A)
    items = dict(tlv.parse(r.data))
    assert items[0x01] == b"\x07"
    assert items[0x02] == b"\x02\x02"
    assert items[0x03] == b"\x02"  # imported (restored from backup)
    pub = dict(tlv.parse(items[0x04]))
    assert int.from_bytes(pub[0x81], "big") == rsa_private_key.public_key().public_numbers().n
    assert pub[0x82] == b"\x01\x00\x01"


def test_metadata_ec_slot(admin):
    r = generate(admin, 0x9E)
    md = dict(tlv.parse(tx(admin, 0xF7, 0, 0x9E).data))
    assert md[0x01] == b"\x11"
    assert md[0x02] == b"\x01\x02"
    assert md[0x03] == b"\x01"
    assert md[0x04] == tlv.find(r.data, 0x7F49)


def test_metadata_errors(piv):
    assert tx(piv, 0xF7, 0, 0x9A).sw == 0x6A88
    assert tx(piv, 0xF7, 0, 0x55).sw == 0x6A88
    assert tx(piv, 0xF7, 1, 0x9A).sw == 0x6A86


def test_signature_wrong_key_fails_verification(admin):
    gen_ec(admin, 0x9A)
    other = gen_ec(admin, 0x9C)
    verify(admin)
    with pytest.raises(InvalidSignature):
        verify_ecdsa(other, dyn_value(sign(admin, 0x9A, DIGEST)), DIGEST)
