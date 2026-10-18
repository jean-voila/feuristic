# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Administration key (9B) authentication: SP 800-73-4 Part 2 Appendix A.1/A.2."""

import os

import pytest

from feuristic.apps.card.piv import consts, localmgmt, storage
from feuristic.core import tlv

from .pivutil import DEFAULT_KEY, block_cipher, dyn, dyn_value, mgmt_auth, put_data, tx

AES192 = consts.ALG_AES192
TDES = consts.ALG_3DES


def test_default_is_aes192_mutual(piv):
    assert not piv.mgmt_authenticated
    mgmt_auth(piv)
    assert piv.mgmt_authenticated


def test_external_authentication(piv):
    enc, _, bs = block_cipher(AES192, DEFAULT_KEY)
    r = tx(piv, 0x87, AES192, 0x9B, dyn((0x81, b"")))
    assert r.sw == 0x9000
    challenge = dyn_value(r, 0x81)
    assert len(challenge) == bs
    r = tx(piv, 0x87, AES192, 0x9B, dyn((0x82, enc(challenge))))
    assert (r.data, r.sw) == (b"", 0x9000)
    assert piv.mgmt_authenticated


def test_external_authentication_wrong_response(piv):
    tx(piv, 0x87, AES192, 0x9B, dyn((0x81, b"")))
    r = tx(piv, 0x87, AES192, 0x9B, dyn((0x82, os.urandom(16))))
    assert r.sw == 0x6982
    assert not piv.mgmt_authenticated


def test_wrong_witness(piv):
    tx(piv, 0x87, AES192, 0x9B, dyn((0x80, b"")))
    r = tx(piv, 0x87, AES192, 0x9B, dyn((0x80, os.urandom(16)), (0x81, os.urandom(16))))
    assert r.sw == 0x6982
    assert not piv.mgmt_authenticated


def test_failed_attempt_revokes_previous_authentication(piv):
    mgmt_auth(piv)
    tx(piv, 0x87, AES192, 0x9B, dyn((0x80, b"")))
    tx(piv, 0x87, AES192, 0x9B, dyn((0x80, bytes(16)), (0x81, bytes(16))))
    assert not piv.mgmt_authenticated


def test_witness_is_single_use(piv):
    _, dec, _ = block_cipher(AES192, DEFAULT_KEY)
    r = tx(piv, 0x87, AES192, 0x9B, dyn((0x80, b"")))
    w = dec(dyn_value(r, 0x80))
    assert tx(piv, 0x87, AES192, 0x9B, dyn((0x80, w), (0x81, bytes(16)))).sw == 0x9000
    piv.mgmt_authenticated = False
    assert tx(piv, 0x87, AES192, 0x9B, dyn((0x80, w), (0x81, bytes(16)))).sw == 0x6985


def test_step2_without_step1(piv):
    assert tx(piv, 0x87, AES192, 0x9B, dyn((0x80, bytes(16)), (0x81, bytes(16)))).sw == 0x6985
    assert tx(piv, 0x87, AES192, 0x9B, dyn((0x82, bytes(16)))).sw == 0x6985


def test_pending_challenge_dropped_by_other_command(piv):
    _, dec, _ = block_cipher(AES192, DEFAULT_KEY)
    r = tx(piv, 0x87, AES192, 0x9B, dyn((0x80, b"")))
    w = dec(dyn_value(r, 0x80))
    tx(piv, 0xCB, 0x3F, 0xFF, bytes.fromhex("5C017E"))
    assert tx(piv, 0x87, AES192, 0x9B, dyn((0x80, w), (0x81, bytes(16)))).sw == 0x6985


def test_mixing_flows_rejected(piv):
    # witness requested, then an external-auth response is sent
    tx(piv, 0x87, AES192, 0x9B, dyn((0x80, b"")))
    assert tx(piv, 0x87, AES192, 0x9B, dyn((0x82, bytes(16)))).sw == 0x6985


def test_wrong_algorithm(piv):
    assert tx(piv, 0x87, TDES, 0x9B, dyn((0x80, b""))).sw == 0x6A86


def test_wrong_lengths(piv):
    tx(piv, 0x87, AES192, 0x9B, dyn((0x80, b"")))
    assert tx(piv, 0x87, AES192, 0x9B, dyn((0x80, bytes(8)), (0x81, bytes(16)))).sw == 0x6A80
    tx(piv, 0x87, AES192, 0x9B, dyn((0x81, b"")))
    assert tx(piv, 0x87, AES192, 0x9B, dyn((0x82, bytes(15)))).sw == 0x6A80


def test_internal_authenticate_with_admin_key_refused(piv):
    """Would be an encryption oracle answering the external-auth challenge."""
    r = tx(piv, 0x87, AES192, 0x9B, dyn((0x81, bytes(16)), (0x82, b"")))
    assert r.sw == 0x6A80


@pytest.mark.parametrize(
    "data",
    [
        b"",
        tlv.build(0x7D, tlv.build(0x80, b"")),
        dyn((0x80, b""), (0x80, b"")),
        dyn((0x83, b"")),
        dyn((0x80, b"")) + b"\x00",
        bytes.fromhex("7C0580"),
    ],
)
def test_malformed_template(piv, data):
    assert tx(piv, 0x87, AES192, 0x9B, data).sw == 0x6A80


def test_3des_management_key(piv, store):
    key = bytes.fromhex("0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123")
    store.set_mgmt_key(TDES, key)
    mgmt_auth(piv, key, TDES)
    piv.deselect()
    # 3DES external authentication
    enc, _, _ = block_cipher(TDES, key)
    r = tx(piv, 0x87, TDES, 0x9B, dyn((0x81, b"")))
    c = dyn_value(r, 0x81)
    assert len(c) == 8
    assert tx(piv, 0x87, TDES, 0x9B, dyn((0x82, enc(c)))).sw == 0x9000


def test_3des_default_style_key(piv, store):
    store.set_mgmt_key(TDES, DEFAULT_KEY)
    mgmt_auth(piv, DEFAULT_KEY, TDES)


@pytest.mark.parametrize(("alg", "n"), [(consts.ALG_AES128, 16), (consts.ALG_AES256, 32)])
def test_set_management_key_via_apdu(piv, ui, alg, n):
    mgmt_auth(piv)
    new = os.urandom(n)
    r = tx(piv, 0xFF, 0xFF, 0xFF, bytes((alg, 0x9B, n)) + new)
    assert r.sw == 0x9000
    assert ui.kinds()[-1] == "piv.set_mgmt_key"
    assert tx(piv, 0xF7, 0, 0x9B).data == bytes((0x01, 0x01, alg)) + bytes.fromhex(
        "0202010105 0100".replace(" ", "")
    )
    mgmt_auth(piv, new, alg)


def test_set_management_key_requires_auth_and_confirmation(piv, ui):
    data = bytes((AES192, 0x9B, 24)) + os.urandom(24)
    assert tx(piv, 0xFF, 0xFF, 0xFF, data).sw == 0x6982
    mgmt_auth(piv)
    ui.answers = [False]
    assert tx(piv, 0xFF, 0xFF, 0xFF, data).sw == 0x6982
    mgmt_auth(piv)  # still the default key


@pytest.mark.parametrize(
    "data",
    [
        bytes((AES192, 0x9B, 16)) + bytes(16),
        bytes((AES192, 0x9C, 24)) + bytes(24),
        bytes((0x07, 0x9B, 24)) + bytes(24),
        bytes((AES192, 0x9B, 25)) + bytes(24),
        b"\x0a\x9b",
    ],
)
def test_set_management_key_malformed(piv, data):
    mgmt_auth(piv)
    assert tx(piv, 0xFF, 0xFF, 0xFF, data).sw == 0x6A80


def test_set_management_key_bad_p1p2(piv):
    mgmt_auth(piv)
    assert tx(piv, 0xFF, 0xFF, 0x00, bytes((AES192, 0x9B, 24)) + bytes(24)).sw == 0x6A86


def test_metadata_mgmt_default_flag(piv, store):
    assert tx(piv, 0xF7, 0, 0x9B).data == bytes.fromhex("01010a020201010501 01".replace(" ", ""))
    localmgmt.generate_mgmt_key(consts.ALG_AES256, store)
    assert tx(piv, 0xF7, 0, 0x9B).data == bytes.fromhex("01010c020201010501 00".replace(" ", ""))


def test_local_key_change_voids_host_session(piv, store):
    mgmt_auth(piv)
    localmgmt.reset_mgmt_key_default(store)
    assert put_data(piv, consts.OBJ_CCC, b"").sw == 0x6982


def test_authentication_survives_unrelated_commands(piv):
    mgmt_auth(piv)
    tx(piv, 0xCB, 0x3F, 0xFF, bytes.fromhex("5C017E"))
    assert piv.mgmt_authenticated
    assert storage.FLAG_MGMT_DEFAULT  # sanity
