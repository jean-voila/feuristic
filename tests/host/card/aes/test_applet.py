# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""feuristic AES-256-GCM ISO/IEC 7816-8 profile v1 (docs/protocols/aes-gcm-iso7816-v1.md)."""

import os

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from feuristic.apps.card.aes import applet as aes_mod
from feuristic.apps.card.aes import keys
from feuristic.core import kdf, namespaces, tlv
from feuristic.core.interaction import SENSITIVE
from feuristic.platform import testing

from .aesutil import AID, decipher, encipher, mse, select, split, tx
from .conftest import MS


def setup_both(aes, kid):
    assert mse(aes, kid, 0xF1).sw == 0x9000


# -- SELECT / MSE ------------------------------------------------------------------


def test_aid(aes):
    assert AID == b"\xf0" + b"feuristic" + b"\x01"
    assert aes.matches(AID) and aes.matches(AID[:4]) and not aes.matches(bytes.fromhex("A000000308"))


def test_select_fci_exact(aes):
    r = select(aes)
    assert r.sw == 0x9000
    assert r.data == bytes.fromhex(
        "6f23840bf066657572697374696301a51480010181014782020e0083020100840110850120"
    )
    assert select(aes, 0x0C).data == b""


def test_mse_variants(aes, key1):
    assert mse(aes, key1.kid, 0x81).sw == 0x9000
    assert aes._env == [key1.kid, None]
    assert mse(aes, key1.kid, 0x41, alg=False, ref_tag=0x84).sw == 0x9000
    assert aes._env == [key1.kid, key1.kid]


@pytest.mark.parametrize(
    "data",
    [
        b"",
        tlv.build(0x80, b"\x47"),
        tlv.build(0x80, b"\x48") + tlv.build(0x83, b"\x01"),
        tlv.build(0x83, b"\x01") + tlv.build(0x84, b"\x01"),
        tlv.build(0x83, b"\x01\x00"),
        tlv.build(0x83, b"\x01") + tlv.build(0x83, b"\x01"),
        tlv.build(0x83, b"\x01") + tlv.build(0x95, b"\x40"),
        b"\x83\x05\x01",
    ],
)
def test_mse_malformed(aes, key1, data):
    assert tx(aes, 0x22, 0x81, 0xB8, data).sw == 0x6A80


@pytest.mark.parametrize(("p1", "p2"), [(0x01, 0xB8), (0x81, 0xA4), (0x81, 0xB6), (0xF3, 0x01), (0x41, 0xAA)])
def test_mse_bad_p1p2(aes, key1, p1, p2):
    assert tx(aes, 0x22, p1, p2, tlv.build(0x83, b"\x01")).sw == 0x6A86


@pytest.mark.parametrize("kid", [0, 2, 16, 17, 255])
def test_mse_unknown_key(aes, key1, kid):
    assert mse(aes, kid).sw == 0x6A88


def test_mse_disabled_key(aes, store, key1):
    store.set_enabled(key1.kid, False)
    assert mse(aes, key1.kid).sw == 0x6A88


# -- round trips ------------------------------------------------------------------------


@pytest.mark.parametrize("n", [0, 1, 15, 16, 17, 255, 1000, aes_mod.MAX_MESSAGE])
def test_roundtrip_and_reference(aes, key1, n):
    setup_both(aes, key1.kid)
    pt = os.urandom(n)
    r = encipher(aes, pt)
    assert r.sw == 0x9000
    nonce, ct, tag = split(r)
    assert len(nonce) == 12 and len(tag) == 16 and len(ct) == n
    # interoperable with any AES-256-GCM implementation
    assert AESGCM(key1.key).decrypt(nonce, ct + tag, None) == pt
    d = decipher(aes, nonce, ct, tag)
    assert (d.data, d.sw) == (pt, 0x9000)


def test_aad(aes, key1):
    setup_both(aes, key1.kid)
    aad = b"header v1"
    nonce, ct, tag = split(encipher(aes, b"secret", aad))
    assert AESGCM(key1.key).decrypt(nonce, ct + tag, aad) == b"secret"
    assert decipher(aes, nonce, ct, tag, aad).data == b"secret"
    assert decipher(aes, nonce, ct, tag).sw == 0x6988
    assert decipher(aes, nonce, ct, tag, b"header v2").sw == 0x6988
    with pytest.raises(InvalidTag):
        AESGCM(key1.key).decrypt(nonce, ct + tag, None)


def test_max_aad(aes, key1):
    setup_both(aes, key1.kid)
    aad = os.urandom(aes_mod.MAX_AAD)
    pt = os.urandom(aes_mod.MAX_MESSAGE)
    nonce, ct, tag = split(encipher(aes, pt, aad))
    assert decipher(aes, nonce, ct, tag, aad).data == pt


def test_decipher_accepts_encipher_output_verbatim(aes, key1):
    setup_both(aes, key1.kid)
    r = encipher(aes, b"abc", b"x")
    d = tx(aes, 0x2A, 0x80, 0x84, tlv.build(0x81, b"x") + r.data, 256)
    assert d.data == b"abc"
    # field order is free on input
    nonce, ct, tag = split(r)
    data = tlv.build(0x83, tag) + tlv.build(0x80, ct) + tlv.build(0x81, b"x") + tlv.build(0x82, nonce)
    assert tx(aes, 0x2A, 0x80, 0x84, data, 256).data == b"abc"


def test_decrypt_foreign_ciphertext(aes, key1):
    """Data encrypted elsewhere with the same key (e.g. restored key) decrypts."""
    setup_both(aes, key1.kid)
    nonce = os.urandom(12)
    sealed = AESGCM(key1.key).encrypt(nonce, b"from the host", b"a")
    assert decipher(aes, nonce, sealed[:-16], sealed[-16:], b"a").data == b"from the host"


@pytest.mark.parametrize("what", ["ct", "tag", "nonce", "aad", "truncated_ct"])
def test_tamper_releases_nothing(aes, key1, what):
    setup_both(aes, key1.kid)
    nonce, ct, tag = split(encipher(aes, b"attack at dawn", b"meta"))
    aad = b"meta"
    flip = lambda b: bytes([b[0] ^ 1]) + b[1:]  # noqa: E731
    if what == "ct":
        ct = flip(ct)
    elif what == "tag":
        tag = flip(tag)
    elif what == "nonce":
        nonce = flip(nonce)
    elif what == "aad":
        aad = flip(aad)
    else:
        ct = ct[:-1]
    r = decipher(aes, nonce, ct, tag, aad)
    assert (r.data, r.sw) == (b"", 0x6988)


def test_wrong_key_fails_authentication(aes, store, key1):
    k2 = store.create("other", rng=os.urandom)
    assert mse(aes, key1.kid, 0x81).sw == 0x9000
    nonce, ct, tag = split(encipher(aes, b"x"))
    assert mse(aes, k2.kid, 0x41).sw == 0x9000
    assert decipher(aes, nonce, ct, tag).sw == 0x6988


# -- input validation --------------------------------------------------------------------


def test_host_nonce_rejected(aes, key1):
    setup_both(aes, key1.kid)
    data = tlv.build(0x82, bytes(12)) + tlv.build(0x80, b"pt")
    assert tx(aes, 0x2A, 0x84, 0x80, data).sw == 0x6A80
    data = tlv.build(0x80, b"pt") + tlv.build(0x83, bytes(16))
    assert tx(aes, 0x2A, 0x84, 0x80, data).sw == 0x6A80


@pytest.mark.parametrize(
    "data",
    [
        b"",
        tlv.build(0x81, b"aad"),
        tlv.build(0x80, b"a") + tlv.build(0x80, b"b"),
        tlv.build(0x80, b"a") + tlv.build(0x81, b"x") + tlv.build(0x81, b"y"),
        tlv.build(0x84, b"a"),
        b"\x80\x05ab",
    ],
)
def test_encipher_malformed(aes, key1, data):
    setup_both(aes, key1.kid)
    assert tx(aes, 0x2A, 0x84, 0x80, data).sw == 0x6A80


@pytest.mark.parametrize("drop", [0x82, 0x80, 0x83])
def test_decipher_missing_field(aes, key1, drop):
    setup_both(aes, key1.kid)
    items = [(0x82, bytes(12)), (0x80, b"ct"), (0x83, bytes(16))]
    data = tlv.build_many([(t, v) for t, v in items if t != drop])
    assert tx(aes, 0x2A, 0x80, 0x84, data).sw == 0x6A80


@pytest.mark.parametrize(("nlen", "tlen"), [(11, 16), (13, 16), (12, 15), (12, 12), (0, 16)])
def test_decipher_bad_sizes(aes, key1, nlen, tlen):
    setup_both(aes, key1.kid)
    assert decipher(aes, bytes(nlen), b"ct", bytes(tlen)).sw == 0x6A80


def test_message_limits(aes, key1, ui):
    setup_both(aes, key1.kid)
    before = len(ui.prompts)
    assert encipher(aes, bytes(aes_mod.MAX_MESSAGE + 1)).sw == 0x6700
    assert encipher(aes, b"x", bytes(aes_mod.MAX_AAD + 1)).sw == 0x6700
    assert decipher(aes, bytes(12), bytes(aes_mod.MAX_MESSAGE + 1), bytes(16)).sw == 0x6700
    assert len(ui.prompts) == before  # rejected before prompting


def test_pso_without_environment(aes, key1):
    assert encipher(aes, b"x").sw == 0x6985
    assert decipher(aes, bytes(12), b"x", bytes(16)).sw == 0x6985
    assert mse(aes, key1.kid, 0x81).sw == 0x9000
    assert decipher(aes, bytes(12), b"x", bytes(16)).sw == 0x6985  # only encipher was set


def test_key_disabled_or_deleted_after_mse(aes, store, key1):
    setup_both(aes, key1.kid)
    store.set_enabled(key1.kid, False)
    assert encipher(aes, b"x").sw == 0x6985  # key change voided the environment
    store.set_enabled(key1.kid, True)
    setup_both(aes, key1.kid)
    store.delete(key1.kid)
    assert encipher(aes, b"x").sw == 0x6985


@pytest.mark.parametrize(("p1", "p2"), [(0x86, 0x80), (0x80, 0x86), (0x9E, 0x9A), (0x00, 0x00)])
def test_pso_bad_p1p2(aes, key1, p1, p2):
    setup_both(aes, key1.kid)
    assert tx(aes, 0x2A, p1, p2, tlv.build(0x80, b"x")).sw == 0x6A86


@pytest.mark.parametrize("ins", [0x20, 0x47, 0x87, 0xCA, 0xCB, 0xB0])
def test_unsupported_ins(aes, ins):
    assert tx(aes, ins, 0, 0).sw == 0x6D00


@pytest.mark.parametrize(("cla", "sw"), [(0x80, 0x6E00), (0x0C, 0x6882), (0x02, 0x6881)])
def test_cla(aes, key1, cla, sw):
    assert tx(aes, 0x22, 0x81, 0xB8, tlv.build(0x83, b"\x01"), cla=cla).sw == sw


def test_missing_master_secret(ui, store, service, key1):
    a = aes_mod.AesApplet(ui, store=store, rng=service)
    setup_both(a, key1.kid)
    assert encipher(a, b"x").sw == 0x6F00


# -- confirmation policy ------------------------------------------------------------------


def test_every_operation_confirmed(aes, key1, ui, french):
    setup_both(aes, key1.kid)
    for _ in range(3):
        encipher(aes, b"x")
    assert ui.kinds() == ["aes.encrypt"] * 3
    p = ui.prompts[0]
    assert (p.title, p.severity, p.key_id) == ("aes.prompt.encrypt", SENSITIVE, key1.kid)
    f = dict(p.fields)
    assert f["aes.field.key"] == "#1 backup"
    assert f["aes.field.length"] == "1 octets"
    assert f["aes.field.fingerprint"] == key1.fingerprint() == p.fingerprint
    assert f["aes.field.operation"] == "Chiffrement AES-256-GCM"


def test_refusal(aes, key1, ui, store):
    setup_both(aes, key1.kid)
    floor = store.nonce_floor()
    ui.answers = [False]
    r = encipher(aes, b"x")
    assert (r.data, r.sw) == (b"", 0x6982)
    assert store.nonce_floor() == floor  # no nonce consumed for a refused operation
    nonce, ct, tag = split(encipher(aes, b"y"))
    ui.answers = [False]
    assert decipher(aes, nonce, ct, tag).sw == 0x6982


def test_session_policy(aes, store, key1, ui):
    store.set_policy(key1.kid, keys.POLICY_SESSION)
    setup_both(aes, key1.kid)
    nonce, ct, tag = split(encipher(aes, b"x"))
    encipher(aes, b"y")
    decipher(aes, nonce, ct, tag)
    assert ui.kinds() == ["aes.encrypt"]
    assert "aes.field.policy" in dict(ui.prompts[0].fields)
    aes.deselect()  # selecting another applet keeps the session confirmation...
    setup_both(aes, key1.kid)
    encipher(aes, b"z")
    assert len(ui.prompts) == 1
    aes.reset()  # ...a card reset (lock, re-enumeration) does not
    setup_both(aes, key1.kid)
    encipher(aes, b"z")
    assert len(ui.prompts) == 2


def test_session_refusal_not_remembered(aes, store, key1, ui):
    store.set_policy(key1.kid, keys.POLICY_SESSION)
    setup_both(aes, key1.kid)
    ui.answers = [False]
    assert encipher(aes, b"x").sw == 0x6982
    assert encipher(aes, b"x").sw == 0x9000
    assert len(ui.prompts) == 2


def test_session_confirmation_voided_by_key_change(aes, store, key1, ui):
    store.set_policy(key1.kid, keys.POLICY_SESSION)
    setup_both(aes, key1.kid)
    encipher(aes, b"x")
    store.rename(key1.kid, "renamed")
    setup_both(aes, key1.kid)
    encipher(aes, b"x")
    assert len(ui.prompts) == 2


# -- nonces -----------------------------------------------------------------------------------


def test_nonce_structure(aes, key1, store):
    setup_both(aes, key1.kid)
    prefix = kdf.derive(MS, b"card/aes-nonce-prefix", 4, key1.uid)
    n1 = split(encipher(aes, b"a"))[0]
    n2 = split(encipher(aes, b"b"))[0]
    assert n1[:4] == n2[:4] == prefix
    assert int.from_bytes(n2[4:], "big") == int.from_bytes(n1[4:], "big") + 1
    # reserved in flash before use
    assert store.counter.get() > int.from_bytes(n2[4:], "big")


def test_nonce_counter_is_global_across_keys(aes, store, key1):
    k2 = store.create("two", rng=os.urandom)
    seen = set()
    for i in range(20):
        mse(aes, key1.kid if i % 2 else k2.kid, 0x81)
        nonce = split(encipher(aes, b"x"))[0]
        seen.add(nonce[4:])
    assert len(seen) == 20


def test_nonce_uniqueness_thousands(aes, key1):
    setup_both(aes, key1.kid)
    nonces = {split(encipher(aes, b""))[0] for _ in range(3000)}
    assert len(nonces) == 3000


def test_nonce_never_reused_across_power_loss(ui, service, key1, store):
    """R12: cut the power at every step of a reservation write, restart, repeat."""
    used = set()
    for crash_at in range(6):
        s = keys.AesKeyStore()
        s.load()
        a = aes_mod.AesApplet(ui, store=s, master_secret=MS, rng=service)
        setup_both(a, key1.kid)
        crashed = False
        for i in range(keys.NONCE_BLOCK + 3):
            if crash_at and i == keys.NONCE_BLOCK:  # this operation must reserve a new block
                testing.KV.crash_after_ops = testing.KV.ops + crash_at - 1
            try:
                r = encipher(a, b"")
            except testing.PowerLoss:
                crashed = True
                break
            nonce = split(r)[0]
            assert nonce not in used
            used.add(nonce)
        testing.KV.crash_after_ops = None
        # advance_to = 2 norcow sets of an existing key = 4 low-level operations
        assert crashed == (1 <= crash_at <= 4)
    assert len(used) > 5 * keys.NONCE_BLOCK


def test_nonce_counter_survives_wipe(aes, store, key1):
    setup_both(aes, key1.kid)
    split(encipher(aes, b"x"))
    floor = store.nonce_floor()
    store.wipe()
    assert store.nonce_floor() == floor
    assert any(app == namespaces.CARD_COUNTERS | 0x80 for app, _ in testing.KV.data)


def test_flash_writes_amortised(aes, key1):
    setup_both(aes, key1.kid)
    encipher(aes, b"x")
    w = testing.KV.writes
    for _ in range(100):
        encipher(aes, b"x")
    assert testing.KV.writes - w <= 2  # at most one reservation (2 redundant copies)


def test_annex_worked_example_is_exact(ui, store, service, monkeypatch):
    """docs/protocols/aes-gcm-iso7816-v1.md §11: byte-exact APDUs."""
    store.put_restored(1, bytes(range(32)), "example", True, keys.POLICY_EVERY)
    monkeypatch.setattr(store, "nonce_prefix", lambda ms, uid: bytes.fromhex("A1B2C3D4"))
    a = aes_mod.AesApplet(ui, store=store, master_secret=MS, rng=service)
    assert tx(a, 0x22, 0x81, 0xB8, bytes.fromhex("800147830101")).sw == 0x9000
    r = tx(a, 0x2A, 0x84, 0x80, bytes.fromhex("8103686472800568656C6C6F"), 256)
    expected = bytes.fromhex("820CA1B2C3D400000000000000008005EA665984F38310D8CB40C46592B03474A27763BA1BED2A")
    assert (r.data, r.sw) == (expected, 0x9000)
    assert tx(a, 0x22, 0x41, 0xB8, bytes.fromhex("800147830101")).sw == 0x9000
    r = tx(a, 0x2A, 0x80, 0x84, bytes.fromhex("8103686472") + expected, 256)
    assert (r.data, r.sw) == (b"hello", 0x9000)
    bad = bytes.fromhex("8103686472") + expected[:-1] + bytes((expected[-1] ^ 1,))
    r = tx(a, 0x2A, 0x80, 0x84, bad, 256)
    assert (r.data, r.sw) == (b"", 0x6988)
