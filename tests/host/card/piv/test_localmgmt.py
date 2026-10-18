# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""On-device PIV management (menus)."""

import pytest

from feuristic.apps.card.piv import consts, localmgmt, storage
from feuristic.core import i18n
from feuristic.core.errors import InvalidInput, UserCancelled
from feuristic.core.interaction import DANGER, SENSITIVE, ScriptedInteraction

from ...aio import run
from .pivutil import cert_object, generate, mgmt_auth, put_data, sign, tx, verify
from .test_x509 import make_cert


def test_initial_status_and_warnings(store):
    st = localmgmt.slots_status(store)
    assert [s.slot for s in st] == [0x9A, 0x9C, 0x9D, 0x9E]
    assert all(s.status_key == "piv.slot.empty" for s in st)
    assert [s.pin_policy for s in st] == [2, 3, 2, 1]
    assert localmgmt.warnings(store) == [
        "piv.warn.default_pin",
        "piv.warn.default_puk",
        "piv.warn.default_mgmt",
    ]


def test_generate_and_delete(store):
    ui = ScriptedInteraction()
    s = run(localmgmt.generate(0x9A, consts.ALG_P256, ui, store))
    assert s.has_key and s.alg_name == "ECC P-256" and len(s.fingerprint) == 16
    assert s.status_key == "piv.slot.key_only"
    assert ui.prompts[-1].severity == SENSITIVE
    run(localmgmt.generate(0x9A, consts.ALG_P256, ui, store))
    assert ui.prompts[-1].severity == DANGER  # replacing
    assert run(localmgmt.delete_slot(0x9A, ui, store))
    assert ui.prompts[-1].kind == "piv.delete"
    assert not run(localmgmt.delete_slot(0x9A, ui, store))


def test_refusals(store):
    with pytest.raises(UserCancelled):
        run(localmgmt.generate(0x9C, consts.ALG_P256, ScriptedInteraction(default=False), store))
    run(localmgmt.generate(0x9C, consts.ALG_P256, ScriptedInteraction(), store))
    with pytest.raises(UserCancelled):
        run(localmgmt.delete_slot(0x9C, ScriptedInteraction(default=False), store))
    assert store.get_slot(0x9C).has_key


def test_bad_arguments(store):
    ui = ScriptedInteraction()
    with pytest.raises(InvalidInput):
        run(localmgmt.generate(0x9B, consts.ALG_P256, ui, store))
    with pytest.raises(InvalidInput):
        run(localmgmt.generate(0x9A, 0x14, ui, store))


def test_cert_summary(piv, store):
    assert localmgmt.cert_summary(0x9A, store) == (None, "piv.no_cert")
    der, _ = make_cert(subject_cn="bob")
    mgmt_auth(piv)
    put_data(piv, consts.OBJ_CERT_9A, cert_object(der))
    summary, err = localmgmt.cert_summary(0x9A, store)
    assert err is None and summary.subject_cn == "bob"
    fields = dict(localmgmt.cert_fields(summary))
    assert fields["piv.field.issuer"] == "Example CA"
    put_data(piv, consts.OBJ_CERT_9C, cert_object(b"\x1f\x8b", 1))
    assert localmgmt.cert_summary(0x9C, store) == (None, "piv.cert.compressed")
    put_data(piv, consts.OBJ_CERT_9D, cert_object(b"\x30\x01\x00"))
    assert localmgmt.cert_summary(0x9D, store) == (None, "piv.cert.unreadable")
    st = {s.slot: s.status_key for s in localmgmt.slots_status(store)}
    assert st[0x9A] == "piv.slot.cert_only"
    assert localmgmt.certificate(0x9A, store) == (der, 0)


def test_set_pin_puk_and_init_identity(piv, store):
    localmgmt.init_identity("246810", "13579135", store)
    assert localmgmt.warnings(store) == ["piv.warn.default_mgmt"]
    assert verify(piv, b"123456").sw == 0x63C2
    assert verify(piv, b"246810").sw == 0x9000
    with pytest.raises(InvalidInput):
        localmgmt.init_identity("111111", "111111", store)


@pytest.mark.parametrize("bad", ["12345", "123456789", "12a456", "", b"\xff\xff\xff\xff\xff\xff"])
def test_device_pin_digits_only(store, bad):
    with pytest.raises(InvalidInput):
        localmgmt.set_pin(bad, store)


def test_local_set_pin_unblocks(piv, store):
    for _ in range(3):
        verify(piv, b"000000")
    assert "piv.warn.pin_blocked" in localmgmt.warnings(store)
    localmgmt.set_pin("654321", store)
    assert localmgmt.retries(store)["pin"] == (3, 3)
    assert verify(piv, b"654321").sw == 0x9000


def test_mgmt_key_generate_and_default(piv, store):
    key = localmgmt.generate_mgmt_key(consts.ALG_AES256, store)
    assert len(key) == 32
    assert localmgmt.mgmt_key_info(store) == ("AES-256", False)
    mgmt_auth(piv, key, consts.ALG_AES256)
    localmgmt.reset_mgmt_key_default(store)
    assert localmgmt.mgmt_key_info(store) == ("AES-192", True)
    mgmt_auth(piv)
    with pytest.raises(InvalidInput):
        localmgmt.generate_mgmt_key(0x07, store)
    k3 = localmgmt.generate_mgmt_key(consts.ALG_3DES, store)
    mgmt_auth(piv, k3, consts.ALG_3DES)


def test_reset(piv, store):
    mgmt_auth(piv)
    generate(piv, 0x9A)
    localmgmt.set_pin("999999", store)
    with pytest.raises(UserCancelled):
        run(localmgmt.reset(ScriptedInteraction(default=False), store))
    ui = ScriptedInteraction()
    run(localmgmt.reset(ui, store))
    assert ui.prompts[-1].kind == "piv.reset" and ui.prompts[-1].severity == DANGER
    assert store.get_slot(0x9A) is None
    assert verify(piv, b"123456").sw == 0x9000
    assert not piv.mgmt_authenticated  # host session voided by the local reset


def test_set_pin_policy_stricter_only(piv, store):
    mgmt_auth(piv)
    generate(piv, 0x9E)
    localmgmt.set_pin_policy(0x9E, consts.PIN_POLICY_ONCE, store)
    assert sign(piv, 0x9E, bytes(32)).sw == 0x6982
    with pytest.raises(InvalidInput):
        localmgmt.set_pin_policy(0x9C, consts.PIN_POLICY_ONCE, store)
    with pytest.raises(InvalidInput):
        localmgmt.set_pin_policy(0x9A, consts.PIN_POLICY_ALWAYS, store)  # empty slot


def test_strings_complete():
    from feuristic.apps.card.piv import strings

    strings.register()
    strings.register()  # idempotent
    for key, (en, fr) in strings.STRINGS.items():
        assert key.startswith("piv.") and en and fr
    assert "piv." not in "".join(i18n.missing_translations())


def test_yubikey_style_reset(piv, store, ui):
    mgmt_auth(piv)
    generate(piv, 0x9A)
    assert tx(piv, 0xFB, 0, 0).sw == 0x6985  # PIN/PUK not blocked
    for _ in range(3):
        verify(piv, b"000000")
    assert tx(piv, 0xFB, 0, 0).sw == 0x6985  # PUK still usable
    for _ in range(3):
        tx(piv, 0x2C, 0, 0x80, b"00000000" + b"111111\xff\xff")
    ui.answers = [False]
    assert tx(piv, 0xFB, 0, 0).sw == 0x6982
    assert tx(piv, 0xFB, 0, 1).sw == 0x6A86
    assert tx(piv, 0xFB, 0, 0).sw == 0x9000
    assert ui.prompts[-1].kind == "piv.reset"
    assert store.get_slot(0x9A) is None
    assert verify(piv).sw == 0x9000
    assert storage.FLAG_PIN_DEFAULT & store.creds().flags
