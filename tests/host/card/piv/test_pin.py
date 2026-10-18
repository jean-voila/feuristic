# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""VERIFY / CHANGE REFERENCE DATA / RESET RETRY COUNTER (SP 800-73-4 Part 2 §3.2)."""

import pytest

from feuristic.apps.card.piv import consts, storage
from feuristic.apps.card.piv.applet import PivApplet
from feuristic.platform import testing

from .conftest import MS
from .pivutil import pad, tx, verify

PIN = b"123456"
PUK = b"12345678"


def change(piv, ref, old, new):
    return tx(piv, 0x24, 0, ref, pad(old) + pad(new))


def unblock(piv, puk, new):
    return tx(piv, 0x2C, 0, 0x80, pad(puk) + pad(new))


def test_default_pin_verifies(piv):
    assert verify(piv).sw == 0x9000
    assert piv.pin_verified


def test_query_status(piv):
    assert tx(piv, 0x20, 0, 0x80).sw == 0x63C3
    verify(piv)
    assert tx(piv, 0x20, 0, 0x80).sw == 0x9000


def test_wrong_pin_counts_down_and_blocks(piv, store):
    assert verify(piv, b"000000").sw == 0x63C2
    assert verify(piv, b"000000").sw == 0x63C1
    assert verify(piv, b"000000").sw == 0x63C0
    assert verify(piv, b"000000").sw == 0x6983
    assert verify(piv, PIN).sw == 0x6983  # correct PIN no longer accepted
    assert tx(piv, 0x20, 0, 0x80).sw == 0x6983
    assert store.is_blocked(consts.REF_PIN)


def test_success_resets_counter(piv, store):
    verify(piv, b"000000")
    verify(piv, b"000000")
    assert verify(piv).sw == 0x9000
    assert store.retries_remaining(consts.REF_PIN) == 3


def test_failed_verify_clears_security_status(piv):
    verify(piv)
    assert verify(piv, b"999999").sw == 0x63C2
    assert not piv.pin_verified


def test_reset_security_status(piv):
    verify(piv)
    assert tx(piv, 0x20, 0xFF, 0x80).sw == 0x9000
    assert not piv.pin_verified
    assert tx(piv, 0x20, 0xFF, 0x80, pad(PIN)).sw == 0x6A80


@pytest.mark.parametrize(
    "data",
    [
        b"123456",  # not padded
        b"12345\xff\xff\xff",  # 5 characters
        b"1234\xff567\xff",  # padding in the middle
        b"123456\xff\xff\xff",  # 9 bytes
        b"\x01\x02\x03\x04\x05\x06\xff\xff",  # non-printable
    ],
)
def test_bad_pin_format_does_not_count(piv, store, data):
    assert tx(piv, 0x20, 0, 0x80, data).sw == 0x6A80
    assert store.retries_remaining(consts.REF_PIN) == 3


@pytest.mark.parametrize("p2", [0x00, 0x81, 0x96, 0x9B])
def test_verify_unsupported_reference(piv, p2):
    assert tx(piv, 0x20, 0, p2, pad(PIN)).sw == 0x6A88


def test_verify_bad_p1(piv):
    assert tx(piv, 0x20, 0x01, 0x80, pad(PIN)).sw == 0x6A86


def test_retry_counter_persisted_before_compare(piv, store, monkeypatch):
    seen = []
    real = storage.Credentials.matches

    def spy(self, ref, padded):
        seen.append(store.pin_counter.get())
        return real(self, ref, padded)

    monkeypatch.setattr(storage.Credentials, "matches", spy)
    verify(piv)
    verify(piv, b"000000")
    assert seen == [1, 1]  # the failure was recorded before each comparison


def test_power_loss_during_success_costs_an_attempt(piv, store):
    # increment writes B then A (2 ops); the reset after success is cut
    testing.KV.crash_after_ops = testing.KV.ops + 2
    with pytest.raises(testing.PowerLoss):
        verify(piv)
    store.load()
    assert store.retries_remaining(consts.REF_PIN) == 2


def test_power_loss_before_increment_grants_nothing(piv, store):
    testing.KV.crash_after_ops = testing.KV.ops
    with pytest.raises(testing.PowerLoss):
        verify(piv, b"000000")
    assert not piv.pin_verified


def test_counter_survives_new_applet_instance(ui, store):
    a = PivApplet(ui, store=store, master_secret=MS)
    verify(a, b"000000")
    b = PivApplet(ui, store=storage.PivStore(), master_secret=MS)
    assert tx(b, 0x20, 0, 0x80).sw == 0x63C2


def test_change_pin(piv, store):
    assert change(piv, 0x80, PIN, b"24681357").sw == 0x9000
    assert verify(piv, PIN).sw == 0x63C2
    assert verify(piv, b"24681357").sw == 0x9000
    assert not store.creds().flags & storage.FLAG_PIN_DEFAULT
    # persisted
    fresh = storage.PivStore()
    assert fresh.creds().matches(consts.REF_PIN, pad(b"24681357"))


def test_change_pin_wrong_old(piv):
    assert change(piv, 0x80, b"111111", b"222222").sw == 0x63C2
    assert verify(piv).sw == 0x9000


def test_change_back_to_default_sets_flag(piv, store):
    change(piv, 0x80, PIN, b"777777")
    change(piv, 0x80, b"777777", PIN)
    assert store.creds().flags & storage.FLAG_PIN_DEFAULT


def test_change_puk(piv, store):
    assert change(piv, 0x81, PUK, b"87654321").sw == 0x9000
    assert unblock(piv, PUK, b"111111").sw == 0x63C2
    assert unblock(piv, b"87654321", b"111111").sw == 0x9000


@pytest.mark.parametrize(
    "data",
    [pad(PIN), pad(PIN) + pad(b"1234"), pad(PIN) + b"\xff" * 8, pad(PIN) + pad(b"654321") + b"\x00"],
)
def test_change_reference_malformed(piv, data):
    assert tx(piv, 0x24, 0, 0x80, data).sw == 0x6A80


def test_change_reference_bad_params(piv):
    assert tx(piv, 0x24, 1, 0x80, pad(PIN) + pad(b"654321")).sw == 0x6A86
    assert tx(piv, 0x24, 0, 0x9B, pad(PIN) + pad(b"654321")).sw == 0x6A88


def test_block_and_unblock_with_puk(piv, store):
    for _ in range(3):
        verify(piv, b"000000")
    assert verify(piv).sw == 0x6983
    assert unblock(piv, PUK, b"135790").sw == 0x9000
    assert store.retries_remaining(consts.REF_PIN) == 3
    assert verify(piv, b"135790").sw == 0x9000


def test_puk_blocks(piv, store):
    assert unblock(piv, b"00000000", b"135790").sw == 0x63C2
    assert unblock(piv, b"00000000", b"135790").sw == 0x63C1
    assert unblock(piv, b"00000000", b"135790").sw == 0x63C0
    assert unblock(piv, PUK, b"135790").sw == 0x6983
    assert change(piv, 0x81, PUK, b"11111111").sw == 0x6983
    assert store.is_blocked(consts.REF_PUK)


def test_reset_retry_counter_bad_params(piv):
    assert tx(piv, 0x2C, 0, 0x81, pad(PUK) + pad(b"135790")).sw == 0x6A88
    assert tx(piv, 0x2C, 1, 0x80, pad(PUK) + pad(b"135790")).sw == 0x6A86
    assert tx(piv, 0x2C, 0, 0x80, pad(PUK)).sw == 0x6A80


def test_pin_change_voids_session_status(piv):
    verify(piv)
    change(piv, 0x80, PIN, b"222222")
    assert tx(piv, 0x20, 0, 0x80).sw == 0x63C3  # must verify the new PIN


def test_alphanumeric_host_pin(piv):
    assert change(piv, 0x80, PIN, b"Ab1!xyz").sw == 0x9000
    assert verify(piv, b"Ab1!xyz").sw == 0x9000


def test_deselect_and_reset_drop_status(piv):
    verify(piv)
    piv.deselect()
    assert not piv.pin_verified
    verify(piv)
    piv.reset()
    assert not piv.pin_verified


def test_metadata_pin_puk(piv):
    r = tx(piv, 0xF7, 0, 0x80)
    assert r.data == bytes.fromhex("0101ff050101060203 03".replace(" ", ""))
    verify(piv, b"000000")
    change(piv, 0x81, PUK, b"99999999")
    assert tx(piv, 0xF7, 0, 0x80).data == bytes.fromhex("0101ff050101060203 02".replace(" ", ""))
    assert tx(piv, 0xF7, 0, 0x81).data == bytes.fromhex("0101ff050100060203 03".replace(" ", ""))
