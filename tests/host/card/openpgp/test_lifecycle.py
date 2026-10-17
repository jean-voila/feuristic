# SPDX-License-Identifier: GPL-3.0-only
"""OpenPGP TERMINATE DF / ACTIVATE FILE (GnuPG factory-reset), persistence and
power-loss behaviour of the identity records."""

import pytest

from feuristic.apps.card.openpgp import const as pgp
from feuristic.core import namespaces
from feuristic.core.interaction import DANGER
from feuristic.platform import testing

from .conftest import Env


def setup_identity(e):
    e.admin()
    assert e.generate(0xB6)[1] == 0x9000
    assert e.generate(0xB8)[1] == 0x9000
    e.put(0x5B, b"Doe<<John")
    e.put(0x5F50, b"https://example.org/k")
    e.put(0x7F21, b"\x30" + bytes(1500))
    e.put(0xD3, b"resetcode")


def test_terminate_requires_admin_or_blocked_pw3(env):
    assert env.tx(0xE6)[1] == 0x6982
    assert env.ui.prompts == []


def test_terminate_activate_flow(env):
    setup_identity(env)
    env.admin()
    assert env.tx(0xE6)[1] == 0x9000
    p = env.ui.prompts[-1]
    assert p.kind == "openpgp.terminate" and p.severity == DANGER
    assert env.select() == (b"", 0x6285)
    assert env.get(0x4F)[1] == 0x6985
    assert env.verify(0x81, b"123456") == 0x6985
    # survives a reboot in the terminated state
    env.reboot()
    assert env.select() == (b"", 0x6285)
    assert env.tx(0x44)[1] == 0x9000
    assert env.select() == (b"", 0x9000)
    assert env.read_public(0xB6)[1] == 0x6A88
    assert env.get(0x5B)[0] == b""
    assert env.get(0x7F21)[0] == b""
    assert env.get(0xC4)[0] == bytes.fromhex("017F7F7F030003")
    assert env.verify(0x81, b"123456") == 0x9000
    assert env.verify(0x83, b"12345678") == 0x9000


def test_gnupg_factory_reset_sequence(env):
    """gpg --card-edit → admin → factory-reset: block PINs, TERMINATE, ACTIVATE."""
    setup_identity(env)
    env.reboot().select()
    for _ in range(4):
        env.raw(bytes.fromhex("002000810840404040404040 40".replace(" ", "")))
    for _ in range(4):
        env.raw(bytes.fromhex("002000830840404040404040 40".replace(" ", "")))
    assert env.get(0xC4)[0][6] == 0
    assert env.raw(bytes.fromhex("00E60000")) == (b"", 0x9000)
    assert env.raw(bytes.fromhex("00440000")) == (b"", 0x9000)
    assert env.select() == (b"", 0x9000)
    assert env.get(0xC4)[0][4:] == b"\x03\x00\x03"


def test_terminate_refused_keeps_everything():
    e = Env(answers=[True, True, False])
    e.select()
    setup_identity(e)
    assert e.tx(0xE6)[1] == 0x6985
    assert e.select() == (b"", 0x9000)
    assert e.read_public(0xB6)[1] == 0x9000


def test_activate_when_operational_is_noop(env):
    setup_identity(env)
    assert env.tx(0x44)[1] == 0x9000
    assert env.read_public(0xB6)[1] == 0x9000
    assert env.tx(0x44, 1, 0)[1] == 0x6A86
    assert env.tx(0xE6, 0, 1)[1] == 0x6A86


def test_identity_persists_across_reload():
    e = Env()
    e.select()
    setup_identity(e)
    pub = e.read_public(0xB6)[0]
    e.reboot().select()
    assert e.read_public(0xB6)[0] == pub
    assert e.get(0x5B)[0] == b"Doe<<John"
    assert e.get(0x7F21)[0] == b"\x30" + bytes(1500)
    assert e.get(0xC4)[0][5] == 3  # resetting code set
    # OpenPGP uses only CARD keys 0x00–0x03 and CARD_COUNTERS keys 0x10–0x1F
    for app, key in testing.KV.data:
        if app == namespaces.CARD:
            assert 0x00 <= key <= 0x03
        elif app == namespaces.CARD_COUNTERS | 0x80:
            assert 0x10 <= key <= 0x1F


def test_identity_record_size_bounded():
    e = Env()
    e.select()
    setup_identity(e)
    e.store.load()
    raw = e.store.records.get(pgp.UID_IDENTITY)
    assert len(raw) <= pgp.MAX_IDENTITY_PAYLOAD


def test_garbage_aux_record_collected():
    e = Env()
    e.select()
    setup_identity(e)
    ref = e.store._aux_ref
    other = pgp.UID_AUX[1 - ref]
    e.store.records.put(other, b"\xa0")  # leftover of an interrupted update
    e.reboot().select()
    assert other not in e.store.records
    assert e.get(0x5F50)[0] == b"https://example.org/k"


def _ops(fn):
    testing.KV.ops = 0
    fn()
    return testing.KV.ops


@pytest.mark.parametrize("tag", [0x5F50, 0x5B])
def test_power_loss_during_put_data(tag):
    """Every crash point leaves the old or the new identity, never a mix."""
    e = Env()
    e.select()
    setup_identity(e)
    old = e.get(tag)[0]
    new = b"https://new.example.org" if tag == 0x5F50 else b"New<<Name"
    snapshot = dict(testing.KV.data)
    e.reboot().select()
    e.admin()
    n = _ops(lambda: e.put(tag, new))
    for k in range(n):
        testing.KV.data = dict(snapshot)
        e.reboot().select()
        e.admin()
        testing.KV.ops = 0
        testing.KV.crash_after_ops = k
        with pytest.raises(testing.PowerLoss):
            e.put(tag, new)
        testing.KV.crash_after_ops = None
        e.reboot().select()
        assert e.get(tag)[0] in (old, new)
        assert e.get(0x7F21)[0] == b"\x30" + bytes(1500)
        assert e.get(0x5B)[0] in (b"Doe<<John", new)
        assert e.read_public(0xB6)[1] == 0x9000


def test_power_loss_during_terminate():
    e = Env()
    e.select()
    setup_identity(e)
    snapshot = dict(testing.KV.data)
    e.reboot().select()
    e.admin()
    n = _ops(lambda: e.tx(0xE6))
    for k in range(n):
        testing.KV.data = dict(snapshot)
        e.reboot().select()
        e.admin()
        testing.KV.ops = 0
        testing.KV.crash_after_ops = k
        with pytest.raises(testing.PowerLoss):
            e.tx(0xE6)
        testing.KV.crash_after_ops = None
        e.reboot()
        sw = e.select()[1]
        if sw == 0x9000:  # old identity fully intact
            assert e.read_public(0xB6)[1] == 0x9000
            assert e.get(0x7F21)[0] == b"\x30" + bytes(1500)
        else:
            assert sw == 0x6285


def test_storage_full_rolls_back(env, kv):
    env.admin()
    kv.capacity = kv.used_bytes() + 200
    assert env.put(0x7F21, bytes(2000)) == 0x6A84
    assert env.get(0x7F21)[0] == b""
    kv.capacity = kv.SECTOR_BYTES
    assert env.put(0x7F21, bytes(2000)) == 0x9000
