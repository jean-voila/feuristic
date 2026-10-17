# SPDX-License-Identifier: GPL-3.0-only
import pytest

from feuristic.apps.backup import provider
from feuristic.apps.backup.errors import UnsupportedItem
from feuristic.core.errors import InvalidInput

from .fakes import DuckProvider, FakeProvider


def test_register_get_all_order(registry):
    a, b, c = FakeProvider("otp"), FakeProvider("fido2"), DuckProvider()
    for p in (a, b, c):
        registry.register(p)
    assert registry.all() == [a, b, c]
    assert registry.get("fido2") is b
    assert registry.get("duck") is c
    registry.register(a)  # idempotent for the same object
    with pytest.raises(ValueError):
        registry.register(FakeProvider("otp"))
    registry.unregister("fido2")
    assert registry.all() == [a, c]
    registry.unregister("nope")
    with pytest.raises(UnsupportedItem):
        registry.get("fido2")
    with pytest.raises(UnsupportedItem):
        registry.get(None)
    registry.clear()
    assert registry.all() == []


def test_all_returns_copy(registry):
    registry.register(FakeProvider("otp"))
    lst = registry.all()
    lst.clear()
    assert len(registry.all()) == 1


@pytest.mark.parametrize("t", ["", "A", "1abc", "a b", "é", "a" * 17, None, 3, "-x"])
def test_invalid_types(registry, t):
    p = FakeProvider()
    p.TYPE = t
    assert not provider.is_valid_type(t)
    with pytest.raises(ValueError):
        registry.register(p)


@pytest.mark.parametrize("t", ["otp", "fido2", "openpgp", "piv", "aes", "a", "x_y-z", "a" * 16])
def test_valid_types(t):
    assert provider.is_valid_type(t)


def test_check_item_common():
    provider.check_item_common({"type": "otp", "v": 1, "x": b""}, "otp")
    provider.check_item_common({"type": "otp", "v": 255})
    for bad in (
        [],
        {"type": "otp"},
        {"type": "otp", "v": 0},
        {"type": "otp", "v": 256},
        {"type": "otp", "v": False},
        {"type": "otp", "v": "1"},
        {"type": "OTP", "v": 1},
        {"type": "otp", "v": 1, 1: 2},
        {"v": 1},
    ):
        with pytest.raises(InvalidInput):
            provider.check_item_common(bad)
    with pytest.raises(InvalidInput):
        provider.check_item_common({"type": "otp", "v": 1}, "fido2")


def test_check_helpers():
    assert provider.check_uid(b"\x01") == b"\x01"
    assert provider.check_uid(bytearray(32)) == bytes(32)
    for bad in (b"", bytes(33), "uid", None):
        with pytest.raises(InvalidInput):
            provider.check_uid(bad)
    assert provider.check_label("é" * 64) == "é" * 64
    for bad in ("é" * 65, None, b"label"):
        with pytest.raises(InvalidInput):
            provider.check_label(bad)
    assert provider.check_fingerprint(None) == ""
    assert provider.check_fingerprint("") == ""
    assert provider.check_fingerprint("00AAff") == "00AAff"
    for bad in ("0g", "a" * 65, 12, b"00"):
        with pytest.raises(InvalidInput):
            provider.check_fingerprint(bad)


def test_base_class_defaults():
    p = provider.BackupProvider()
    for call in (
        p.list_identities,
        lambda: p.export_identity(b"x"),
        lambda: p.exists({}),
        lambda: p.describe({}),
        lambda: p.restore_identity({}, False),
    ):
        with pytest.raises(NotImplementedError):
            call()
    assert p.on_exported(b"x") is None
    p.TYPE = "otp"
    p.validate({"type": "otp", "v": 1})
    with pytest.raises(InvalidInput):
        p.validate({"type": "piv", "v": 1})
