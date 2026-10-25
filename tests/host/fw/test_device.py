# SPDX-License-Identifier: GPL-3.0-only
"""Device initialisation never replaces a stored master secret."""

import pytest

from feuristic.core import namespaces as ns
from feuristic.fw import device
from feuristic.platform import testing


@pytest.fixture(autouse=True)
def _forget_cache():
    device.forget_master_secret()
    yield
    device.forget_master_secret()


def test_first_initialisation_creates_a_secret(kv):
    device.initialize()
    ms = kv.get(ns.SYS, ns.SYS_MASTER_SECRET)
    assert ms is not None and len(ms) == 32
    assert device.is_initialized()
    assert device.master_secret() == ms


def test_interrupted_onboarding_keeps_the_existing_secret(kv):
    device.initialize()
    ms = kv.get(ns.SYS, ns.SYS_MASTER_SECRET)
    # Power cut before the public flag was written, or the flag was lost.
    kv.delete(ns.SYS_PUBLIC, ns.SYS_PUB_INITIALIZED, True)
    device.forget_master_secret()
    assert not device.is_initialized()

    device.initialize()

    assert kv.get(ns.SYS, ns.SYS_MASTER_SECRET) == ms
    assert device.master_secret() == ms
    assert device.is_initialized()


@pytest.mark.parametrize("stored", [b"", b"\x00" * 31, b"\x01" * 33])
def test_malformed_secret_is_replaced(kv, stored):
    kv.set(ns.SYS, ns.SYS_MASTER_SECRET, stored)
    device.initialize()
    ms = kv.get(ns.SYS, ns.SYS_MASTER_SECRET)
    assert len(ms) == 32 and ms != stored


def test_wiped_storage_gets_a_fresh_secret(kv):
    device.initialize()
    first = kv.get(ns.SYS, ns.SYS_MASTER_SECRET)
    testing.KV.reset()  # models config.wipe()
    device.forget_master_secret()
    device.initialize()
    assert kv.get(ns.SYS, ns.SYS_MASTER_SECRET) != first


def test_master_secret_is_protected_storage(kv):
    device.initialize()
    ms = kv.get(ns.SYS, ns.SYS_MASTER_SECRET)
    # SYS and SYS_PUBLIC share an id; the public key 0 is the schema byte.
    assert kv.get(ns.SYS, ns.SYS_MASTER_SECRET, True) != ms
    testing.KV.unlocked = False
    device.forget_master_secret()
    with pytest.raises(RuntimeError):
        device.master_secret()


def test_current_or_older_schema_is_supported(kv):
    assert device.schema_supported()  # nothing stored yet
    device.initialize()
    assert device.schema_supported()
    kv.set(ns.SYS_PUBLIC, ns.SYS_PUB_SCHEMA, bytes((device.SCHEMA_VERSION - 1,)), True)
    assert device.schema_supported()


def test_newer_schema_is_refused(kv):
    device.initialize()
    kv.set(ns.SYS_PUBLIC, ns.SYS_PUB_SCHEMA, bytes((device.SCHEMA_VERSION + 1,)), True)
    assert not device.schema_supported()


def test_schema_check_works_while_locked(kv):
    device.initialize()
    kv.set(ns.SYS_PUBLIC, ns.SYS_PUB_SCHEMA, bytes((device.SCHEMA_VERSION + 1,)), True)
    testing.KV.unlocked = False
    assert not device.schema_supported()
