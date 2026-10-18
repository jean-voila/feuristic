# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Fixtures of the AES-256-GCM / RNG profile tests."""

import pytest

from feuristic.apps.card.aes import keys, rng
from feuristic.apps.card.aes.applet import AesApplet
from feuristic.core import i18n
from feuristic.core.interaction import ScriptedInteraction

MS = bytes(range(100, 132))


@pytest.fixture
def ui():
    return ScriptedInteraction()


@pytest.fixture
def service():
    rng._reset_default()
    s = rng.RngService()
    yield s
    rng._reset_default()


@pytest.fixture
def store(service):
    keys._reset_default()
    s = keys.AesKeyStore()
    s.load()
    yield s
    keys._reset_default()


@pytest.fixture
def aes(ui, store, service):
    return AesApplet(ui, store=store, master_secret=MS, rng=service)


@pytest.fixture
def key1(store, service):
    return store.create("backup", rng=service.health.random_bytes)


@pytest.fixture
def french():
    i18n.set_language(i18n.FR)
    yield
    i18n.set_language(i18n.EN)
