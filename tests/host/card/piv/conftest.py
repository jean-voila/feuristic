# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Fixtures of the PIV applet tests."""

import pytest

from feuristic.apps.card.piv import storage
from feuristic.apps.card.piv.applet import PivApplet
from feuristic.core import i18n
from feuristic.core.interaction import ScriptedInteraction

MS = bytes(range(32))


@pytest.fixture
def ui():
    return ScriptedInteraction()


@pytest.fixture
def store():
    storage._reset_default()
    s = storage.PivStore()
    s.load()
    yield s
    storage._reset_default()


@pytest.fixture
def piv(ui, store):
    return PivApplet(ui, store=store, master_secret=MS)


@pytest.fixture
def french():
    i18n.set_language(i18n.FR)
    yield
    i18n.set_language(i18n.EN)


@pytest.fixture(scope="session")
def rsa_private_key():
    from cryptography.hazmat.primitives.asymmetric import rsa

    return rsa.generate_private_key(public_exponent=65537, key_size=2048)
