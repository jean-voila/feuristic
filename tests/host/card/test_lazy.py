# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Applet unloading releases its own modules and preserves session policy."""

import sys
from types import ModuleType

import pytest

from feuristic.apps.card.lazy import LazyApplet


class Instance:
    def deselect(self):
        pass

    def reset(self):
        pass


def test_deselection_unloads_only_factory_modules(monkeypatch):
    existing = ModuleType("lazy_existing")
    later = ModuleType("lazy_later")
    monkeypatch.setitem(sys.modules, existing.__name__, existing)

    def factory(_name):
        sys.modules["lazy_owned"] = ModuleType("lazy_owned")
        return Instance()

    applet = LazyApplet("piv", b"aid", factory, unload_on_deselect=True)
    first = applet._get()
    monkeypatch.setitem(sys.modules, later.__name__, later)
    applet.deselect()
    assert applet._instance is None and "lazy_owned" not in sys.modules
    assert sys.modules[existing.__name__] is existing
    assert sys.modules[later.__name__] is later
    assert applet._get() is not first
    applet.reset()
    assert "lazy_owned" not in sys.modules


def test_failed_factory_does_not_pin_partially_loaded_modules():
    def factory(_name):
        sys.modules["lazy_failed"] = ModuleType("lazy_failed")
        raise MemoryError("allocation failure")

    applet = LazyApplet("piv", b"aid", factory, unload_on_deselect=True)
    with pytest.raises(MemoryError):
        applet._get()
    assert applet._instance is None and "lazy_failed" not in sys.modules


def test_aes_instance_survives_deselection_for_session_approvals():
    applet = LazyApplet("aes", b"aid", lambda _name: Instance())
    instance = applet._get()
    instance.session_approvals = {3}
    applet.deselect()
    assert applet._get() is instance
    assert applet._get().session_approvals == {3}
