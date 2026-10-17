# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Fixtures of the FIDO2 test-suite (python-fido2 against the simulated device)."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

from ctap_harness import Device, SimUI, open_hid  # noqa: E402
from fido2.ctap2 import Ctap2  # noqa: E402


@pytest.fixture
def ui():
    return SimUI()


@pytest.fixture
def device(ui):
    return Device(ui)


@pytest.fixture
def hid(device):
    return open_hid(device)


@pytest.fixture
def ctap2(hid):
    return Ctap2(hid)
