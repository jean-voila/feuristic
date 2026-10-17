# SPDX-License-Identifier: GPL-3.0-only
"""Shared pytest configuration for host (CPython) unit tests."""

import os
import sys

import pytest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "shims"))
sys.path.insert(0, os.path.join(HERE, "..", "..", "src"))

from feuristic.platform import testing  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_platform():
    """Every test starts with empty storage, a fresh clock and the real RNG."""
    testing.reset_all()
    yield
    testing.reset_all()


@pytest.fixture
def kv():
    return testing.KV


@pytest.fixture
def clock():
    return testing.CLOCK


@pytest.fixture
def det_rng():
    testing.set_rng(testing.deterministic_rng())
    yield
    testing.set_rng(None)
