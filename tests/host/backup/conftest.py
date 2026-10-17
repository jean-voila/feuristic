# SPDX-License-Identifier: GPL-3.0-only
import pytest

from feuristic.apps.backup import envelope, provider


@pytest.fixture
def fast_kdf(monkeypatch):
    """Lower the PBKDF2 iteration count for speed (format tests use the real one)."""
    monkeypatch.setattr(envelope, "ITERATIONS", 1000)
    monkeypatch.setattr(envelope, "KDF_CHUNK", 300)
    return 1000


@pytest.fixture
def registry():
    provider.clear()
    yield provider
    provider.clear()
