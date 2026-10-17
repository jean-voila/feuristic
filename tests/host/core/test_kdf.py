# SPDX-License-Identifier: GPL-3.0-only
import pytest

from feuristic.core import kdf
from feuristic.core.errors import InvalidInput


def test_derive_is_deterministic_and_separated():
    ms = bytes(range(32))
    a = kdf.derive(ms, b"fido2/cred-wrap")
    assert a == kdf.derive(ms, b"fido2/cred-wrap")
    assert a != kdf.derive(ms, b"fido2/u2f-wrap")
    assert a != kdf.derive(ms, b"fido2/cred-wrap", context=b"x")
    assert len(kdf.derive(ms, b"card/serial", 16)) == 16


def test_known_answer():
    # Pin the construction: HKDF-SHA256(ms, "feuristic/v1", label || 0x00 || ctx)
    import hashlib
    import hmac

    ms = bytes(32)
    prk = hmac.new(b"feuristic/v1", ms, hashlib.sha256).digest()
    okm = hmac.new(prk, b"card/serial\x00\x01", hashlib.sha256).digest()
    assert kdf.derive(ms, b"card/serial") == okm


def test_rejects_unknown_label_and_bad_ms():
    with pytest.raises(InvalidInput):
        kdf.derive(bytes(32), b"nope")
    with pytest.raises(InvalidInput):
        kdf.derive(bytes(31), b"card/serial")


def test_labels_are_unique_prefix_free():
    labels = list(kdf.LABELS)
    for x in labels:
        for y in labels:
            if x != y:
                assert not y.startswith(x + b"\x00")
