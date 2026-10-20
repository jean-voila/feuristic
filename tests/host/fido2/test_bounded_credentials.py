# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Full-capacity selection must not retain every decoded private key."""

import weakref

import pytest
from ctap_harness import CDH

from feuristic.apps.fido2 import credentials as cr
from feuristic.platform import crypto


def test_one_rp_at_capacity_keeps_private_keys_bounded(device, ctap2, monkeypatch):
    alive = weakref.WeakSet()
    peak = 0
    decode = cr.decode_record

    def observed(*args):
        nonlocal peak
        credential = decode(*args)
        alive.add(credential)
        peak = max(peak, len(alive))
        return credential

    monkeypatch.setattr(cr, "decode_record", observed)
    rp = "a" * 63 + "." + "b" * 56 + ".example"
    for index in range(100):
        device.auth.store.create_resident(
            rp,
            index.to_bytes(64, "big"),
            "n" * 64,
            "d" * 64,
            cr.ALG_ES256,
            (index + 1).to_bytes(32, "big"),
            cr.PROTECT_UV_OPTIONAL,
            True,
            True,
        )
    credentials = device.auth.store.for_rp(crypto.sha256(rp.encode()))
    assert len(credentials) == 100
    assert len(credentials[10:15]) == 5
    assert credentials[0].user_id == (99).to_bytes(64, "big")
    assert len(credentials.labels()[10:15]) == 5
    assertion = ctap2.get_assertion(rp, CDH)
    assert assertion.user["id"] == (99).to_bytes(64, "big")
    assert peak <= 4


def test_memory_exhaustion_cannot_hide_an_existing_credential(device, monkeypatch):
    credential = device.auth.store.create_resident(
        "example.com", b"alice", "Alice", "Alice", cr.ALG_ES256, b"\x01" * 32, 1, False, False
    )

    def exhausted(*args):
        raise MemoryError()

    monkeypatch.setattr(cr, "decode_record", exhausted)
    with pytest.raises(MemoryError):
        device.auth.store.get(credential.uid)
    with pytest.raises(MemoryError):
        device.auth.store.find_user(crypto.sha256(b"example.com"), b"alice")
    device.auth.store.invalidate()
    with pytest.raises(MemoryError):
        device.auth.store.count()


def test_owner_digest_collision_cannot_delete_either_credential(device, monkeypatch, kv):
    from feuristic.core.errors import StorageCorrupted

    for user in (b"alice", b"bob"):
        device.auth.store.create_resident(
            "example.com", user, "Name", "Display", cr.ALG_ES256, b"\x01" * 32, 1, False, False
        )
    before = dict(kv.data)
    digest = crypto.sha256

    def colliding_owner(data):
        return b"c" * 32 if len(data) in (35, 37) else digest(data)

    monkeypatch.setattr(crypto, "sha256", colliding_owner)
    device.auth.store.invalidate()
    with pytest.raises(StorageCorrupted):
        device.auth.store.count()
    assert kv.data == before
