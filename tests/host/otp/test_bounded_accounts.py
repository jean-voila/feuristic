# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Full-capacity OTP writes and unlock do not retain every decoded secret."""

import weakref

import pytest

from feuristic.apps.otp import accounts, uri


def test_full_capacity_queries_keep_decoded_secrets_bounded(monkeypatch):
    alive = weakref.WeakSet()
    peak = 0
    decode = accounts._decode

    def observed(*args):
        nonlocal peak
        account = decode(*args)
        alive.add(account)
        peak = max(peak, len(alive))
        return account

    monkeypatch.setattr(accounts, "_decode", observed)
    db = accounts.OtpAccounts()
    for number in range(32):
        label = str(number)
        name = label + "x" * (64 - len(label))
        db.add(uri.OtpParams("hotp", "i" * 32, name, b"s" * 64, "SHA512", 8, counter=1000))
    assert len(db) == 32
    assert len(db._used_indices()) == 32
    assert db.find("i" * 32, "0" + "x" * 63).secret == b"s" * 64
    db.load()
    assert peak <= 4


def test_oom_during_lookup_cannot_hide_existing_account(monkeypatch):
    db = accounts.OtpAccounts()
    db.add(uri.OtpParams("totp", "Corp", "Alice", b"s" * 20))

    def exhausted(*args):
        raise MemoryError()

    monkeypatch.setattr(accounts, "_decode", exhausted)
    with pytest.raises(MemoryError):
        db.find("Corp", "Alice")
    with pytest.raises(MemoryError):
        db._used_indices()
