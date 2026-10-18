# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""R04 with real encrypted norcow, including compaction and A/B rewrites."""

from upytest import run, storage_setup, test

from feuristic.apps.fido2.context import Context
from feuristic.apps.fido2.credentials import ALG_ES256
from feuristic.apps.fido2.ctap2 import Authenticator
from feuristic.apps.fido2.largeblobs import serialize
from feuristic.apps.otp.accounts import OtpAccounts
from feuristic.apps.otp.uri import OtpParams
from feuristic.core.interaction import ScriptedInteraction


def drive(coro):
    try:
        while True:
            coro.send(None)
    except StopIteration as exc:
        return exc.value


@test
def maximum_capacity_with_updates():
    ui = ScriptedInteraction()
    auth = Authenticator(Context(b"m" * 32, ui))
    auth.pin.local_set_pin("123456")
    rp = "a" * 63 + "." + "b" * 56 + ".example"
    for i in range(100):
        auth.store.create_resident(
            rp,
            i.to_bytes(64, "big"),
            "n" * 64,
            "d" * 64,
            ALG_ES256,
            (i + 1).to_bytes(32, "big"),
            3,
            True,
            True,
        )
    otp = OtpAccounts()
    first = None
    for i in range(32):
        name = str(i) + "x" * (64 - len(str(i)))
        uid = otp.add(OtpParams("hotp", "i" * 32, name, b"s" * 64, "SHA512", 8, counter=1000))
        drive(otp.generate_hotp(uid, ui))
        if first is None:
            first = uid
    for value in (b"x", b"y", b"z"):
        entries = [{1: value * 4074}]
        assert len(serialize(entries)) == 4096
        auth.large_blobs.write_entries(entries)
        assert auth.large_blobs.entries() == entries
    # With live data near the sector limit, this must compact successfully.
    for _ in range(20):
        cred = auth.store.for_rp(auth.store.rps()[0][1])[0]
        auth.store.update_user(cred, "n" * 64, "d" * 64)
        account = otp.get(first)
        otp.rename(first, account.issuer, account.account)
    reloaded = Authenticator(Context(b"m" * 32, ui))
    assert reloaded.store.count() == 100
    assert reloaded.large_blobs.entries() == entries
    assert len(OtpAccounts().accounts()) == 32
    assert OtpAccounts().hotp_counter(first) == 1001


storage_setup()
run()
