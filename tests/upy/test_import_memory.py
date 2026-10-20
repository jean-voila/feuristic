# SPDX-License-Identifier: GPL-3.0-only
"""Bounded collection and real native decoder allocation lifetimes.

The unix heap uses 64-bit objects and keeps the MCU's CCM state on its heap;
these regressions establish release/reuse, not physical hardware RAM fit.
"""

import gc

import feuristic_import
from upytest import raises, run, storage_setup, test

from feuristic.apps.backup import frames
from feuristic.apps.importer.session import DEVICE_MAX_BACKUPS, DEVICE_MAX_BYTES, DUPLICATE, ImportSession


@test
def packed_native_identity_pauses_without_retaining_decoder_workspaces():
    native = feuristic_import.Session(b"Import memory test", 512, 1)
    collector = ImportSession(DEVICE_MAX_BACKUPS, DEVICE_MAX_BYTES, compact=True)
    size = 5127  # maximum OpenPGP export measured by host provider regression
    count = frames.frame_count(size, frames.PROFILE_LARGE)
    base = size // count
    extra = size - count * base
    # No list of all encoded QR texts is kept alongside the decoder.
    for index in range(count - 1, -1, -1):
        length = base + (1 if index < extra else 0)
        text = frames.encode_frame(b"memory01", index + 1, count, b"x" * length)
        assert collector.add_payload(text.encode()).accepted
    assert collector.bytes_used() == size
    gc.collect()
    active = gc.mem_alloc()
    assert native.pause_decode()
    gc.collect()
    paused = gc.mem_alloc()
    assert active - paused >= 110_000
    raw = collector.take_complete()
    assert len(raw) == size and raw == b"x" * size
    assert collector.bytes_used() == 0 and collector.counts() == (0, 0)
    raw = None
    gc.collect()
    assert native.resume_decode()
    assert native.pause_decode()
    native.close()
    collector.abort()


@test
def packed_ledger_cannot_report_an_incomplete_identity_complete():
    collector = ImportSession(DEVICE_MAX_BACKUPS, DEVICE_MAX_BYTES, compact=True)
    text = frames.encode_frame(b"memory02", 2, 3, b"encrypted bytes")
    assert collector.add_payload(text.encode()).accepted
    assert collector.take_complete() is None
    assert collector.counts() == (0, 1)
    assert collector.progress()[0].missing == [1, 3]
    assert collector.add_payload(text.encode()).status == DUPLICATE
    assert collector.bytes_used() == len(b"encrypted bytes")
    collector.abort()


@test
def application_modules_require_suspended_transports_and_preserve_shared_state():
    import sys

    from feuristic.apps.backup import provider
    from feuristic.core import clock
    from feuristic.core.errors import InvalidInput
    from feuristic.fw import device, session, transports

    storage_setup()
    session.register_strings()
    device.initialize()
    session._load_stores()
    registry = provider.all()
    shared_clock = clock.CLOCK
    transports.fido_server()
    transports._card_obj()
    __import__("feuristic.ui.app_aes")
    __import__("feuristic.ui.app_openpgp")
    __import__("feuristic.apps.backup.restore")
    raises(RuntimeError, session.release_import_modules)
    transports.suspend()
    session.release_import_modules()
    for name in (
        "feuristic.apps.fido2.ctap2",
        "feuristic.apps.card.openpgp.storage",
        "feuristic.apps.card.piv.storage",
        "feuristic.apps.card.aes.keys",
        "feuristic.ui.app_aes",
        "feuristic.ui.app_openpgp",
        "feuristic.apps.backup.restore",
        "feuristic.apps.backup.export",
        "feuristic.apps.backup.envelope",
    ):
        assert name not in sys.modules
        parent, attr = name.rsplit(".", 1)
        module = sys.modules.get(parent)
        assert module is None or not hasattr(module, attr)
    assert provider.all() == registry
    assert sys.modules["feuristic.core.clock"].CLOCK is shared_clock
    assert "feuristic.apps.fido2.strings" in sys.modules
    assert sys.modules["feuristic.apps.backup.frames"] is frames
    transports.resume()
    try:
        # Fresh NORMAL providers share the original error/registry classes.
        for p in registry:
            raises(InvalidInput, p.validate, {"type": p.TYPE, "v": 1})
        assert transports.fido_server().app.auth is not None
        assert transports._card_obj().dispatcher.applets
    finally:
        transports.suspend()
        session.release_import_modules()


@test
def otp_caller_catches_reimported_totp_exception_after_import():
    from feuristic.apps.otp.totp import TimeNotSynchronised as OldException
    from feuristic.fw import session
    from feuristic.ui import app_otp, screens

    session.release_import_modules()
    from feuristic.apps.otp.totp import TimeNotSynchronised

    assert TimeNotSynchronised is not OldException
    warnings = []

    class Store:
        def get(self, uid):
            return None

        def totp_code(self, uid):
            raise TimeNotSynchronised()

    async def warning(*args, **kwargs):
        warnings.append(args)

    old_store, old_warning = app_otp._store, screens.show_warning
    app_otp._store = Store
    screens.show_warning = warning
    try:
        coro = app_otp._show_totp(b"account1")
        try:
            coro.send(None)
        except StopIteration:
            pass
        else:
            raise AssertionError("unexpected OTP screen suspension")
        assert len(warnings) == 1
    finally:
        app_otp._store, screens.show_warning = old_store, old_warning


@test
def card_select_loads_only_requested_applets_and_preserves_aes_session_policy():
    import sys

    from feuristic.fw import session, transports

    def drive(coro):
        try:
            while True:
                coro.send(None)
        except StopIteration as result:
            return result.value

    def select(card, aid):
        response = drive(card.transmit(b"\x00\xa4\x04\x00" + bytes((len(aid),)) + aid))
        assert response[-2:] == b"\x90\x00"

    session.release_import_modules()
    transports.resume()
    try:
        card = transports._card_obj()
        for kind in ("openpgp", "piv", "aes"):
            assert "feuristic.apps.card." + kind + ".applet" not in sys.modules
        assert drive(card.transmit(b"\x00\x84\x00\x00\x20"))[-2:] == b"\x90\x00"
        pgp, piv, aes = card.dispatcher.applets
        select(card, pgp.AID)
        assert pgp._instance.AID == pgp.AID
        assert piv._instance is None and aes._instance is None
        assert "feuristic.apps.card.piv.applet" not in sys.modules
        assert "feuristic.apps.card.aes.applet" not in sys.modules
        pgp._instance._verified[0] = True
        select(card, piv.AID)
        assert not any(pgp._instance._verified)
        assert aes._instance is None
        select(card, aes.AID)
        aes._instance._session_ok.add(7)
        select(card, piv.AID)
        select(card, aes.AID)
        assert 7 in aes._instance._session_ok
        card.dispatcher.reset()
        assert not aes._instance._session_ok
    finally:
        transports.suspend()
        session.release_import_modules()


@test
def translations_use_frozen_constants_without_retaining_application_dicts():
    from feuristic.apps.card.aes import strings
    from feuristic.core import i18n
    from feuristic.fw import session

    assert i18n.FIRMWARE and isinstance(i18n._ROM, tuple)
    gc.collect()
    before = gc.mem_alloc()
    session.register_strings()
    gc.collect()
    assert gc.mem_alloc() - before < 256
    assert i18n._tables == []
    strings.register()
    assert strings.STRINGS == {}
    previous = i18n.language()
    try:
        for key, values in i18n._ROM:
            for language in (i18n.EN, i18n.FR):
                i18n.set_language(language)
                assert i18n.t(key) == (values[language] or values[i18n.EN])
        i18n.set_language(i18n.EN)
        assert i18n.t("backup.ui.frames", 4) == "4 QR images"
        i18n.set_language(i18n.FR)
        assert i18n.t("backup.ui.frames", 4) == "4 images QR"
    finally:
        i18n.set_language(previous)


run()
