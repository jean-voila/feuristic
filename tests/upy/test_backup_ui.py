# SPDX-License-Identifier: GPL-3.0-only
"""Backup menu state/cleanup tests on the actual MicroPython runtime.

Screens are substituted here; physical/debuglink navigation is covered by
test_menus_backup.py. Cryptographic envelope/frame construction is real.
"""

from upytest import raises, run, test

from feuristic.apps.backup import envelope, export, frames, provider, restore
from feuristic.apps.backup.errors import RestoreLimitExceeded, WeakPassphrase
from feuristic.core.errors import PolicyDenied, UserCancelled
from feuristic.fw import import_mode, pin
from feuristic.ui import app_backup, app_otp, screens


def drive(coro):
    try:
        while True:
            coro.send(None)
    except StopIteration as exc:
        return exc.value


class Patch:
    def __init__(self):
        self.old = []

    def set(self, module, name, value):
        self.old.append((module, name, getattr(module, name)))
        setattr(module, name, value)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        for module, name, value in reversed(self.old):
            setattr(module, name, value)


async def noop(*args, **kwargs):
    return None


async def approve(*args, **kwargs):
    return True


class EntryUI:
    def __init__(self, texts, approved=True):
        self.texts = texts
        self.approved = approved
        self.auth = []
        self.errors = []

    async def text(self, *args, **kwargs):
        return self.texts.pop(0)

    async def reauth(self, distinct_from=None):
        self.auth.append(distinct_from)
        return self.approved

    async def error(self, message):
        self.errors.append(message)

    def install(self, patch):
        patch.set(screens, "show_info", noop)
        patch.set(screens, "confirm", approve)
        patch.set(screens, "show_error", self.error)
        patch.set(screens, "request_text", self.text)
        patch.set(pin, "reauthenticate", self.reauth)


@test
def phrase_confirm_and_reauth_then_owned_buffer():
    ui = EntryUI(["correct horse battery", "wrong phrase value", "123456789012", "123456789012"])
    with Patch() as patch:
        ui.install(patch)
        pw = drive(app_backup._passphrase(None))
        assert pw == b"123456789012"  # numeric phrase distinct from PIN is allowed
        assert len(ui.errors) == 1
        assert ui.auth == [pw]
        app_backup.wipe(pw)


@test
def phrase_policy_retries_and_cancel():
    with Patch() as patch:
        ui = EntryUI(["short", "short", "short"])
        ui.install(patch)
        raises(WeakPassphrase, drive, app_backup._passphrase(None))
        assert not ui.auth and len(ui.errors) == 3
        ui.texts = [None]
        assert drive(app_backup._passphrase(None)) is None
        ui.texts = ["correct horse battery", None]
        assert drive(app_backup._passphrase(None)) is None


@test
def phrase_refused_auth_wipes_buffer():
    ui = EntryUI(["correct horse battery", "correct horse battery"], approved=False)
    with Patch() as patch:
        ui.install(patch)
        raises(UserCancelled, drive, app_backup._passphrase(None))
        assert ui.auth and ui.auth[0] == bytes(len(ui.auth[0]))


class Result:
    frames = ["FB1:A", "FB1:B", "FB1:C"]
    label = "Test identity"
    seq = 1
    count = 1


@test
def qr_navigation_requires_all_frames_and_hides_on_timeout():
    actions = [
        screens.QR_BOTH,
        screens.QR_PREV,
        screens.QR_NEXT,
        screens.QR_PREV,
        screens.QR_NEXT,
        screens.QR_NEXT,
        screens.QR_BOTH,
    ]
    shown = []

    async def page(title, data, timeout_ms, **kwargs):
        assert timeout_ms == 60000
        shown.append(data)
        return actions.pop(0)

    with Patch() as patch:
        patch.set(screens, "show_info", noop)
        patch.set(screens, "confirm", approve)
        patch.set(screens, "show_qr_page", page)
        assert drive(app_backup._display(Result())) is True
        assert shown == ["FB1:A", "FB1:A", "FB1:A", "FB1:B", "FB1:A", "FB1:B", "FB1:C"]
        actions[:] = [None]
        assert drive(app_backup._display(Result())) is False
        actions[:] = [screens.QR_BACK]
        assert drive(app_backup._display(Result())) is False


class FakeProvider(provider.BackupProvider):
    TYPE = "test"

    def __init__(self):
        self.events = []
        self.fail = False

    def list_identities(self):
        return [(b"one", "First identity"), (b"two", "Second identity")]

    def export_identity(self, uid):
        self.events.append(("export", uid))
        return {"type": self.TYPE, "v": 1, "uid": uid, "secret": b"private key material"}

    def on_exported(self, uid):
        if self.fail:
            raise PolicyDenied("cannot mark exported")
        self.events.append(("marked", uid))


@test
def export_real_frames_full_set_and_secret_cleanup():
    p = FakeProvider()
    saved = provider.all()
    provider.clear()
    provider.register(p)
    shown = []
    keys = []
    original_close = export.ExportSession.close

    def close(session):
        if session._key is not None:
            keys.append(session._key)
        original_close(session)

    async def page(title, data, *args, **kwargs):
        assert p.events[-1][0] == "marked"
        assert screens.qr_fits(data)
        shown.append(data)
        return screens.QR_NEXT

    async def yes(*args, **kwargs):
        return True

    async def menu(*args, **kwargs):
        return 0

    class Progress:
        def __init__(self, text):
            pass

        def report(self, value):
            pass

        def stop(self):
            pass

    try:
        with Patch() as patch:
            ui = EntryUI(["correct horse battery", "correct horse battery"])
            ui.install(patch)
            patch.set(screens, "menu", menu)
            patch.set(screens, "confirm", yes)
            patch.set(screens, "confirm_fields", yes)
            patch.set(screens, "show_qr_page", page)
            patch.set(screens, "show_busy", lambda text: None)
            patch.set(screens, "Progress", Progress)
            patch.set(app_backup, "_yield", noop)
            patch.set(envelope, "ITERATIONS", 10)
            patch.set(export.ExportSession, "close", close)
            drive(app_backup.export_full())
            assert len(ui.auth) == 1
            assert ui.auth[0] == bytes(len(ui.auth[0]))
            assert keys and keys[0] == bytes(32)
            assert p.events == [
                ("export", b"one"),
                ("marked", b"one"),
                ("export", b"two"),
                ("marked", b"two"),
            ]
            assembled = {}
            for text in shown:
                f = frames.parse_frame(text)
                if f.backup_id not in assembled:
                    assembled[f.backup_id] = frames.Reassembler(f.backup_id)
                assembled[f.backup_id].add(f)
            assert len(assembled) == 2
            for r in assembled.values():
                raw = r.assemble()
                h = envelope.parse_header(raw)
                key = drive(envelope.derive_key(b"correct horse battery", h.salt))
                content = envelope.open_with_key(raw, key)
                app_backup.wipe(key)
                assert content.kind == envelope.KIND_FULL
                assert content.items[0]["secret"] == b"private key material"
            # Hiding a live QR on timeout also closes and wipes the session.
            patch.set(screens, "show_qr_page", noop)
            ui.texts[:] = ["correct horse battery", "correct horse battery"]
            drive(app_backup.export_record("test", b"one"))
            assert keys[-1] == bytes(32)
            patch.set(screens, "show_qr_page", page)
            # A failed export-state write must not show even one QR.
            p.fail = True
            shown.clear()
            ui.texts[:] = ["correct horse battery", "correct horse battery"]
            drive(app_backup.export_record("test", b"one"))
            assert not shown and keys[-1] == bytes(32)
    finally:
        provider.clear()
        for old in saved:
            provider.register(old)


@test
def restore_controller_requires_local_ready_and_respects_cancel():
    class Import:
        finished = False

        def is_ready(self):
            return True

        def has_otp(self):
            return False

        def counts(self):
            return 1, 0

        def finish(self):
            self.finished = True

    class State:
        purpose = "backup"
        message = "Sequence complete"
        ejected = False
        decoder_paused = True
        finishing = False

    actions = []
    state = State()

    async def wait(st, title, text, button):
        state.ejected = True
        # long-left must never restore

    async def action(imp):
        actions.append(True)

    with Patch() as patch:
        patch.set(import_mode, "_wait_screen", wait)
        patch.set(import_mode, "_do_action", action)
        imp = Import()
        drive(import_mode._controller(None, imp, state))
        assert not actions and imp.finished


@test
def restore_controller_bounds_sessions_and_explains_restart():
    class Import:
        finished = False

        def has_otp(self):
            return False

        def counts(self):
            return 1, 0

        def take_complete(self):
            return b"authenticated envelope handled by core"

        def finish(self):
            self.finished = True

    class State:
        purpose = "backup"
        message = "Sequence complete"
        ejected = False
        decoder_paused = True
        finishing = False

    class Progress:
        stopped = False

        def report(self, *args):
            pass

        def stop(self):
            self.stopped = True

    class Streaming:
        closed = False

        def __init__(self, ui, phrase, **kwargs):
            assert kwargs["max_envelopes"] == 192
            assert kwargs["max_sets"] == 4
            streams.append(self)

        async def restore_envelope(self, raw):
            raise RestoreLimitExceeded("quota")

        def close(self):
            self.closed = True

    streams, messages = [], []
    state, imp = State(), Import()

    async def error(message, **kwargs):
        assert kwargs["close_others"] is False
        messages.append(message)
        state.ejected = True

    with Patch() as patch:
        patch.set(import_mode, "_wait_screen", approve)
        patch.set(app_backup, "_Derivation", Progress)
        patch.set(restore, "StreamingRestore", Streaming)
        patch.set(screens, "show_error", error)
        drive(import_mode._controller(None, imp, state))
        assert imp.finished and state.finishing and streams[0].closed
        assert messages == [import_mode.t("import.ui.session_limit")]


@test
def long_otp_export_falls_back_to_encrypted_provider():
    class Account:
        def label(self):
            return "Long account"

    class Store:
        def get(self, uid):
            return Account()

        def export_uri(self, uid):
            return "otpauth://totp/" + "a" * 200

    calls = []

    async def fallback(kind, uid):
        calls.append((kind, uid))

    with Patch() as patch:
        patch.set(app_otp, "_store", Store)
        patch.set(app_backup, "export_record", fallback)
        patch.set(screens, "show_info", noop)
        drive(app_otp._export(b"otp"))
        assert calls == [("otp", b"otp")]


@test
def native_text_layout_supports_128_bytes():
    import trezorui_api

    # Previously panicked at construction: native buffers had capacity 50.
    with trezorui_api.request_passphrase(prompt="Backup", prompt_empty="Backup", max_len=128):
        pass


@test
def native_progress_preserves_caller_workflow():
    from trezor import ui, workflow

    def forbidden():
        raise AssertionError("progress closed its caller workflow")

    progress = screens.Progress("Deriving backup key")
    try:
        with Patch() as patch:
            patch.set(workflow, "close_others", forbidden)
            progress.report(0)
            assert ui.CURRENT_LAYOUT is progress.layout
            progress.report(0.5)
            progress.report(1)
    finally:
        progress.stop()
    assert ui.CURRENT_LAYOUT is None


run()
