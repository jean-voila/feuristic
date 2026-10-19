# SPDX-License-Identifier: GPL-3.0-only
"""Management UI security transitions with real application stores and scripted screens."""

import importlib
import sys
from collections import deque
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from feuristic.apps.card.aes import keys as aes_keys
from feuristic.apps.card.openpgp import const as pgp
from feuristic.apps.card.openpgp import storage as pgp_storage
from feuristic.apps.card.piv import consts as pc
from feuristic.apps.card.piv import storage as piv_storage
from feuristic.apps.fido2.context import Context
from feuristic.apps.fido2.ctap2 import Authenticator
from feuristic.core import i18n
from feuristic.core.errors import InvalidInput, UserCancelled

from ..aio import run


class Script:
    def __init__(self):
        self.menus = deque()
        self.pins = deque()
        self.texts = deque()
        self.confirms = deque()
        self.reauths = deque()
        self.events = []
        self.progress = []

    async def menu(self, title, items, current=0, **kwargs):
        self.events.append(("menu", title, items, kwargs))
        answer = self.menus.popleft()
        if isinstance(answer, str):
            return items.index(answer)
        return answer

    async def request_pin(self, title, *args, **kwargs):
        return self.pins.popleft()

    async def request_text(self, title, maximum):
        return self.texts.popleft()

    async def confirm(self, title, text="", **kwargs):
        self.events.append(("confirm", title, text, kwargs))
        return self.confirms.popleft()

    async def confirm_fields(self, title, fields, **kwargs):
        self.events.append(("fields", title, fields, kwargs))
        return self.confirms.popleft()

    async def show_info(self, title, text="", **kwargs):
        self.events.append(("info", title, text, kwargs))

    async def show_error(self, text):
        self.events.append(("error", text))

    async def show_qr(self, title, text):
        self.events.append(("qr", title, text))

    async def reauthenticate(self):
        self.events.append(("reauth",))
        return self.reauths.popleft()

    def show_busy(self, text):
        self.events.append(("busy", text))

    def Progress(self, text):  # noqa: N802
        progress = SimpleNamespace(report=lambda _: None, stop=lambda: self.progress.append("stopped"))
        self.progress.append("started")
        return progress


@pytest.fixture
def ui(monkeypatch):
    # Install an isolated firmware-only package for each script. No Trezor
    # runtime or real screen modules are imported into the host test process.
    script = Script()
    import feuristic

    package = ModuleType("feuristic.ui")
    package.__path__ = [str(Path(__file__).parents[3] / "src/feuristic/ui")]
    monkeypatch.setitem(sys.modules, "feuristic.ui", package)
    monkeypatch.setattr(feuristic, "ui", package, raising=False)
    for name in (
        "management",
        "interaction",
        "strings_apps",
        "app_aes",
        "app_fido2",
        "app_openpgp",
        "app_piv",
    ):
        monkeypatch.delitem(sys.modules, "feuristic.ui." + name, raising=False)
    monkeypatch.setitem(sys.modules, "feuristic.ui.screens", script)
    monkeypatch.setitem(
        sys.modules, "trezor", SimpleNamespace(loop=SimpleNamespace(), workflow=SimpleNamespace())
    )
    monkeypatch.setitem(
        sys.modules, "feuristic.fw.pin", SimpleNamespace(reauthenticate=script.reauthenticate)
    )
    from feuristic.apps.card.openpgp import strings as pgp_strings
    from feuristic.ui import strings as shell_strings
    from feuristic.ui import strings_apps

    shell_strings.register()
    pgp_strings.register()
    strings_apps.register()
    i18n.set_language(i18n.EN)
    aes_store = aes_keys.AesKeyStore()
    aes_store.load()
    piv_store = piv_storage.PivStore()
    piv_store.load()
    pgp_store = pgp_storage.IdentityStore()
    pgp_store.load()
    monkeypatch.setattr(aes_keys, "_default", aes_store)
    monkeypatch.setattr(piv_storage, "_default", piv_store)
    monkeypatch.setattr(pgp_storage, "_default", pgp_store)
    modules = SimpleNamespace(
        **{
            name: importlib.import_module("feuristic.ui." + name)
            for name in ("management", "app_aes", "app_fido2", "app_openpgp", "app_piv")
        }
    )
    auth = Authenticator(Context(b"m" * 32, None))
    monkeypatch.setattr(modules.app_fido2, "_auth", lambda: auth)
    yield SimpleNamespace(
        script=script, modules=modules, aes=aes_store, piv=piv_store, pgp=pgp_store, auth=auth
    )
    for name in (
        "management",
        "interaction",
        "strings_apps",
        "app_aes",
        "app_fido2",
        "app_openpgp",
        "app_piv",
    ):
        sys.modules.pop("feuristic.ui." + name, None)


def test_cancel_repeat_pin_does_not_save(ui):
    ui.script.reauths.append(True)
    ui.script.pins.extend(["654321", None])
    before = ui.piv.creds().pin_hash
    run(ui.modules.app_piv._set_pin())
    assert ui.piv.creds().pin_hash == before
    assert ui.piv.epoch == 0


@pytest.mark.parametrize("digits", ["12345", "123456789", "abc123"])
def test_piv_pin_rejects_invalid_before_confirmation(ui, digits):
    ui.script.reauths.append(True)
    ui.script.pins.extend([digits, None])
    run(ui.modules.app_piv._set_pin())
    assert any(e[0] == "error" for e in ui.script.events)
    assert ui.piv.epoch == 0


def test_piv_pin_change_invalidates_host_session(ui):
    ui.script.reauths.append(True)
    ui.script.pins.extend(["654321", "654321"])
    run(ui.modules.app_piv._set_pin())
    assert not (ui.piv.creds().flags & piv_storage.FLAG_PIN_DEFAULT)
    assert ui.piv.epoch == 1


def test_aes_deny_reauthentication_preserves_key(ui):
    key = ui.aes.create("original")
    ui.script.texts.append("renamed")
    ui.script.reauths.append(False)
    run(ui.modules.app_aes._rename(key.kid))
    assert ui.aes.get(key.kid).name == "original"


@pytest.mark.parametrize("confirm", [False, True])
def test_aes_delete_requires_reauthentication_and_held_confirmation(ui, confirm):
    key = ui.aes.create("secret")
    ui.script.reauths.append(True)
    ui.script.confirms.append(confirm)
    assert bool(run(ui.modules.management.run(ui.modules.app_aes._delete(key.kid)))) is confirm
    assert (ui.aes.get(key.kid) is None) is confirm
    dialog = next(e for e in ui.script.events if e[0] == "fields")
    assert dialog[3]["hold"] is True
    assert dialog[3]["timeout_ms"] > 0
    assert ui.script.events[0] == ("reauth",)


def test_aes_session_policy_requires_explicit_warning(ui):
    ui.script.menus.append(1)
    ui.script.confirms.append(False)
    assert run(ui.modules.app_aes._policy()) is None
    assert "until the device is locked" in ui.script.events[-1][2]


def test_aes_activation_and_policy_bump_epoch(ui):
    key = ui.aes.create("secret")
    epoch = ui.aes.epoch
    ui.script.reauths.append(True)
    ui.script.confirms.append(True)
    run(ui.modules.app_aes._toggle(key.kid))
    assert ui.aes.get(key.kid).enabled is False
    assert ui.aes.epoch == epoch + 1
    ui.script.menus.append(1)
    ui.script.confirms.append(True)
    ui.script.reauths.append(True)
    run(ui.modules.app_aes._set_policy(key.kid))
    assert ui.aes.get(key.kid).policy == aes_keys.POLICY_SESSION
    assert ui.aes.epoch == epoch + 2


def test_fido_pin_setup_and_wrong_old_pin_retry_accounting(ui):
    ui.script.reauths.extend([True, True])
    ui.script.texts.extend(["correct-pin", "correct-pin"])
    run(ui.modules.app_fido2._pin_change())
    assert ui.auth.state.pin_is_set()
    retries = ui.auth.state.pin_retries
    ui.script.texts.extend(["wrong-pin", "replacement", "replacement"])
    run(ui.modules.management.run(ui.modules.app_fido2._pin_change()))
    assert ui.auth.state.pin_retries == retries - 1
    assert any(e[0] == "error" and "Wrong PIN" in e[1] for e in ui.script.events)


def test_fido_setup_cancellation_does_not_set_pin(ui):
    ui.script.reauths.append(True)
    ui.script.texts.extend(["1234", None])
    run(ui.modules.app_fido2._pin_change())
    assert not ui.auth.state.pin_is_set()


def test_openpgp_pin_mutation_bumps_epoch_and_wipes_input(ui, monkeypatch):
    captured = []
    real_set = ui.modules.app_openpgp.mgmt.set_pin

    def capture(store, which, value):
        captured.append(value)
        real_set(store, which, value)

    monkeypatch.setattr(ui.modules.app_openpgp.mgmt, "set_pin", capture)
    ui.script.menus.append(0)
    ui.script.reauths.append(True)
    ui.script.pins.extend(["654321", "654321"])
    run(ui.modules.app_openpgp._pin_action(pgp.PW1))
    assert ui.pgp.epoch == 1
    assert captured == [bytearray(6)]


def test_openpgp_generation_requires_session_clock(ui):
    run(ui.modules.app_openpgp._generate())
    assert "Synchronise the time" in ui.script.events[-1][2]
    assert not ui.pgp.ident.has_keys()


def test_piv_policy_never_below_slot_default(ui):
    run(ui.modules.app_piv.mgmt.generate(pc.SLOT_SIGN, pc.ALG_P256, _Accept()))
    ui.script.menus.append(None)
    run(ui.modules.app_piv._set_policy(pc.SLOT_SIGN))
    assert ui.script.events[-1][2] == ["Every use"]


def test_generated_piv_management_key_wiped_after_cancel(ui):
    key = bytearray(b"x" * 24)
    ui.script.menus.append(None)
    run(ui.modules.app_piv._show_management_key(key))
    assert key == bytearray(24)
    assert ui.script.events[0][3]["timeout_ms"] == 60_000


@pytest.mark.parametrize("exc, displayed", [(InvalidInput(), True), (UserCancelled(), False)])
def test_management_errors_never_display_exception_content(ui, exc, displayed):
    async def fail():
        raise exc

    run(ui.modules.management.run(fail()))
    assert any(e[0] == "error" for e in ui.script.events) is displayed


class _Accept:
    async def confirm(self, prompt):
        return True


def test_openpgp_local_generation_and_targeted_deletion(ui):
    from feuristic.core import clock

    clock.CLOCK.set(1_800_000_000)
    ui.script.menus.extend([0, None])  # Ed25519 profile, leave View keys
    ui.script.reauths.append(True)
    ui.script.confirms.append(True)
    run(ui.modules.app_openpgp._generate())
    assert all(k.present for k in ui.pgp.ident.keys)
    assert len({k.fpr for k in ui.pgp.ident.keys}) == 3
    assert ui.script.progress == ["started", "stopped"]
    ui.script.menus.append(1)  # decryption role only
    ui.script.reauths.append(True)
    ui.script.confirms.append(True)
    run(ui.modules.app_openpgp._delete())
    assert [k.present for k in ui.pgp.ident.keys] == [True, False, True]


def test_openpgp_rejected_replacement_preserves_existing_keys(ui):
    from feuristic.core import clock

    clock.CLOCK.set(1_800_000_000)
    run(ui.modules.app_openpgp.mgmt.generate_keys(ui.pgp, "ed25519", 1_800_000_000))
    before = [k.fpr for k in ui.pgp.ident.keys]
    ui.script.menus.append(0)
    ui.script.reauths.append(True)
    ui.script.confirms.append(False)
    run(ui.modules.app_openpgp._generate())
    assert [k.fpr for k in ui.pgp.ident.keys] == before
    assert ui.script.progress == []
    assert "will be destroyed" in ui.script.events[-1][2]


def test_piv_management_key_generation_changes_credentials(ui):
    ui.script.menus.extend([0, 0, None, None])
    ui.script.reauths.append(True)
    ui.script.confirms.append(True)
    run(ui.modules.app_piv._management_key())
    assert ui.piv.creds().mgmt_alg == pc.ALG_AES192
    assert ui.piv.creds().mgmt_key != pc.DEFAULT_MGMT_KEY
    assert len(ui.piv.creds().mgmt_key) == 24
    assert not ui.piv.creds().flags & piv_storage.FLAG_MGMT_DEFAULT


def test_all_identity_menus_route_to_encrypted_backup(ui, monkeypatch):
    exported = []

    async def export_record(kind, uid):
        exported.append((kind, uid))

    monkeypatch.setitem(sys.modules, "feuristic.ui.app_backup", SimpleNamespace(export_record=export_record))
    key = ui.aes.create("key")
    ui.script.menus.extend([4, None])
    run(ui.modules.app_aes._key_menu(key.kid))
    run(ui.modules.app_piv.mgmt.generate(pc.SLOT_AUTH, pc.ALG_P256, _Accept()))
    ui.script.menus.extend([4, None])
    run(ui.modules.app_piv._slot_menu(pc.SLOT_AUTH))
    run(ui.modules.app_openpgp._export())
    cred = ui.auth.store.create_resident(
        "example.org",
        b"alice",
        "Alice",
        "Alice",
        -7,
        (1).to_bytes(32, "big"),
        3,
        True,
        True,
    )
    ui.script.menus.extend([1, None])
    run(ui.modules.app_fido2._credential(cred.uid))
    assert exported == [
        ("aes", b"AESkey\x00\x01"),
        ("piv", b"PIVslot\x9a"),
        ("openpgp", b"openpgp"),
        ("fido2", cred.uid),
    ]


@pytest.mark.parametrize("module", ["app_fido2", "app_aes", "app_openpgp", "app_piv"])
def test_application_back_does_not_mutate_storage(ui, module, kv):
    before = dict(kv.data)
    # PIV intentionally initialises its credential record before warning
    # about defaults. Other application menus don't create any state.
    if module == "app_piv":
        ui.piv.creds()
        before = dict(kv.data)
    ui.script.menus.append(None)
    run(getattr(ui.modules, module).menu())
    assert kv.data == before
