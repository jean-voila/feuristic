# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""On-device OpenPGP keys, PIN recovery and encrypted backup."""

from trezor import loop

from ..apps.card.openpgp import const as pgp
from ..apps.card.openpgp import localmgmt as mgmt
from ..apps.card.openpgp import storage
from ..core import clock
from ..core.i18n import t
from ..core.secure import wipe
from . import management, screens


def _store():
    return storage.default()


async def _yield() -> None:
    await loop.sleep(0)


async def _view() -> None:
    while True:
        status = mgmt.status(_store())
        items = [t("openpgp.role." + key["role"]) for key in status["keys"]]
        selected = await screens.menu(t("openpgp.menu.view"), items, close_others=False)
        if selected is None:
            return
        key = status["keys"][selected]
        fields = [
            ("openpgp.field.role", t("openpgp.role." + key["role"])),
            ("manage.status", t("manage.present") if key["present"] else t("openpgp.status.no_key")),
            ("openpgp.field.algorithm", key["algorithm"]),
            ("openpgp.field.fingerprint", key["fingerprint"] or t("openpgp.no_fingerprint")),
            ("openpgp.field.created", str(key["created"])),
        ]
        if selected == pgp.SIG:
            fields.append(("openpgp.role.sig", str(status["signatures"])))
        if status["terminated"]:
            fields.append(("manage.status", t("openpgp.status.terminated")))
        await management.info(items[selected], fields)


async def _generate() -> None:
    from ..fw import pin

    now = clock.CLOCK.now()
    if now is None:
        await screens.show_info(t("openpgp.menu.generate"), t("openpgp.time_required"), close_others=False)
        return
    profiles = mgmt.profiles()
    choice = await screens.menu(
        t("openpgp.menu.generate"),
        [t(label) for _, label in profiles],
        close_others=False,
    )
    if choice is None:
        return
    if not await pin.reauthenticate():
        return
    replacing = any(k["present"] for k in mgmt.status(_store())["keys"])
    if not await management.confirm("manage.pgp.generate", "manage.pgp.replace" if replacing else ""):
        return
    progress = screens.Progress(t("openpgp.generating"))
    try:
        await mgmt.generate_keys(_store(), profiles[choice][0], now, _yield, progress.report)
    finally:
        progress.stop()
    await management.done("manage.pgp.generated")
    await _view()


async def _delete() -> None:
    from ..fw import pin

    status = mgmt.status(_store())
    roles = [i for i in pgp.ROLES if status["keys"][i]["present"]]
    if not roles:
        await screens.show_info(t("openpgp.status.no_key"), close_others=False)
        return
    items = [t("openpgp.role." + pgp.ROLE_NAMES[i]) for i in roles] + [t("manage.all_keys")]
    choice = await screens.menu(t("openpgp.menu.delete"), items, close_others=False)
    if choice is None or not await pin.reauthenticate():
        return
    selected_roles = roles if choice == len(roles) else [roles[choice]]
    fields = [(t("openpgp.field.role"), items[choice], False)]
    for role in selected_roles:
        fields.append((t("openpgp.field.fingerprint"), status["keys"][role]["fingerprint"], True))
    if not await screens.confirm_fields(
        t("manage.pgp.delete"),
        fields,
        hold=True,
        timeout_ms=management.TIMEOUT_MS,
        close_others=False,
    ):
        return
    mgmt.delete_keys(_store(), selected_roles)
    await management.done("manage.deleted")


async def _pin_action(which) -> None:
    from ..fw import pin

    title = ("openpgp.pin.pw1", "openpgp.pin.pw3", "openpgp.pin.rc")[which]
    choices = [t("manage.new_value"), t("manage.unblock")]
    if which == pgp.RC:
        choices.append(t("manage.remove_rc"))
    selection = await screens.menu(t(title), choices, close_others=False)
    if selection is None or not await pin.reauthenticate():
        return
    if selection == 0:
        value = await management.new_pin(title, pgp.PW_MIN[which])
        if value is None:
            return
        try:
            mgmt.set_pin(_store(), which, value)
        finally:
            wipe(value)
    elif selection == 1:
        if not await management.confirm("manage.unblock", title):
            return
        mgmt.unblock(_store(), which)
    else:
        if not await management.confirm("manage.remove_rc"):
            return
        mgmt.set_pin(_store(), pgp.RC, b"")
    await management.done()


async def _pins() -> None:
    while True:
        status = mgmt.status(_store())
        choices = [t("openpgp.pin.pw1"), t("openpgp.pin.pw3"), t("openpgp.pin.rc"), t("manage.info")]
        choice = await screens.menu(t("openpgp.menu.pins"), choices, close_others=False)
        if choice is None:
            return
        if choice == 3:
            await screens.show_info(
                t("openpgp.menu.pins"),
                t("manage.pgp.pin_info", status["pw1_retries"], status["pw3_retries"], status["rc_retries"])
                + "\n"
                + t("manage.pgp.defaults"),
                close_others=False,
            )
        else:
            await management.run(_pin_action(choice))


async def _export() -> None:
    from ..apps.card.openpgp.provider import UID
    from . import app_backup

    await app_backup.export_record("openpgp", UID)


async def _reset() -> None:
    from ..fw import pin

    if await pin.reauthenticate() and await management.confirm("openpgp.menu.reset", "manage.pgp.reset"):
        mgmt.factory_reset(_store())
        await management.done()


async def menu() -> None:
    cur = 0
    while True:
        cur = await screens.menu(
            t("openpgp.menu.title"),
            [t("openpgp.menu." + name) for name in ("generate", "view", "delete", "export", "pins", "reset")],
            cur,
            close_others=False,
        )
        if cur is None:
            return
        await management.run((_generate, _view, _delete, _export, _pins, _reset)[cur]())
