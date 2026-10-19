# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Local FIDO2 service/account management, protection information and PIN."""

from ..apps.fido2 import localmgmt as mgmt
from ..core.i18n import t
from . import management, screens
from .interaction import InlineInteraction


def _auth():
    from ..fw import transports

    return transports.fido_server().app.auth


async def _credential(uid) -> None:
    cur = 0
    while True:
        info = mgmt.credential_info(_auth(), uid)
        cur = await screens.menu(
            info["user_name"] or info["display_name"] or info["rp_id"],
            [t("fido2.menu.info"), t("menu.export_identity"), t("fido2.menu.delete")],
            cur,
            close_others=False,
        )
        if cur is None:
            return
        if cur == 0:
            fields = mgmt.info_fields(_auth(), uid)
            fields.extend(
                [
                    ("fido2.hmac_secret", t("ui.yes") if info["hmac_secret"] else t("ui.no")),
                    ("fido2.large_blob", t("ui.yes") if info["large_blob"] else t("ui.no")),
                ]
            )
            await management.info(t("fido2.menu.info"), fields)
        elif cur == 1:
            from . import app_backup

            await app_backup.export_record("fido2", uid)
        else:
            from ..fw import pin

            if await pin.reauthenticate() and await mgmt.delete_credential(_auth(), InlineInteraction(), uid):
                await management.done("fido2.deleted")
                return


async def _accounts(rp_hash, rp_id) -> None:
    cur = 0
    while True:
        accounts = mgmt.list_credentials(_auth(), rp_hash)
        if not accounts:
            return
        cur = await screens.menu(rp_id, [label for _, label in accounts], cur, close_others=False)
        if cur is None:
            return
        await management.run(_credential(accounts[cur][0]))


async def _services() -> None:
    cur = 0
    while True:
        rps = mgmt.list_rps(_auth())
        if not rps:
            await screens.show_info(t("fido2.empty"), close_others=False)
            return
        cur = await screens.menu(
            t("fido2.menu.services"),
            [f"{rp} ({n})" for _, rp, n in rps],
            cur,
            close_others=False,
        )
        if cur is None:
            return
        await management.run(_accounts(rps[cur][0], rps[cur][1]))


async def _choose_pin():
    minimum = _auth().state.min_pin_length
    while True:
        first = await screens.request_text(t("manage.new_pin"), 63)
        if first is None:
            return None
        if len(first) < minimum or len(first.encode()) > 63 or "\0" in first:
            await screens.show_error(t("manage.fido_pin_length", minimum))
            continue
        second = await screens.request_text(t("manage.repeat_fido"), 63)
        if second is None:
            return None
        if first == second:
            return first
        await screens.show_error(t("pin.mismatch"))


async def _pin_change() -> None:
    from ..fw import pin

    is_set, retries = mgmt.pin_status(_auth())
    if is_set and not retries:
        await screens.show_error(t("fido2.pin.blocked"))
        return
    if not await pin.reauthenticate():
        return
    old = None
    if is_set:
        old = await screens.request_text(t("manage.old_pin"), 63)
        if old is None:
            return
    new = await _choose_pin()
    if new is None:
        return
    if is_set:
        mgmt.change_pin(_auth(), old, new)
    else:
        mgmt.set_pin(_auth(), new)
    await management.done("fido2.pin.changed" if is_set else "fido2.pin.set")


async def _pin_menu() -> None:
    while True:
        is_set, retries = mgmt.pin_status(_auth())
        status = t("fido2.pin.status", retries) if is_set else t("fido2.pin.none")
        choice = await screens.menu(
            t("fido2.menu.pin"),
            [t("fido2.menu.change_pin" if is_set else "fido2.menu.set_pin"), status],
            close_others=False,
        )
        if choice is None:
            return
        if choice == 0:
            await management.run(_pin_change())
        else:
            await screens.show_info(t("fido2.menu.pin"), status, close_others=False)


async def _wipe() -> None:
    from ..fw import pin

    if await pin.reauthenticate() and await mgmt.wipe_all(_auth(), InlineInteraction()):
        await management.done("fido2.wiped")


async def menu() -> None:
    cur = 0
    while True:
        cur = await screens.menu(
            t("fido2.app"),
            [t("fido2.menu.services"), t("fido2.menu.pin"), t("fido2.menu.wipe")],
            cur,
            close_others=False,
        )
        if cur is None:
            return
        await management.run((_services, _pin_menu, _wipe)[cur]())


async def challenge_info() -> None:
    await screens.show_info(t("menu.challenge"), t("manage.challenge_info"), close_others=False)
