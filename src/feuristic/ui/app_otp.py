# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""OTP menus (spec §9: OTP — voir code / ajouter QR USB / sauvegarder QR / supprimer)."""

import trezorui_api
from trezor import loop

from ..core.errors import FeuristicError, UserCancelled
from ..core.i18n import t
from . import screens
from .interaction import InlineInteraction


def _store():
    from ..apps.otp import accounts as otp_accounts

    return otp_accounts.default()


async def _show_totp(uid) -> None:
    """Show the TOTP code, refreshed every second, until a button is pressed."""
    from ..apps.otp.totp import TimeNotSynchronised

    store = _store()
    acc = store.get(uid)
    while True:
        try:
            code, remaining = store.totp_code(uid)
        except TimeNotSynchronised:
            await screens.show_warning(t("otp.time_not_set"), t("otp.time_not_set.hint"))
            return
        text = f"{code}\n{t('otp.remaining', remaining)}"
        res = await screens.run(
            trezorui_api.show_info(title=acc.label(), description=text, time_ms=1000),
            0,
            False,
            screens.AnyButtonLayout,
        )
        # show_info with time_ms returns CANCELLED on timeout: refresh; any
        # button press closes the view with another result
        if res is not trezorui_api.CANCELLED:
            return
        await loop.sleep(0)


async def _show_hotp(uid) -> None:
    try:
        code = await _store().generate_hotp(uid, InlineInteraction())
    except UserCancelled:
        return
    except FeuristicError:
        await screens.show_error(t("otp.hotp.exhausted"))
        return
    acc = _store().get(uid)
    await screens.show_info(acc.label(), code)


async def _export(uid) -> None:
    from ..fw import pin

    store = _store()
    acc = store.get(uid)
    uri = store.export_uri(uid)
    if not screens.qr_fits(uri):
        from . import app_backup

        uri = None
        await screens.show_info(t("otp.export_qr"), t("backup.ui.otp_long"))
        await app_backup.export_record("otp", uid)
        return
    if not await pin.reauthenticate():
        return
    if not await InlineInteraction().confirm(store.export_prompt(acc)):
        return
    try:
        from ..apps.otp.accounts import EXPORT_DISPLAY_TIMEOUT_MS

        await screens.show_qr(acc.label(), uri, EXPORT_DISPLAY_TIMEOUT_MS)
    finally:
        uri = None
        screens.show_busy(t("ui.qr_autohide"))


async def _delete(uid) -> None:
    store = _store()
    acc = store.get(uid)
    if await InlineInteraction().confirm(store.delete_prompt(acc)):
        store.delete(uid)
        await screens.show_info(t("otp.deleted"), timeout_ms=1500)


async def _account_menu(uid) -> None:
    store = _store()
    cur = 0
    while True:
        try:
            acc = store.get(uid)
        except FeuristicError:
            return
        items = [t("otp.view_code"), t("otp.export_qr"), t("otp.delete")]
        cur = await screens.menu(acc.label(), items, cur)
        if cur is None:
            return
        if cur == 0:
            await (_show_hotp(uid) if acc.is_hotp else _show_totp(uid))
        elif cur == 1:
            await _export(uid)
        else:
            await _delete(uid)
            return


async def add_from_usb() -> None:
    try:
        from ..fw import import_mode
    except ImportError:
        await screens.show_info(t("ui.not_implemented"), timeout_ms=2000)
        return
    await import_mode.run(purpose="otp")


async def menu() -> None:
    cur = 0
    while True:
        accounts = _store().accounts()
        labels = [a.label() for a in accounts]
        items = labels + [t("otp.add_qr_usb")]
        cur = await screens.menu(t("otp.title"), items, cur)
        if cur is None:
            return
        if cur == len(labels):
            # The suspended caller must not retain decrypted accounts while
            # the image decoder and a freshly imported provider use the heap.
            accounts = labels = items = None
            await add_from_usb()
        else:
            await _account_menu(accounts[cur].uid)
