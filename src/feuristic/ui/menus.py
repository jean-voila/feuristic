# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Menu tree of the device (spec §9).

feuristic
├── Authentification   (Passkeys, OTP, Challenge-response)
├── Cryptographie      (OpenPGP, PIV, AES, Aléa)
├── Sauvegarde         (Exporter une identité, Export complet, Restaurer)
├── Réglages           (PIN, Heure TOTP, Interfaces USB, Langue, Matériel, Effacement)
└── Verrouiller

Application sub-menus live next to their application glue
(``feuristic.ui.app_*``); entries whose application is not part of the
build show "not available".
"""

from trezor import config, utils

from ..core import i18n
from ..core.i18n import t
from . import screens
from .interaction import InlineInteraction


async def _not_available() -> None:
    await screens.show_info(t("ui.not_implemented"), timeout_ms=2000)


async def _call(module: str, func: str) -> None:
    """Run ``feuristic.ui.<module>.<func>()`` if that UI module exists."""
    try:
        mod = __import__("feuristic.ui." + module, None, None, [func])
    except ImportError:
        await _not_available()
        return
    await getattr(mod, func)()


# --- Authentication ---------------------------------------------------------


async def auth_menu() -> None:
    cur = 0
    while True:
        items = [t("menu.passkeys"), t("menu.otp"), t("menu.challenge")]
        cur = await screens.menu(t("menu.auth"), items, cur)
        if cur is None:
            return
        if cur == 0:
            await _call("app_fido2", "menu")
        elif cur == 1:
            from . import app_otp

            await app_otp.menu()
        else:
            await _call("app_fido2", "challenge_info")


# --- Cryptography -----------------------------------------------------------


async def crypto_menu() -> None:
    cur = 0
    while True:
        items = [t("menu.openpgp"), t("menu.piv"), t("menu.aes"), t("menu.rng")]
        cur = await screens.menu(t("menu.crypto"), items, cur)
        if cur is None:
            return
        await _call(
            ("app_openpgp", "app_piv", "app_aes", "app_aes")[cur], ("menu", "menu", "menu", "rng_menu")[cur]
        )


# --- Backup -----------------------------------------------------------------


async def backup_menu() -> None:
    cur = 0
    while True:
        items = [t("menu.export_identity"), t("menu.export_full"), t("menu.restore")]
        cur = await screens.menu(t("menu.backup"), items, cur)
        if cur is None:
            return
        await _call("app_backup", ("export_identity", "export_full", "restore")[cur])


# --- Settings ---------------------------------------------------------------


async def time_menu() -> None:
    from ..core import clock

    while True:
        now = clock.CLOCK.now()
        if now is None:
            status = t("settings.time_unset")
        else:
            from ..apps.timesync.datetime_fmt import format_utc

            status = format_utc(now)
        items = [t("settings.time_sync_usb"), status]
        sel = await screens.menu(t("menu.time"), items)
        if sel is None:
            return
        if sel == 0:
            from ..fw import timesync_mode

            await timesync_mode.run()


async def language_menu() -> None:
    from ..fw import device

    sel = await screens.menu(t("menu.language"), ["English", "Français"], device.language())
    if sel is not None:
        device.set_language(i18n.FR if sel == 1 else i18n.EN)


async def about() -> None:
    from .. import version

    fields = [
        (t("about.version"), version.VERSION, False),
        (t("about.model"), utils.INTERNAL_MODEL, False),
        (t("about.third_party"), "GPL-3.0-only", False),
    ]
    await screens.confirm_fields(t("about.title"), fields, verb=t("ui.ok"))


async def wipe_device() -> None:
    from ..fw import pin

    if not await screens.confirm(t("settings.wipe_title"), t("settings.wipe_text"), hold=True):
        return
    if not await pin.reauthenticate():
        return
    if not await screens.confirm(t("settings.wipe_title"), t("settings.wipe_again"), hold=True):
        return
    config.wipe()
    utils.reboot()


async def settings_menu() -> None:
    from ..fw import pin

    cur = 0
    while True:
        items = [
            t("menu.pin"),
            t("menu.time"),
            t("menu.usb"),
            t("menu.language"),
            t("menu.about"),
            t("menu.wipe"),
        ]
        cur = await screens.menu(t("menu.settings"), items, cur)
        if cur is None:
            return
        if cur == 0:
            await pin.change_pin()
        elif cur == 1:
            await time_menu()
        elif cur == 2:
            await screens.show_info(t("menu.usb"), t("settings.usb_info"))
        elif cur == 3:
            await language_menu()
        elif cur == 4:
            await about()
        else:
            await wipe_device()


# --- Home -------------------------------------------------------------------


async def home() -> None:
    from ..fw import session

    cur = 0
    while True:
        items = [t("menu.auth"), t("menu.crypto"), t("menu.backup"), t("menu.settings"), t("menu.lock")]
        cur = await screens.menu(t("menu.home"), items, cur, back=False)
        if cur is None:
            continue
        if cur == 0:
            await auth_menu()
        elif cur == 1:
            await crypto_menu()
        elif cur == 2:
            await backup_menu()
        elif cur == 3:
            await settings_menu()
        else:
            session.lock()
            return


def inline_ui() -> InlineInteraction:
    return InlineInteraction()
