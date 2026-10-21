# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Device PIN: onboarding, unlock, change (spec §10.1: PIN mandatory)."""

from micropython import const
from trezor import config

from ..core import i18n
from ..core.i18n import t
from ..core.secure import wipe
from ..platform import crypto
from ..ui import screens
from . import device

PIN_MIN = const(4)
PIN_MAX = const(50)
_STORAGE_MAX_TRIES = const(16)


def _valid(pin: str) -> bool:
    return PIN_MIN <= len(pin) <= PIN_MAX and all("0" <= c <= "9" for c in pin)


async def choose_new_pin():
    """Ask a new PIN twice. Returns it, or None if the user backs out."""
    while True:
        first = await screens.request_pin(t("pin.new"))
        if first is None:
            return None
        if not _valid(first):
            await screens.show_error(t("pin.too_short"))
            continue
        second = await screens.request_pin(t("pin.repeat"))
        if second is None:
            continue
        if first != second:
            await screens.show_error(t("pin.mismatch"))
            continue
        return first


async def onboarding() -> None:
    """First boot (or after wipe): language, third-party notice, PIN, master secret."""
    idx = await screens.menu(t("boot.choose_language"), ["English", "Français"], back=False)
    device.set_language(i18n.FR if idx == 1 else i18n.EN)
    await screens.show_warning(t("boot.welcome"), t("boot.third_party"), t("ui.continue"))
    if not config.has_pin():
        await screens.show_info(t("boot.welcome"), t("boot.set_pin_intro"))
        pin = None
        while pin is None:
            pin = await choose_new_pin()
        if not config.change_pin(pin, None):
            raise RuntimeError("failed to set PIN")
    device.initialize()


async def unlock() -> None:
    """Lockscreen + PIN entry until the storage is unlocked."""
    wrong = False
    while not config.is_unlocked():
        await screens.show_lockscreen()
        rem = config.get_pin_rem()
        attempts = t("pin.attempts", rem) if rem < _STORAGE_MAX_TRIES else ""
        pin = await screens.request_pin(t("pin.enter"), attempts, wrong=wrong, last=rem == 1)
        if pin is None:
            continue
        if config.unlock(pin, None):
            return
        wrong = True
        if not device.is_initialized():
            # too many attempts: upstream storage wiped itself
            await screens.show_warning(t("ui.warning"), t("pin.wiped"))
            return


async def change_pin() -> bool:
    old = await screens.request_pin(t("pin.enter"))
    if old is None:
        return False
    if not config.check_pin(old, None):
        await screens.show_error(t("pin.wrong"))
        return False
    new = await choose_new_pin()
    if new is None:
        return False
    if not config.change_pin(new, None):
        await screens.show_error(t("pin.wrong"))
        return False
    await screens.show_info(t("pin.changed"), timeout_ms=2000)
    return True


async def reauthenticate(distinct_from=None) -> bool:
    """Re-enter the device PIN before exporting secrets (spec §9).

    If ``distinct_from`` is a backup passphrase, compare it with the PIN
    the user actually entered, after verifying that PIN. Never submit a
    passphrase to the PIN checker: a different phrase must not consume a try.
    """
    pin = await screens.request_pin(t("pin.enter"))
    if pin is None:
        return False
    raw = None
    try:
        if not config.check_pin(pin, None):
            await screens.show_error(t("pin.wrong"))
            return False
        if distinct_from is not None:
            raw = bytearray(pin.encode())
            if crypto.ct_equal(raw, distinct_from):
                await screens.show_error(t("pin.backup_distinct"))
                return False
        return True
    finally:
        pin = None
        wipe(raw)
