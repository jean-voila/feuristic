# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Boot sequence and main session of the feuristic firmware."""

from trezor import config, log, loop, workflow

from ..core import i18n
from . import device, pin, usbmodes

_transports_started = False


def register_strings() -> None:
    from ..apps.otp import strings as otp_strings
    from ..apps.timesync import strings as ts_strings
    from ..ui import strings as ui_strings

    ui_strings.register()
    otp_strings.register()
    ts_strings.register()
    try:
        from . import apps_registry

        apps_registry.register_strings()
    except ImportError:
        pass


def _load_stores() -> None:
    """Resolve interrupted copy-on-write updates and build RAM indexes."""
    from ..apps.otp import accounts

    accounts.default().load()
    try:
        from . import apps_registry

        apps_registry.load()
    except ImportError:
        pass


def _start_transports() -> None:
    global _transports_started
    if _transports_started:
        return
    _transports_started = True
    try:
        from . import transports

        transports.start()
    except ImportError:
        if __debug__:
            log.warning(__name__, "USB transports not available")


async def _home() -> None:
    from ..ui import menus

    await menus.home()


async def _lockscreen() -> None:
    await pin.unlock()
    if config.is_unlocked():
        _after_unlock()


def lock() -> None:
    """Lock the storage (autolock or menu). USB stays up; FIDO/CCID requests
    then ask for the PIN on the device."""
    if not config.has_pin():
        return
    config.lock()
    device.forget_master_secret()
    workflow.set_default(_lockscreen)
    workflow.close_others()
    workflow.kill_default()
    workflow.start_default()


def _after_unlock() -> None:
    device.apply_language(device.language())
    _load_stores()
    usbmodes.start_normal()
    _start_transports()
    workflow.idle_timer.set(device.AUTOLOCK_MS, lock)
    workflow.set_default(_home)
    workflow.kill_default()
    workflow.start_default()


async def _boot() -> None:
    try:
        if not device.is_initialized() or not config.has_pin():
            if config.has_pin() and not config.is_unlocked():
                await pin.unlock()
            await pin.onboarding()
        else:
            await pin.unlock()
            if not device.is_initialized():
                # storage was wiped after too many wrong PINs
                await pin.onboarding()
        _after_unlock()
    except Exception as e:
        if __debug__:
            log.exception(__name__, e)
        from trezor import utils

        utils.halt(e.__class__.__name__)


def run() -> None:
    register_strings()
    device.apply_language(device.language() if device.is_initialized() else i18n.EN)
    if __debug__:
        # Debug builds: enumerate before unlock so that the debuglink can
        # drive the PIN/onboarding screens (release builds enumerate after
        # unlock, like upstream).
        usbmodes.start_normal()
        try:
            import apps.debug

            apps.debug.boot()
        except ImportError:
            pass
    loop.schedule(_boot())
    loop.run()
