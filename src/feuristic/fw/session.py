# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Boot sequence and main session of the feuristic firmware."""

from trezor import config, log, loop, workflow

from ..core import i18n
from . import device, pin, usbmodes

_transports_started = False


def register_strings() -> None:
    from ..apps.backup import strings as backup_strings
    from ..apps.card.aes import strings as aes_strings
    from ..apps.card.openpgp import strings as pgp_strings
    from ..apps.card.piv import strings as piv_strings
    from ..apps.fido2 import strings as fido_strings
    from ..apps.importer import strings as import_strings
    from ..apps.otp import strings as otp_strings
    from ..apps.timesync import strings as ts_strings
    from ..ui import strings as ui_strings

    for mod in (
        ui_strings,
        otp_strings,
        ts_strings,
        fido_strings,
        pgp_strings,
        piv_strings,
        aes_strings,
        backup_strings,
        import_strings,
    ):
        mod.register()


def _load_stores() -> None:
    """Resolve interrupted copy-on-write updates and build RAM indexes, and
    register the backup providers."""
    from ..apps.backup import provider as backup_registry
    from ..apps.card.aes.provider import AesBackupProvider
    from ..apps.card.openpgp import storage as pgp_storage
    from ..apps.card.openpgp.provider import OpenPgpBackupProvider
    from ..apps.card.piv.provider import PivBackupProvider
    from ..apps.otp import accounts
    from ..apps.otp.provider import OtpBackupProvider

    accounts.default().load()
    backup_registry.clear()
    providers = (
        OtpBackupProvider(),
        OpenPgpBackupProvider(pgp_storage.default()),
        PivBackupProvider(),
        AesBackupProvider(),
    )
    for p in providers:
        backup_registry.register(p)


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


def _register_fido_provider() -> None:
    from ..apps.backup import provider as backup_registry
    from ..apps.fido2.provider import Fido2BackupProvider
    from . import transports

    server = transports.fido_server()
    if server is not None:
        try:
            backup_registry.unregister("fido2")
        except Exception:
            pass
        backup_registry.register(Fido2BackupProvider(server.app.auth))


def lock() -> None:
    """Lock the storage (autolock or menu). USB stays up; FIDO/CCID requests
    then ask for the PIN on the device."""
    if not config.has_pin():
        return
    config.lock()
    device.forget_master_secret()
    try:
        from . import transports

        transports.on_lock()
    except ImportError:
        pass
    workflow.set_default(_lockscreen)
    workflow.close_others()
    workflow.kill_default()
    workflow.start_default()


def after_unlock_from_usb() -> None:
    """Unlock completed from a FIDO/CCID request: restore the home screen."""
    _after_unlock()


def _after_unlock() -> None:
    device.apply_language(device.language())
    _load_stores()
    usbmodes.start_normal()
    _start_transports()
    _register_fido_provider()
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
