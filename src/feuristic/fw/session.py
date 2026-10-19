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
    from ..ui import strings_apps, strings_backup

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
        strings_apps,
        strings_backup,
    ):
        mod.register()


def _load_stores() -> None:
    """Register providers lazily; stores recover their records at first use."""
    from ..apps.backup import provider as backup_registry
    from .backup_providers import create

    backup_registry.clear()
    entries = (
        ("otp", "otp.title"),
        ("openpgp", "openpgp.backup.label"),
        ("piv", "piv.title"),
        ("aes", "aes.title"),
        ("fido2", "fido2.app"),
    )
    for kind, label_key in entries:
        backup_registry.register(backup_registry.LazyProvider(kind, label_key, create))


def _start_transports() -> None:
    global _transports_started
    if _transports_started:
        return
    _transports_started = True
    from . import transports

    transports.start()


async def _home() -> None:
    from ..ui import menus

    await menus.home()


async def _lockscreen() -> None:
    await pin.unlock()
    if config.is_unlocked():
        _after_unlock()


def _register_fido_provider() -> None:
    """Keep the FIDO registry entry independent of the current HID server."""
    from ..apps.backup import provider as backup_registry
    from .backup_providers import create

    if not any(p.TYPE == "fido2" for p in backup_registry.all()):
        backup_registry.register(backup_registry.LazyProvider("fido2", "fido2.app", create))


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
    _forget_stores()
    workflow.set_default(_lockscreen)
    workflow.close_others()
    workflow.kill_default()
    workflow.start_default()


def _forget_stores() -> None:
    """Release providers and singleton caches containing unlocked identities."""
    from ..apps.backup import provider

    provider.clear()
    release_import_stores()


def release_import_stores() -> None:
    """Drop singleton identities between streamed restores, keeping registry/KDF.

    Looking up modules avoids loading an unused application's code just to
    discard its cache. The registry contains lazy providers and therefore no
    references to these stores or to the suspended FIDO HID server.
    """
    import sys

    for name in (
        "feuristic.apps.otp.accounts",
        "feuristic.apps.card.openpgp.storage",
        "feuristic.apps.card.piv.storage",
        "feuristic.apps.card.aes.keys",
    ):
        module = sys.modules.get(name)
        if module is not None:
            module._reset_default()


def reload_stores() -> None:
    """Refresh shared stores/providers after a temporary import session."""
    from . import transports

    transports.on_lock()
    _forget_stores()
    if config.is_unlocked():
        _load_stores()
        _register_fido_provider()


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
