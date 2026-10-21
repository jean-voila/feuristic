# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Exclusive USB modes (docs/architecture.md §5.2)."""

from trezor import io, loop

from . import device

NORMAL = io.USB_MODE_NORMAL
TIMESYNC = io.USB_MODE_TIMESYNC
IMPORT = io.USB_MODE_IMPORT

_bus = io.USB()
_started = False
_switching = False


def start_normal() -> None:
    """First start after unlock (the kernel configured NORMAL at boot)."""
    global _started
    if not _started:
        _bus.open(device.usb_serial())
        _started = True


def disconnect() -> None:
    """Close USB for a local secret-export session; switch(NORMAL) reconnects."""
    if __debug__:
        from trezor import utils

        if utils.EMULATOR:
            return  # Keep emulator debuglink buttons available; pollers are suspended.
    _bus.close()


async def switch(mode: int) -> None:
    """Detach, wait so the host notices, then re-enumerate in ``mode``."""
    global _started, _switching
    from . import session, transports

    while _switching:
        await loop.sleep(1)
    _switching = True
    try:
        if mode != NORMAL:
            # Disable consumers before the detach delay yields. Otherwise their
            # polling loops can recreate all protected applets during import.
            transports.suspend()
            await transports.wait_suspended()
        _bus.close()
        await loop.sleep(io.USB_MODE_DETACH_MS)
        io.usb_set_mode(mode, device.usb_serial())
        _started = True
        if mode == NORMAL:
            session.reload_stores()
            transports.resume()
    finally:
        _switching = False


def restore_normal():
    """Schedule cleanup which survives closure of its calling workflow.

    Await the returned mailbox on an ordinary return. A GeneratorExit path
    must only schedule it: yielding from a coroutine's close is forbidden.
    Cancelling a mailbox waiter does not cancel the independent cleanup.
    """
    done = loop.mailbox()

    async def restore():
        try:
            await switch(NORMAL)
        except Exception as exc:
            done.put(exc)
        else:
            done.put(True)

    loop.schedule(restore())
    return done


def current() -> int:
    return io.usb_get_mode()
