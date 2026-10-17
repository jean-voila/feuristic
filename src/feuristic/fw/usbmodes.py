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


def start_normal() -> None:
    """First start after unlock (the kernel configured NORMAL at boot)."""
    global _started
    if not _started:
        _bus.open(device.usb_serial())
        _started = True


async def switch(mode: int) -> None:
    """Detach, wait so the host notices, then re-enumerate in ``mode``."""
    global _started
    _bus.close()
    await loop.sleep(io.USB_MODE_DETACH_MS)
    io.usb_set_mode(mode, device.usb_serial())
    _started = True


def current() -> int:
    return io.usb_get_mode()
