# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Temporary CDC-ACM time-sync mode (spec §3.2, §4, docs/protocols/time-sync-v1.md).

Sequence: detach → re-enumerate as CDC-ACM only → serve the line protocol
until a time is applied, the user cancels from the menu, or the idle
timeout expires → flush → re-enumerate in NORMAL mode.
"""

import trezorui_api
from micropython import const
from trezor import io, loop

from ..apps.timesync.protocol import TimeSyncSession
from ..core.i18n import t
from ..ui import screens
from ..ui.interaction import InlineInteraction
from . import usbmodes

IDLE_TIMEOUT_MS = const(5 * 60 * 1000)


_READ = object()


async def _read_ready():
    await loop.wait(io.USBIF_VCP | io.POLL_READ)
    return _READ


async def _serve(session) -> bool:
    """Returns False if the user cancelled from the device."""
    pipe = io.USBPipe(io.USBIF_VCP)
    buf = bytearray(64)
    while not session.done:
        waiting = trezorui_api.show_warning(
            title=t("usb.timesync_title"),
            button=t("ui.cancel"),
            description=t("usb.timesync_wait"),
            allow_cancel=True,
        )
        res = await loop.race(_read_ready(), screens.run(waiting, 0, False))
        if res is not _READ:
            return False  # any button on the waiting screen = cancel
        n = pipe.read(buf)
        if n <= 0:
            continue
        for resp in await session.feed(bytes(buf[:n])):
            data = memoryview(resp)
            while data:
                written = pipe.write(data)
                if written <= 0:
                    await loop.wait(io.USBIF_VCP | io.POLL_WRITE)
                    continue
                data = data[written:]
    # let the host read the final "OK" before we detach
    await loop.sleep(200)
    return True


async def run() -> bool:
    """Run the time-sync mode; returns True if a time was applied."""
    session = TimeSyncSession(InlineInteraction())
    completed = False
    try:
        await usbmodes.switch(usbmodes.TIMESYNC)
        await loop.race(_serve(session), loop.sleep(IDLE_TIMEOUT_MS))
        completed = True
    finally:
        done = usbmodes.restore_normal()
        if completed:
            await done
    return session.applied
