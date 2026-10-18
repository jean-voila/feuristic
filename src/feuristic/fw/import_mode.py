# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Temporary "QR import" USB mode (spec §3.3, §8.2).

1. free memory, allocate the import session, re-enumerate as MSC only;
2. the USB task serves the FAT12 volume; images are decoded while they are
   written (ADR-0003) and QR codes are read once each file is complete and
   synchronised;
3. payloads feed :class:`~feuristic.apps.importer.session.ImportSession`
   (``otpauth://`` URI or ``FB1:`` backup frames, several files per session);
4. once ready, the user confirms the import/restore on the device;
5. the device asks the user to eject the volume and keeps the interface
   until the host ejects it (SCSI START STOP UNIT), then re-enumerates in
   NORMAL mode. Cancelling or unplugging aborts and purges everything.
"""

import gc

import trezorui_api
import utime
from micropython import const
from trezor import io, loop, utils

from ..apps.importer import session as isession
from ..core.i18n import t
from ..ui import screens
from ..ui.interaction import InlineInteraction
from . import usbmodes

POLL_MS = const(50)
IDLE_TIMEOUT_MS = const(10 * 60 * 1000)

_EV_FRAME_MAX = const(65)


def _readme() -> bytes:
    text = (
        "feuristic - QR import\r\n\r\n"
        "Copy PNG or baseline JPEG images (max 256 KiB, 1024x1024) of one QR code\r\n"
        "each to this drive, then follow the instructions on the device.\r\n"
        "Copied images are decoded on the fly and are not stored: reading them\r\n"
        "back returns zeros. Eject the drive when the device asks for it.\r\n\r\n"
        "Copiez des images PNG ou JPEG baseline (max 256 Kio, 1024x1024) contenant\r\n"
        "chacune un QR code, puis suivez les instructions sur l'appareil.\r\n"
        "Les images sont decodees a la volee et ne sont pas conservees : leur\r\n"
        "relecture renvoie des zeros. Ejectez le volume quand l'appareil le demande.\r\n"
    )
    return text.encode()


class _State:
    def __init__(self) -> None:
        self.message = t("importer.instructions")
        self.changed = loop.mailbox()
        self.ejected = False
        self.detached = False

    def set(self, message: str) -> None:
        self.message = message
        self.changed.put(True, replace=True)


async def _usb_task(sess, imp, state) -> None:
    """Serve the MSC pipe forever (the controller ends the race)."""
    pipe = io.USBPipe(io.USBIF_MSC)
    buf = bytearray(_EV_FRAME_MAX)
    while True:
        try:
            await loop.wait(pipe.iface_num() | io.POLL_READ, POLL_MS)
            n = pipe.read(buf)
            if n > 0:
                sess.feed(bytes(buf[:n]))
        except loop.Timeout:
            pass
        # flush queued IN data / stalls
        while True:
            frame = sess.tx()
            if frame is None:
                break
            if pipe.write(frame) <= 0:
                await loop.wait(pipe.iface_num() | io.POLL_WRITE)
                continue
            sess.tx_done()
        sess.poll(utime.ticks_ms())
        while True:
            ev = sess.event()
            if ev is None:
                break
            kind, _stream, code, name = ev
            if kind == "start":
                state.set(t("import.receiving", name or "..."))
            elif kind == "stream_error":
                state.set(t("import.err.stream", code))
            elif kind in ("ejected", "stopped"):
                state.ejected = True
                state.changed.put(True, replace=True)
        res = sess.decode()
        if res is not None:
            if res[0] == "qr":
                ev = imp.add_payload(res[1])
                msg = t(ev.key) if ev.key else ""
                if ev.total:
                    msg += "\n" + t("importer.progress", ev.received, ev.total)
                state.set(msg)
            else:
                state.set(t("import.err." + res[1], res[2]))


async def _wait_screen(state, title: str, text: str, button: str):
    """Show ``text`` until the user presses the button (returns True) or the
    state changes (returns False)."""
    layout = trezorui_api.show_warning(title=title, button=button, description=text, allow_cancel=True)
    res = await loop.race(screens.run(layout, 0, False), state.changed)
    return res is not True


async def _passphrase(req):
    p = await screens.request_text(t("backup.passphrase.enter"), 128)
    return None if p is None else bytearray(p.encode())


async def _do_action(imp) -> None:
    action = imp.action()
    ui = InlineInteraction()
    if action.kind == isession.ACTION_OTP:
        from ..apps.otp import accounts

        try:
            await accounts.default().import_uri(bytes(action.otp_uri), ui)
            await screens.show_info(t("otp.import.added"), timeout_ms=2000, close_others=False)
        except Exception as e:
            await screens.show_error(t(_otp_error_key(e)))
    elif action.kind == isession.ACTION_RESTORE:
        from ..apps.backup import restore, strings

        progress = screens.Progress(t("backup.kdf.progress"))
        try:
            report = await restore.restore(
                ui, action.envelopes, _passphrase, progress=lambda d, n: progress.report(d / n if n else 1)
            )
        except Exception as e:
            progress.stop()
            await screens.show_error(t(strings.error_key(e)))
            return
        progress.stop()
        await screens.show_info(
            t("backup.restore.done"), t("backup.restore.summary", len(report.restored), len(report.skipped))
        )


def _otp_error_key(e) -> str:
    from ..apps.otp.accounts import AlreadyExists
    from ..core.errors import InvalidInput, StorageFull, UserCancelled

    if isinstance(e, UserCancelled):
        return "ui.cancel"
    if isinstance(e, AlreadyExists):
        return "otp.import.exists"
    if isinstance(e, StorageFull):
        return "otp.full"
    if isinstance(e, InvalidInput):
        return "otp.import.invalid"
    return "ui.error"


async def _controller(imp, state) -> None:
    title = t("importer.title")
    # phase 1: collect images until an action is ready (or the user cancels)
    cancelled = False
    while not imp.is_ready():
        if state.ejected:
            return
        if await _wait_screen(state, title, state.message, t("ui.cancel")):
            cancelled = True  # nothing is imported; still ask for a clean eject
            break
    if not cancelled:
        # phase 2: confirm and perform the action on the device
        await _do_action(imp)
    imp.finish()
    # phase 3: eject. The interface disappears only after the host ejects the
    # volume (spec §3.3); pressing the button here leaves anyway (the host
    # may then warn about an unclean removal, nothing is lost).
    while not state.ejected:
        if await _wait_screen(state, title, t("importer.eject"), t("import.leave_now")):
            return


async def run(purpose: str = "otp") -> None:
    """Run the import mode from the device menu."""
    from . import transports

    try:
        import feuristic_import
    except ImportError:
        await screens.show_error(t("ui.not_implemented"))
        return
    transports.on_lock()  # drop protocol objects: free heap for the decoder
    gc.collect()
    max_out = 512 if utils.INTERNAL_MODEL == "T2B1" else 720
    try:
        sess = feuristic_import.Session(_readme(), max_out, utime.ticks_ms())
    except MemoryError:
        gc.collect()
        await screens.show_error(t("import.err.memory"))
        return
    imp = isession.ImportSession()
    state = _State()
    try:
        await usbmodes.switch(usbmodes.IMPORT)
        await loop.race(_controller(imp, state), _usb_task(sess, imp, state), loop.sleep(IDLE_TIMEOUT_MS))
    finally:
        imp.abort()
        sess.close()
        del sess
        gc.collect()
        await usbmodes.switch(usbmodes.NORMAL)
