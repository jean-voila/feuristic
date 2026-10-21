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

from ..apps.importer import payload
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
        "Copy all QR images of ONE identity, confirm on the device, then copy\r\n"
        "the next identity. For large sets use short names QR000001.PNG and\r\n"
        "batches of at most 32 images (fewer if host metadata fills the drive).\r\n"
        "Wait for the received QR count, then delete that batch FROM THIS DRIVE\r\n"
        "ONLY. Keep your originals. Continue without ejecting until complete.\r\n"
        "While confirmation is pending, writes fail with\r\n"
        "NOT READY: wait for the device to resume, then retry failed copies.\r\n"
        "Copied images are decoded on the fly and are not stored: reading them\r\n"
        "back returns zeros. Eject the drive when the device asks for it.\r\n\r\n"
        "Copiez des images PNG ou JPEG baseline (max 256 Kio, 1024x1024) contenant\r\n"
        "chacune un QR code, puis suivez les instructions sur l'appareil.\r\n"
        "Copiez UNE identite, confirmez sur l'appareil puis copiez la suivante.\r\n"
        "Pour les grands ensembles : noms courts QR000001.PNG, lots de 32 images\r\n"
        "maximum (moins si les fichiers caches de l'ordinateur saturent le volume).\r\n"
        "Attendez le nombre de QR recus, puis supprimez ce lot DU VOLUME SEULEMENT.\r\n"
        "Gardez vos originaux. Continuez sans ejecter jusqu'a l'identite complete.\r\n"
        "Pendant la confirmation, les copies sont refusees : attendez la\r\n"
        "reprise puis recommencez les copies qui ont echoue.\r\n"
        "Les images sont decodees a la volee et ne sont pas conservees : leur\r\n"
        "relecture renvoie des zeros. Ejectez le volume quand l'appareil le demande.\r\n"
    )
    return text.encode()


class _State:
    def __init__(self, purpose="otp") -> None:
        self.purpose = purpose
        self.message = t("import.ui.instructions")
        self.changed = loop.mailbox()
        self.ejected = False
        self.detached = False
        self.decoder_paused = False
        self.retry_copy = False
        self.finishing = False

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
            elif kind == "write_paused":
                state.retry_copy = True
                state.set(t("import.ui.copy_paused"))
            elif kind in ("ejected", "stopped"):
                state.ejected = True
                state.changed.put(True, replace=True)
        res = sess.decode()
        if res is not None:
            if res[0] == "qr":
                kind = payload.classify(res[1]).kind
                if (state.purpose == "backup" and kind == payload.KIND_OTPAUTH) or (
                    state.purpose == "otp" and kind == payload.KIND_BACKUP_FRAME
                ):
                    state.set(t("import.ui.wrong_purpose"))
                    continue
                ev = imp.add_payload(res[1])
                msg = t(ev.key, ev.index, ev.total) if ev.key else ""
                if ev.total:
                    msg += "\n" + t("importer.progress", ev.received, ev.total)
                if imp.has_backup():
                    done, missing = imp.counts()
                    msg += "\n" + t("importer.progress.sequences", done, missing)
                state.set(msg)
            else:
                state.set(t("import.err." + res[1], res[2]))
        # At this point the completed image's payload was copied into the
        # bounded collector and no QR decoder is using the scratch buffers.
        # Pause only at a BOT boundary; new writes then fail explicitly.
        if not state.decoder_paused and (state.finishing or _has_ready(imp)) and sess.pause_decode():
            state.decoder_paused = True
            state.changed.put(True, replace=True)


async def _wait_screen(state, title: str, text: str, button: str):
    """True = approved, False = updated, None = cancelled. Never interpret
    the long-left cancellation as permission to restore."""
    layout = trezorui_api.show_warning(title=title, button=button, description=text, allow_cancel=True)
    res = await loop.race(screens.run(layout, 0, False), state.changed)
    if res is True:
        return False
    if res is trezorui_api.CONFIRMED:
        return True
    return None


async def _passphrase(req):
    p = await screens.request_text(t("backup.passphrase.enter"), 128, close_others=False)
    return None if p is None else bytearray(p.encode())


async def _do_action(imp) -> None:
    """OTP action. Backup envelopes use the streaming controller below."""
    action = imp.action()
    ui = InlineInteraction()
    if action.kind == isession.ACTION_OTP:
        from ..apps.otp import accounts

        try:
            await accounts.default().import_uri(bytes(action.otp_uri), ui)
            await screens.show_info(t("otp.import.added"), timeout_ms=2000, close_others=False)
        except Exception as e:
            await screens.show_error(t(_otp_error_key(e)))


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


def _has_ready(imp) -> bool:
    return imp.has_otp() or imp.counts()[0] > 0


async def _resume_decoder(sess, state) -> None:
    from . import session

    session.release_import_stores()
    gc.collect()
    while not sess.resume_decode():
        await loop.sleep(POLL_MS)
    state.decoder_paused = False
    state.retry_copy = False
    state.set(t("import.ui.instructions"))


async def _controller(sess, imp, state, streaming=None, progress=None) -> None:
    from ..apps.backup.errors import RestoreLimitExceeded
    from ..core.errors import FeuristicError, UserCancelled

    title = t("importer.title")
    raw = None
    try:
        while not state.ejected:
            ready = _has_ready(imp) and state.decoder_paused
            if ready and state.purpose == "otp":
                await _do_action(imp)
                break
            text = state.message
            if ready:
                text += "\n" + t("import.ui.ready")
            started = streaming is not None and bool(streaming.report.restored or streaming.report.skipped)
            if not ready and started:
                text += "\n" + t("import.ui.restored", len(streaming.report.restored))
            button = t("ui.continue") if ready else t("ui.done" if started else "ui.cancel")
            result = await _wait_screen(state, title, text, button)
            if result is None or (result is True and not ready):
                missing = imp.counts()[1]
                incomplete = [] if streaming is None else streaming.incomplete_sets()
                if (missing or incomplete) and not await screens.confirm(
                    t("backup.restore_incomplete.title"),
                    t("import.ui.incomplete"),
                    verb=t("ui.done"),
                    close_others=False,
                ):
                    continue
                break
            if result is not True or not ready:
                continue
            raw = imp.take_complete()
            if raw is None:
                continue
            # Decoder RAM is already freed; hold at most one authenticated
            # identity, then release it before accepting the next images.
            from ..apps.backup import restore, strings
            from ..ui.backup_progress import Derivation, yield_control

            if streaming is None:
                progress = Derivation()
                streaming = restore.StreamingRestore(
                    InlineInteraction(),
                    _passphrase,
                    progress=progress.report,
                    yield_fn=yield_control,
                    max_envelopes=isession.DEVICE_MAX_ENVELOPES,
                    max_sets=isession.DEVICE_MAX_SETS,
                )
            # Only provider code imported for this identity is temporary.
            # The live controller, registry and KDF must precede the mark.
            modules = utils.unimport_begin()
            from ..core import store as record_store

            old_buffer = record_store.use_write_buffer(imp._arena)
            try:
                report = await streaming.restore_envelope(raw)
                if report.failed is not None:
                    await screens.show_error(t(strings.error_key(report.failed[2])), close_others=False)
                    break
            except RestoreLimitExceeded:
                await screens.show_error(t("import.ui.session_limit"), close_others=False)
                break
            except UserCancelled:
                break
            except FeuristicError as exc:
                await screens.show_error(t(strings.error_key(exc)), close_others=False)
                break
            finally:
                record_store.use_write_buffer(old_buffer)
                raw = None
                progress.stop()
                from . import session

                session.release_import_stores()
                utils.unimport_end(modules)
            await screens.show_info(
                t("backup.restore_done.title"),
                t("import.ui.restored", len(streaming.report.restored)),
                timeout_ms=1500,
                close_others=False,
            )
            if state.ejected:
                break
            if state.retry_copy:
                await screens.show_warning(t("importer.title"), t("import.ui.retry_copy"), close_others=False)
            await _resume_decoder(sess, state)
    except MemoryError:
        await screens.show_error(t("import.err.memory"), close_others=False)
    finally:
        raw = None
        if progress is not None:
            progress.stop()
        if streaming is not None:
            streaming.close()
        gc.collect()
    imp.finish()
    state.finishing = True
    # Phase 3: keep MSC until host ejects, or the session times out.
    while not state.ejected:
        await _wait_screen(state, title, t("importer.eject"), t("ui.ok"))


async def run(purpose: str = "otp") -> None:
    """Run the import mode from the device menu."""
    from . import session, transports

    if purpose not in ("otp", "backup"):
        raise ValueError("unknown import purpose")
    import feuristic_import

    sess = None
    imp = None
    streaming = None
    progress = None
    completed = False
    no_memory = False
    try:
        transports.suspend()  # free protocol objects before allocating the decoder
        await transports.wait_suspended()
        session.release_import_modules()
        if purpose == "backup":
            # These modules survive every identity. Load them before native
            # pages occupy the heap, rather than splitting their freed holes
            # during the first restore.
            from ..apps.backup import restore
            from ..ui import backup_progress

            progress = backup_progress.Derivation()
            streaming = restore.StreamingRestore(
                InlineInteraction(),
                _passphrase,
                progress=progress.report,
                yield_fn=backup_progress.yield_control,
                max_envelopes=isession.DEVICE_MAX_ENVELOPES,
                max_sets=isession.DEVICE_MAX_SETS,
                reserve_ledger=True,
            )
        gc.collect()
        max_out = 256 if utils.INTERNAL_MODEL == "T2B1" else 720
        imp = isession.ImportSession(
            max_backups=isession.DEVICE_MAX_BACKUPS,
            max_bytes=isession.DEVICE_MAX_BYTES,
            compact=True,
            reserve_bytes=5440,
        )
        sess = feuristic_import.Session(_readme(), max_out, utime.ticks_ms())
        state = _State(purpose)
        await usbmodes.switch(usbmodes.IMPORT)
        await loop.race(
            _controller(sess, imp, state, streaming, progress),
            _usb_task(sess, imp, state),
            loop.sleep(IDLE_TIMEOUT_MS),
        )
        completed = True
    except MemoryError:
        no_memory = True
        completed = True
    finally:
        if imp is not None:
            imp.abort()
        if sess is not None:
            sess.close()
        sess = None
        imp = None
        if streaming is not None:
            streaming.close()
        if progress is not None:
            progress.stop()
        streaming = progress = None
        gc.collect()
        # GeneratorExit may not yield: the independent cleanup task survives
        # both workflow closure and cancellation while awaiting its mailbox.
        done = usbmodes.restore_normal()
        if completed:
            await done
    if no_memory:
        await screens.show_error(t("import.err.memory"))
