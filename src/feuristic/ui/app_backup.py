# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""On-device encrypted backup export and USB-image restore entry points.

Only one identity's encrypted frames are held in memory. No export payload
is returned to a USB handler. The core marks an identity exported before
returning its frames, as required by backup-format-v1 §7.
"""

import gc

from trezor import loop

from ..apps.backup import envelope, export, frames, provider, strings
from ..apps.backup.errors import WeakPassphrase
from ..core.errors import FeuristicError, NotFound, PolicyDenied, UserCancelled
from ..core.i18n import t
from ..core.secure import wipe
from . import screens, strings_backup
from .interaction import InlineInteraction

strings_backup.register()


async def _passphrase(_request):
    from ..fw import pin

    for _ in range(export.MAX_POLICY_ATTEMPTS):
        if not await screens.confirm(
            t("backup.passphrase.enter"), t("backup.ui.passphrase"), verb=t("ui.continue")
        ):
            return None
        first = await screens.request_text(
            t("backup.passphrase.enter"), envelope.PASSPHRASE_MAX_LEN, close_others=False
        )
        if first is None:
            return None
        pw = bytearray(first.encode())
        first = None
        try:
            try:
                envelope.check_passphrase(pw)
            except WeakPassphrase:
                await screens.show_error(t("backup.ui.passphrase"))
                continue
            second = await screens.request_text(
                t("backup.passphrase.confirm"), envelope.PASSPHRASE_MAX_LEN, close_others=False
            )
            if second is None:
                return None
            repeat = bytearray(second.encode())
            second = None
            try:
                matches = envelope.passphrases_match(pw, repeat)
            finally:
                wipe(repeat)
            if matches:
                if not await pin.reauthenticate(distinct_from=pw):
                    raise UserCancelled("backup reauthentication refused")
                result = pw
                pw = None  # ownership passes to export._begin, which wipes it
                return result
            await screens.show_error(t("backup.passphrase.mismatch"))
        finally:
            if pw is not None:
                wipe(pw)
    raise WeakPassphrase("backup phrase entry failed")


class _Derivation:
    def __init__(self) -> None:
        self.progress = None

    def report(self, done, total) -> None:
        # Start only after the passphrase dialogs have finished.
        if self.progress is None:
            self.progress = screens.Progress(t("backup.ui.progress"))
        self.progress.report(done / total if total else 1)
        if done >= total:
            self.stop()

    def stop(self) -> None:
        if self.progress is not None:
            self.progress.stop()
            self.progress = None


async def _yield():
    await loop.sleep(0)


async def _display(result) -> bool:
    """Return True only once every QR has been shown and the user finishes."""
    total = len(result.frames)
    if not await screens.confirm(
        t("backup.identity.counter", result.seq, result.count),
        result.label + "\n" + t("backup.ui.frames", total) + "\n" + t("backup.version", 1),
        verb=t("ui.continue"),
    ):
        return False
    index = 0
    furthest = -1
    while True:
        # Caesar uses the entire screen for the QR; show its number first.
        await screens.show_info(
            t("backup.frame.counter", index + 1, total),
            result.label,
            timeout_ms=1000,
            close_others=False,
        )
        action = await screens.show_qr_page(
            t("backup.frame.counter", index + 1, total),
            result.frames[index],
            screens.QR_TIMEOUT_MS,
            close_others=False,
        )
        furthest = max(furthest, index)
        if action is None or action == screens.QR_BACK:
            return False
        if action == screens.QR_PREV:
            index = max(0, index - 1)
        elif action == screens.QR_NEXT:
            if index == total - 1:
                return True
            index += 1
        elif action == screens.QR_BOTH:
            if furthest == total - 1:
                return True
            if not await screens.confirm(
                t("backup.ui.incomplete"), t("backup.ui.controls"), verb=t("ui.continue")
            ):
                return False


async def _run(item_type=None, uid=None) -> None:
    profile = await screens.menu(
        t("backup.ui.profile"), [t("backup.profile.large"), t("backup.profile.dense")]
    )
    if profile is None:
        return
    profile = frames.PROFILE_LARGE if profile == 0 else frames.PROFILE_DENSE
    ui = InlineInteraction()
    session = None
    result = None
    progress = _Derivation()
    complete = False
    try:
        if item_type is None:
            if not await screens.confirm(t("backup.export_full.title"), t("backup.warn.slow")):
                return
            session = await export.begin_full_export(
                ui,
                _passphrase,
                profile=profile,
                progress=progress.report,
                yield_fn=_yield,
            )
        else:
            session = await export.begin_identity_export(
                ui,
                item_type,
                uid,
                _passphrase,
                profile=profile,
                progress=progress.report,
                yield_fn=_yield,
            )
        progress.stop()
        if not await screens.confirm(t("backup.menu.title"), t("backup.ui.controls"), verb=t("ui.continue")):
            return
        for index in range(len(session)):
            gc.collect()
            result = session.build(index)
            if not await _display(result):
                break
            result.frames.clear()
            result = None
        else:
            complete = True
    except UserCancelled:
        return
    except PolicyDenied:
        await screens.show_error(t("backup.ui.failed"))
        return
    except NotFound:
        await screens.show_info(t("backup.nothing") if item_type is None else t("backup.ui.unavailable"))
        return
    except FeuristicError as exc:
        await screens.show_error(t(strings.error_key(exc)))
        return
    except (MemoryError, ValueError):
        await screens.show_error(t("backup.ui.failed"))
        return
    finally:
        progress.stop()
        if result is not None:
            result.frames.clear()
        if session is not None:
            session.close()
        screens.show_busy(t("backup.ui.closed"))
        gc.collect()
    await screens.show_info(t("backup.ui.done" if complete else "backup.ui.cancelled"), timeout_ms=2000)


async def export_record(item_type, uid) -> None:
    """Export the registered provider's identity, including local auth."""
    await _run(item_type, uid)


async def export_identity() -> None:
    available = []
    for p in provider.all():
        identities = p.list_identities()
        if identities:
            available.append((p, identities))
    if not available:
        await screens.show_info(t("backup.nothing"), timeout_ms=2000)
        return
    category = await screens.menu(t("backup.ui.choose_type"), [export.category_name(p) for p, _ in available])
    if category is None:
        return
    p, identities = available[category]
    selected = await screens.menu(export.category_name(p), [label for _, label in identities])
    if selected is not None:
        await export_record(p.TYPE, identities[selected][0])


async def export_full() -> None:
    await _run()


async def restore() -> None:
    from ..fw import import_mode

    await import_mode.run(purpose="backup")
