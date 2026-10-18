# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""On-device implementation of :class:`feuristic.core.interaction.Interaction`.

Protocol handlers run inside long-lived USB tasks that are *not* workflows.
Each dialog is therefore spawned as a workflow (like upstream's FIDO dialog)
so that the default homescreen task does not take the screen back while the
user is deciding, and other workflows (an open menu) are closed first.
"""

from trezor import loop, workflow

from ..core import interaction as ia
from ..core.i18n import t
from . import screens


def _fields(prompt) -> list:
    items = []
    for label, value in prompt.fields:
        items.append((t(label), str(value), False))
    if prompt.fingerprint:
        items.append((t("ui.fingerprint"), prompt.fingerprint, True))
    return items


class DeviceInteraction(ia.Interaction):
    def __init__(self) -> None:
        #: called with True while a dialog is shown (USB glue sends keepalives)
        self.on_busy = None
        self._lock = False
        self._current = None

    async def _spawn(self, coro):
        # Only one dialog at a time; a second request waits for the first.
        while self._lock:
            await loop.sleep(50)
        self._lock = True
        if self.on_busy is not None:
            self.on_busy(True)
        try:
            self._current = workflow.spawn(coro)
            return await self._current
        finally:
            self._current = None
            self._lock = False
            if self.on_busy is not None:
                self.on_busy(False)

    def cancel(self) -> None:
        """Abort the dialog on screen (host-side CTAPHID CANCEL): the waiting
        protocol handler sees a refusal."""
        if self._current is not None:
            self._current.close()

    def wink(self) -> None:
        """CTAPHID WINK: briefly show the device name so the user can identify it."""
        if self._current is not None:
            return

        async def dialog() -> None:
            await screens.show_info("feuristic", "\u25cf \u25cf \u25cf", timeout_ms=1500)

        loop.schedule(workflow.spawn(dialog()))

    async def confirm(self, prompt) -> bool:
        async def dialog() -> bool:
            hold = prompt.severity == ia.DANGER
            items = _fields(prompt)
            if items:
                return await screens.confirm_fields(
                    t(prompt.title), items, hold=hold, timeout_ms=prompt.timeout_ms
                )
            return await screens.confirm(t(prompt.title), hold=hold, timeout_ms=prompt.timeout_ms)

        try:
            return bool(await self._spawn(dialog()))
        except Exception:
            # a closed/cancelled dialog is a refusal, never an approval
            return False

    async def select(self, title: str, options, timeout_ms: int = ia.DEFAULT_TIMEOUT_MS):
        async def dialog():
            return await screens.menu(t(title), list(options), back=True, timeout_ms=timeout_ms)

        try:
            res = await self._spawn(dialog())
        except Exception:
            return None
        if isinstance(res, int) and 0 <= res < len(options):
            return res
        return None

    async def notify(self, kind: str, title: str, fields=()) -> None:
        text = "\n".join(f"{t(k)}: {v}" for k, v in fields)

        async def dialog() -> None:
            await screens.show_info(t(title), text, timeout_ms=3000)

        try:
            await self._spawn(dialog())
        except Exception:
            pass


class InlineInteraction(ia.Interaction):
    """Interaction for code that already runs inside a menu workflow (time
    sync, import, local management): dialogs are drawn directly, without
    spawning a workflow or closing the caller."""

    async def confirm(self, prompt) -> bool:
        hold = prompt.severity == ia.DANGER
        items = _fields(prompt)
        if items:
            return await screens.confirm_fields(
                t(prompt.title), items, hold=hold, timeout_ms=prompt.timeout_ms, close_others=False
            )
        return await screens.confirm(
            t(prompt.title), hold=hold, timeout_ms=prompt.timeout_ms, close_others=False
        )

    async def select(self, title: str, options, timeout_ms: int = ia.DEFAULT_TIMEOUT_MS):
        res = await screens.menu(
            t(title), list(options), back=True, timeout_ms=timeout_ms, close_others=False
        )
        if isinstance(res, int) and 0 <= res < len(options):
            return res
        return None

    async def notify(self, kind: str, title: str, fields=()) -> None:
        text = "\n".join(f"{t(k)}: {v}" for k, v in fields)
        await screens.show_info(t(title), text, timeout_ms=3000, close_others=False)
