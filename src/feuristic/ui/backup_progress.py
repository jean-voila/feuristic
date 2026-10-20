# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Small backup KDF progress adapter, independent of export orchestration."""

from trezor import loop

from ..core.i18n import t
from . import screens


class Derivation:
    def __init__(self) -> None:
        self.progress = None

    def report(self, done, total) -> None:
        if self.progress is None:
            self.progress = screens.Progress(t("backup.ui.progress"))
        self.progress.report(done / total if total else 1)
        if done >= total:
            self.stop()

    def stop(self) -> None:
        if self.progress is not None:
            self.progress.stop()
            self.progress = None


async def yield_control():
    await loop.sleep(0)
