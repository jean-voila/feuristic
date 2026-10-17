# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""FIDO2 application object: routes CTAPHID MSG/CBOR requests to the U2F
and CTAP2 handlers (used by :class:`~.ctaphid.HidServer`)."""

from . import strings
from .ctap1 import U2f
from .ctap2 import Authenticator
from .ctaphid import CMD_CBOR, CMD_MSG


class Fido2App:
    def __init__(self, ctx) -> None:
        strings.register()
        self.ctx = ctx
        self.auth = Authenticator(ctx)
        self.u2f = U2f(self.auth)

    async def handle(self, txn) -> tuple:
        """Process a complete CTAPHID transaction; return ``(cmd, payload)``."""
        if txn.cmd == CMD_MSG:
            return self.u2f.handle(txn.payload)
        # a CTAP2 command supersedes any U2F approval being collected
        self.u2f.reset_dialog()
        return CMD_CBOR, await self.auth.dispatch(txn.payload, txn)

    def background_job(self):
        """Coroutine to run concurrently (pending U2F presence dialog)."""
        return self.u2f.dialog_job()
