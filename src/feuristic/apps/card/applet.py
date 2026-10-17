# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Base class for the applications of the virtual smart card.

The virtual card hosts several applets (OpenPGP, PIV, feuristic AES/RNG
profile) selected by AID (ISO 7816-4 SELECT by DF name). Applets never share
keys (spec §2.1, §6.2).
"""


class Applet:
    #: full AID (bytes); SELECT matches if the command data is a prefix of it
    #: (partial AID selection, ISO 7816-4 §11.2.2.2), unless EXACT_SELECT.
    AID = b""
    EXACT_SELECT = False
    NAME = "applet"

    def __init__(self, ui) -> None:
        #: :class:`feuristic.core.interaction.Interaction`
        self.ui = ui

    def matches(self, aid_prefix: bytes) -> bool:
        if not aid_prefix:
            return False
        if self.EXACT_SELECT:
            return bytes(aid_prefix) == self.AID
        return self.AID.startswith(bytes(aid_prefix))

    async def select(self, cmd) -> "Response":  # noqa: F821
        """Handle SELECT (already matched). Return the SELECT response."""
        raise NotImplementedError

    def deselect(self) -> None:
        """Called when another applet is selected or the card is reset.

        Applets must drop any volatile authentication state here
        (verified PINs, authenticated management key, ...)."""

    def reset(self) -> None:
        """Card power-on/reset (ICC power off, USB re-enumeration, lock)."""
        self.deselect()

    async def process(self, cmd) -> "Response":  # noqa: F821
        """Handle a (de-chained) command for this applet."""
        raise NotImplementedError
