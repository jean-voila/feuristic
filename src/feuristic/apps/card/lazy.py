# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Applet descriptors which load private application code only on SELECT."""

from .applet import Applet


class LazyApplet(Applet):
    """Keep each selected applet's normal reset/deselect semantics intact."""

    def __init__(self, name, aid, factory) -> None:
        self.NAME = name
        self.AID = aid
        self._factory = factory
        self._instance = None

    def _get(self):
        if self._instance is None:
            self._instance = self._factory(self.NAME)
        return self._instance

    async def select(self, cmd):
        return await self._get().select(cmd)

    async def process(self, cmd):
        return await self._get().process(cmd)

    def deselect(self) -> None:
        if self._instance is not None:
            self._instance.deselect()

    def reset(self) -> None:
        if self._instance is not None:
            self._instance.reset()
