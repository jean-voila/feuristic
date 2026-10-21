# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Applet descriptors which load private application code only on SELECT."""

import gc
import sys

from .applet import Applet


class LazyApplet(Applet):
    """Keep each selected applet's normal reset/deselect semantics intact."""

    def __init__(self, name, aid, factory, unload_on_deselect=False) -> None:
        self.NAME = name
        self.AID = aid
        self._factory = factory
        self._instance = None
        self._unload = unload_on_deselect
        self._modules = ()

    def _get(self):
        if self._instance is None:
            if not self._unload:
                self._instance = self._factory(self.NAME)
            else:
                before = set(sys.modules)
                try:
                    self._instance = self._factory(self.NAME)
                finally:
                    self._modules = tuple(name for name in sys.modules if name not in before)
                    if self._instance is None:
                        self._release()
        return self._instance

    def _release(self):
        self._instance = None
        for name in self._modules:
            module = sys.modules.pop(name, None)
            parent, _, leaf = name.rpartition(".")
            package = sys.modules.get(parent)
            if package is not None and getattr(package, leaf, None) is module:
                delattr(package, leaf)
        self._modules = ()
        gc.collect()

    async def select(self, cmd):
        return await self._get().select(cmd)

    async def process(self, cmd):
        return await self._get().process(cmd)

    def deselect(self) -> None:
        if self._instance is not None:
            self._instance.deselect()
            if self._unload:
                self._release()

    def reset(self) -> None:
        if self._instance is not None:
            self._instance.reset()
            if self._unload:
                self._release()
