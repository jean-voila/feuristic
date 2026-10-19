# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""DebugLink helper: read the current Rust layout as JSON and press buttons.

Only available in emulator / debug builds (the debuglink interface is not
compiled into release firmware).
"""

from __future__ import annotations

import contextlib
import json
import time

from trezorlib import messages, models
from trezorlib.debuglink import DebugLink
from trezorlib.transport.udp import UdpTransport


class Screen:
    def __init__(self, data: dict) -> None:
        self.data = data

    def _find(self, node, key):
        if isinstance(node, dict):
            if key in node:
                yield node[key]
            for v in node.values():
                yield from self._find(v, key)
        elif isinstance(node, list):
            for v in node:
                yield from self._find(v, key)

    @property
    def title(self) -> str:
        for t in self._find(self.data, "title"):
            if isinstance(t, dict) and "text" in t:
                return t["text"]
            if isinstance(t, str):
                return t
        return ""

    @property
    def choice(self) -> str:
        for c in self._find(self.data, "current_choice"):
            if isinstance(c, dict):
                return str(c.get("content", ""))
        return ""

    def text(self) -> str:
        """All visible strings concatenated (for `in` assertions)."""
        out: list[str] = []

        def walk(n):
            if isinstance(n, str):
                out.append(n)
            elif isinstance(n, dict):
                for k, v in n.items():
                    if k not in ("component", "icon"):
                        walk(v)
            elif isinstance(n, list):
                for v in n:
                    walk(v)

        walk(self.data)
        return " ".join(out)

    @property
    def component(self) -> str:
        return str(self.data.get("component", ""))

    def __repr__(self) -> str:
        return f"Screen(title={self.title!r}, choice={self.choice!r})"


class Debug:
    def __init__(self, port: int, model=models.T3B1) -> None:
        self.port = port
        self.model = model
        self._connect()

    def _connect(self) -> None:
        self.dl = DebugLink(UdpTransport(f"127.0.0.1:{self.port}"), auto_interact=True)
        self.dl.model = self.model

    def screen(self, retries: int = 6) -> Screen:
        """Current layout. Survives USB re-enumerations (mode switches), during
        which the emulated debuglink socket is closed and reopened."""
        for attempt in range(retries):
            try:
                st = self.dl._call(
                    messages.DebugLinkGetState(wait_layout=messages.DebugWaitType.IMMEDIATE), timeout=3
                )
                while not isinstance(st, messages.DebugLinkState):
                    st = self.dl._read(timeout=3)
                raw = "".join(st.tokens)
                return Screen(json.loads(raw) if raw else {})
            except Exception:
                if attempt == retries - 1:
                    raise
                with contextlib.suppress(Exception):
                    self.dl.close()
                time.sleep(0.5)
                self._connect()
        raise AssertionError("unreachable")

    def wait_for(self, predicate, timeout: float = 10.0) -> Screen:
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            last = self.screen()
            if predicate(last):
                return last
            time.sleep(0.1)
        raise AssertionError(f"screen condition not met, last screen: {last!r}\n{last.data if last else ''}")

    def wait_title(self, title: str, timeout: float = 10.0) -> Screen:
        return self.wait_for(lambda s: s.title == title, timeout)

    def _press(self, button: messages.DebugPhysicalButton, hold_ms: int | None = None) -> None:
        self.dl._decision(messages.DebugLinkDecision(physical_button=button, hold_ms=hold_ms), wait=False)
        time.sleep(0.15)

    def left(self) -> None:
        self._press(messages.DebugPhysicalButton.LEFT_BTN)

    def right(self) -> None:
        self._press(messages.DebugPhysicalButton.RIGHT_BTN)

    def both(self) -> None:
        self._press(messages.DebugPhysicalButton.MIDDLE_BTN)

    def hold_left(self, ms: int = 1300) -> None:
        self._press(messages.DebugPhysicalButton.LEFT_BTN, hold_ms=ms)

    def hold_both(self, ms: int = 1500) -> None:
        self._press(messages.DebugPhysicalButton.MIDDLE_BTN, hold_ms=ms)

    def input(self, text: str) -> None:
        """Submit a string to a PIN / text entry layout."""
        self.dl._decision(messages.DebugLinkDecision(input=text), wait=False)
        time.sleep(0.15)

    def _buttons(self, screen: Screen) -> dict:
        for b in screen._find(screen.data, "buttons"):
            if isinstance(b, dict):
                return b
        return {}

    def approve(self, max_steps: int = 20, *, hold: bool = False) -> None:
        """Scroll a confirmation screen to its last page and confirm it."""
        for _ in range(max_steps):
            scr = self.screen()
            btns = self._buttons(scr)
            middle_btn = btns.get("middle_btn") or {}
            right_btn = btns.get("right_btn") or {}
            for button, physical in (
                (middle_btn, messages.DebugPhysicalButton.MIDDLE_BTN),
                (right_btn, messages.DebugPhysicalButton.RIGHT_BTN),
            ):
                if button.get("component") == "HoldToConfirm":
                    assert hold, "held confirmation requires approve(hold=True)"
                    self._press(physical, hold_ms=1500)
                    return
            right = right_btn.get("text")
            middle = middle_btn.get("text")
            if right:
                self.right()
                return
            if middle:
                self.both()
                return
            self.right()  # next page (down arrow)
        raise AssertionError("no confirm button found")

    def select(self, label: str, max_steps: int = 40) -> None:
        """Move the carousel to ``label`` and select it."""
        for _ in range(max_steps):
            if self.screen().choice == label:
                self.both()
                return
            self.right()
        raise AssertionError(f"menu item {label!r} not found")

    def close(self) -> None:
        self.dl.close()
