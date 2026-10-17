# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Contract between protocol handlers and the on-device user interface.

Protocol handlers (CTAP2, OpenPGP, PIV, ...) never draw on the screen. They
describe what must be confirmed with a :class:`Prompt` and ``await`` an
:class:`Interaction` implementation:

* on the device: ``feuristic.ui.DeviceInteraction`` (Rust layouts, buttons);
* in host tests: :class:`ScriptedInteraction`, which records prompts and
  replays scripted answers.

Text conventions: ``title`` and field labels are **i18n keys** (see
:mod:`feuristic.core.i18n`); field values are data shown verbatim.
"""

from micropython import const

DEFAULT_TIMEOUT_MS = const(30_000)

# prompt severities
NORMAL = const(0)
SENSITIVE = const(1)  # uses a key or reveals data: distinct confirmation screen
DANGER = const(2)  # export / erase / overwrite: hold-to-confirm, never default


class Prompt:
    """A confirmation request.

    ``kind`` is a stable identifier (``"fido2.make_credential"``,
    ``"openpgp.sign"``, ``"otp.export"`` ...) used by tests and by the UI
    to pick an icon/layout. ``fields`` is a sequence of ``(label_key,
    value)`` pairs. ``fingerprint`` (optional) is a hex string displayed in
    monospace (spec §6.3).
    """

    def __init__(
        self,
        kind: str,
        title: str,
        fields=(),
        severity: int = NORMAL,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
        fingerprint=None,
    ) -> None:
        self.kind = kind
        self.title = title
        self.fields = tuple(fields)
        self.severity = severity
        self.timeout_ms = timeout_ms
        self.fingerprint = fingerprint

    def __repr__(self) -> str:
        return f"Prompt({self.kind!r}, {self.title!r}, {self.fields!r})"


class Interaction:
    """Abstract interface (documentation only; duck-typed)."""

    async def confirm(self, prompt: Prompt) -> bool:
        """Show ``prompt``; return True only on explicit user approval.

        Returns False on refusal **or** timeout (callers map timeouts to the
        protocol's "operation denied" status)."""
        raise NotImplementedError

    async def select(self, title: str, options, timeout_ms: int = DEFAULT_TIMEOUT_MS):
        """Let the user pick one of ``options`` (list of str). Return the
        index, or None if cancelled/timed out."""
        raise NotImplementedError

    async def notify(self, kind: str, title: str, fields=()) -> None:
        """Show a transient, non-blocking information screen."""
        raise NotImplementedError


class ScriptedInteraction(Interaction):
    """Test double: answers come from a script, prompts are recorded.

    ``answers`` items are consumed in order by ``confirm`` (bool) and
    ``select`` (int or None). If the script is exhausted ``default`` is used.
    """

    def __init__(self, answers=(), default=True) -> None:
        self.answers = list(answers)
        self.default = default
        self.prompts = []
        self.selects = []
        self.notifications = []

    async def confirm(self, prompt: Prompt) -> bool:
        self.prompts.append(prompt)
        if self.answers:
            return bool(self.answers.pop(0))
        return bool(self.default)

    async def select(self, title: str, options, timeout_ms: int = DEFAULT_TIMEOUT_MS):
        self.selects.append((title, list(options)))
        if self.answers:
            return self.answers.pop(0)
        return 0 if self.default else None

    async def notify(self, kind: str, title: str, fields=()) -> None:
        self.notifications.append((kind, title, tuple(fields)))

    def kinds(self) -> list:
        return [p.kind for p in self.prompts]
