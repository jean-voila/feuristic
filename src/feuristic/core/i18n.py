# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Built-in English/French string tables (spec §9: FR/EN in the first release,
no translation loaded from the host).

Each application module declares its strings in a ``strings.py`` next to it::

    STRINGS = {
        "otp.title": ("One-time passwords", "Mots de passe à usage unique"),
    }

and registers them with :func:`register`. Keys are dotted, lower-case and
prefixed by the application name. :func:`t` looks a key up in the current
language and falls back to English, then to the key itself (so a missing
translation is visible but never crashes).
"""

from micropython import const

from ..platform._backend import FIRMWARE

if FIRMWARE:
    from ._i18n_rom import TABLE as _ROM
else:
    _ROM = ()

EN = const(0)
FR = const(1)
LANGUAGES = ("en", "fr")

_tables = []
_lang = EN


def _entry(key):
    if FIRMWARE:
        low = 0
        high = len(_ROM)
        while low < high:
            middle = (low + high) // 2
            candidate = _ROM[middle]
            if candidate[0] < key:
                low = middle + 1
            elif candidate[0] > key:
                high = middle
            else:
                return candidate[1]
        return None
    for table in _tables:
        value = table.get(key)
        if value is not None:
            return value
    return None


def register(strings: dict) -> None:
    """Register a read-only application table without copying every entry.

    Tables remain owned by their strings modules. Re-registering identical
    translations is harmless; conflicting keys are rejected before mutation.
    """
    if FIRMWARE:
        # Application modules can still register their host-compatible table
        # after lazy loading. Verify it against ROM, then release the temporary
        # dictionary rather than retaining a second copy on the device heap.
        for key, value in strings.items():
            if _entry(key) != value:
                raise ValueError("firmware i18n table differs from ROM: " + key)
        strings.clear()
        return
    new_keys = False
    for k, v in strings.items():
        previous = _entry(k)
        if previous is not None and previous != v:
            raise ValueError("duplicate i18n key: " + k)
        if not isinstance(v, tuple) or len(v) != 2:
            raise ValueError("i18n value must be (en, fr): " + k)
        if previous is None:
            new_keys = True
    if new_keys:
        _tables.append(strings)


def set_language(lang: int) -> None:
    global _lang
    if lang not in (EN, FR):
        raise ValueError("language")
    _lang = lang


def language() -> int:
    return _lang


def t(key: str, *args) -> str:
    """Translate ``key`` and apply ``str.format(*args)`` if args are given."""
    entry = _entry(key)
    if entry is None:
        s = key
    else:
        s = entry[_lang] or entry[EN]
    if args:
        return s.format(*args)
    return s


def keys() -> list:
    if FIRMWARE:
        return [entry[0] for entry in _ROM]
    return sorted({key for table in _tables for key in table})


def missing_translations() -> list:
    """Keys whose French text is empty (used by tests to enforce coverage)."""
    return [key for key in keys() if not _entry(key)[FR]]
