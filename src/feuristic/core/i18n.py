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

EN = const(0)
FR = const(1)
LANGUAGES = ("en", "fr")

_tables = {}
_lang = EN


def register(strings: dict) -> None:
    """Merge ``strings`` into the global table. Duplicate keys are a bug."""
    for k, v in strings.items():
        if k in _tables and _tables[k] != v:
            raise ValueError("duplicate i18n key: " + k)
        if not isinstance(v, tuple) or len(v) != 2:
            raise ValueError("i18n value must be (en, fr): " + k)
        _tables[k] = v


def set_language(lang: int) -> None:
    global _lang
    if lang not in (EN, FR):
        raise ValueError("language")
    _lang = lang


def language() -> int:
    return _lang


def t(key: str, *args) -> str:
    """Translate ``key`` and apply ``str.format(*args)`` if args are given."""
    entry = _tables.get(key)
    if entry is None:
        s = key
    else:
        s = entry[_lang] or entry[EN]
    if args:
        return s.format(*args)
    return s


def keys() -> list:
    return sorted(_tables)


def missing_translations() -> list:
    """Keys whose French text is empty (used by tests to enforce coverage)."""
    return [k for k, v in _tables.items() if not v[FR]]
