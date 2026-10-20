# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""ROM lookup parity and temporary registration ownership on firmware."""

import importlib.util
from pathlib import Path

import pytest

from feuristic.core import i18n
from feuristic.core._i18n_rom import TABLE

ROOT = Path(__file__).resolve().parents[3]


def test_generated_table_matches_all_application_translations():
    spec = importlib.util.spec_from_file_location("generate_i18n_rom", ROOT / "tools/generate_i18n_rom.py")
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    assert generator.DESTINATION.read_text() == generator.render()
    assert dict(TABLE) == generator.translations()
    assert [key for key, _value in TABLE] == sorted({key for key, _value in TABLE})


def test_firmware_binary_lookup_keeps_all_languages_and_formats(monkeypatch):
    monkeypatch.setattr(i18n, "FIRMWARE", True)
    monkeypatch.setattr(i18n, "_ROM", TABLE)
    monkeypatch.setattr(i18n, "_lang", i18n.EN)
    assert i18n.keys() == [key for key, _value in TABLE]
    for key, pair in TABLE:
        assert i18n._entry(key) is pair
        for language in (i18n.EN, i18n.FR):
            i18n.set_language(language)
            assert i18n.t(key) == (pair[language] or pair[i18n.EN])
    assert i18n.t("") == ""
    assert i18n.t("zzzz.unknown") == "zzzz.unknown"
    assert i18n._entry("aa.unknown") is None
    assert i18n.missing_translations() == []
    i18n.set_language(i18n.EN)
    assert i18n.t("backup.ui.frames", 4) == dict(TABLE)["backup.ui.frames"][0].format(4)


def test_firmware_registration_releases_only_verified_temporary_tables(monkeypatch):
    monkeypatch.setattr(i18n, "FIRMWARE", True)
    monkeypatch.setattr(i18n, "_ROM", TABLE)
    original_tables = i18n._tables[:]
    temporary = dict(TABLE[:3])
    i18n.register(temporary)
    assert temporary == {}
    assert i18n._tables == original_tables
    i18n.register(temporary)
    key = TABLE[0][0]
    bad = {key: ("wrong", "incorrect")}
    with pytest.raises(ValueError):
        i18n.register(bad)
    assert bad
    with pytest.raises(ValueError):
        i18n.register({"new.uncompiled.key": ("New", "Nouveau")})
