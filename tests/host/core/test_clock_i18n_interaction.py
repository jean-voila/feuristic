# SPDX-License-Identifier: GPL-3.0-only
import pytest

from feuristic.core import clock as clock_mod
from feuristic.core import i18n, interaction
from feuristic.core.errors import InvalidInput

from ..aio import run

T0 = 1_800_000_000


def test_clock_unset_then_set_and_runs(clock):
    sc = clock_mod.SessionClock()
    assert not sc.is_set()
    assert sc.now() is None
    assert sc.classify(T0) == clock_mod.FIRST_SET
    sc.set(T0)
    assert sc.now() == T0
    clock.advance(61_500)
    assert sc.now() == T0 + 61


def test_clock_classification(clock):
    sc = clock_mod.SessionClock()
    sc.set(T0)
    assert sc.classify(T0 + 10) == clock_mod.ACCEPT
    assert sc.classify(T0 - 60) == clock_mod.ACCEPT
    assert sc.classify(T0 - 61) == clock_mod.CONFIRM_BACKWARD
    assert sc.classify(T0 + 301) == clock_mod.CONFIRM_FORWARD
    with pytest.raises(InvalidInput):
        sc.classify(5)
    with pytest.raises(InvalidInput):
        sc.set(clock_mod.MAX_UNIX + 1)
    with pytest.raises(InvalidInput):
        sc.set("1800000000")
    sc.clear()
    assert not sc.is_set()


def test_i18n_register_translate_fallback():
    i18n.register({"test.hello": ("Hello {}", "Bonjour {}"), "test.only_en": ("Only", "")})
    i18n.set_language(i18n.EN)
    assert i18n.t("test.hello", "Ana") == "Hello Ana"
    i18n.set_language(i18n.FR)
    assert i18n.t("test.hello", "Ana") == "Bonjour Ana"
    assert i18n.t("test.only_en") == "Only"
    assert i18n.t("test.unknown") == "test.unknown"
    assert "test.only_en" in i18n.missing_translations()
    i18n.set_language(i18n.EN)
    with pytest.raises(ValueError):
        i18n.register({"test.hello": ("Other", "Autre")})
    with pytest.raises(ValueError):
        i18n.register({"test.bad": "not a tuple"})
    with pytest.raises(ValueError):
        i18n.set_language(7)


def test_scripted_interaction():
    ui = interaction.ScriptedInteraction(answers=[False, 2], default=True)
    p = interaction.Prompt("x.y", "title", [("k", "v")], severity=interaction.DANGER)
    assert run(ui.confirm(p)) is False
    assert run(ui.select("t", ["a", "b", "c"])) == 2
    assert run(ui.confirm(p)) is True
    run(ui.notify("n", "t"))
    assert ui.kinds() == ["x.y", "x.y"]
    assert "x.y" in repr(p)
    assert ui.notifications == [("n", "t", ())]
