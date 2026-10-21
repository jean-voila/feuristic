# SPDX-License-Identifier: GPL-3.0-only
"""R01 (emulated): boot, two-button menu, PIN, FR/EN."""

import pytest
from conftest import TEST_PIN, enter_pin, onboard


def test_first_boot_shows_language_choice(debug):
    s = debug.wait_for(lambda s: s.choice in ("English", "Français"))
    assert s.title in ("Language", "Langue")


def test_onboarding_english_reaches_home(ready):
    s = ready.screen()
    assert s.title == "feuristic"
    assert s.choice == "Authentication"


def test_onboarding_french(debug):
    onboard(debug, lang="Français")
    s = debug.wait_title("feuristic")
    assert s.choice == "Authentification"
    debug.select("Verrouiller")
    debug.wait_for(
        lambda s: "FEURISTIC" in s.text() and "Appuyez sur un bouton..." in " ".join(s.text().split())
    )
    debug.left()
    enter_pin(debug)
    debug.wait_title("feuristic")


def test_carousel_navigation(ready):
    seen = []
    for _ in range(6):
        seen.append(ready.screen().choice)
        ready.right()
    assert seen[:5] == ["Authentication", "Cryptography", "Backup", "Settings", "Lock"]
    assert seen[5] == "Authentication"  # wraps around


def test_long_press_left_goes_back(ready):
    ready.select("Settings")
    ready.wait_title("Settings")
    ready.hold_left()
    ready.wait_title("feuristic")


@pytest.mark.parametrize("button", ["left", "right", "both"])
def test_lock_and_unlock_with_pin(ready, emu, button):
    ready.select("Lock")
    ready.wait_for(lambda s: "FEURISTIC" in s.text() and "Press any button..." in s.text())
    getattr(ready, button)()
    ready.wait_for(lambda s: s.component == "PinKeyboard")
    enter_pin(ready)
    ready.wait_title("feuristic")


def test_pin_survives_power_cycle(ready, emu):
    emu.restart()
    from harness.debug import Debug
    from harness.emulator import PORT_DEBUG

    d = Debug(emu.port(PORT_DEBUG))
    try:
        d.wait_for(lambda s: "FEURISTIC" in s.text() and "Press any button..." in s.text())
        d.both()
        enter_pin(d, "9999")  # wrong PIN: back to the lockscreen
        d.wait_for(lambda s: s.component != "PinKeyboard", timeout=15)
        d.both()
        enter_pin(d, TEST_PIN)
        d.wait_title("feuristic", timeout=20)
    finally:
        d.close()
