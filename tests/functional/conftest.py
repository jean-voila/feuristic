# SPDX-License-Identifier: GPL-3.0-only
"""Functional tests against the feuristic emulator.

Build the emulator first:  make emu   (or tools/env.sh + xtask build firmware
--emulator -m t3b1 --debug-link --disable-animation).
"""

import itertools
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(__file__))

from harness.debug import Debug  # noqa: E402
from harness.emulator import PORT_DEBUG, Emulator, binary_path  # noqa: E402

_ports = itertools.count(int(os.environ.get("FEURISTIC_EMU_BASE_PORT", "22000")), 16)

TEST_PIN = "1234"


def pytest_collection_modifyitems(config, items):
    if not binary_path().exists():
        skip = pytest.mark.skip(reason=f"emulator binary not built: {binary_path()}")
        for item in items:
            item.add_marker(skip)


@pytest.fixture
def emu():
    e = Emulator(base_port=next(_ports))
    e.start()
    yield e
    e.cleanup()


@pytest.fixture
def debug(emu):
    d = Debug(emu.port(PORT_DEBUG))
    yield d
    d.close()


def onboard(debug, lang="English", pin=TEST_PIN):
    """Walk the first-boot flow: language, third-party notice, PIN twice."""
    debug.wait_for(lambda s: s.choice in ("English", "Français"))
    debug.select(lang)
    debug.wait_for(lambda s: "Third-party" in s.text() or "Firmware tiers" in s.text())
    debug.both()
    debug.wait_for(lambda s: "PIN" in s.text())
    debug.both()  # PIN intro
    enter_pin(debug, pin)
    enter_pin(debug, pin)


def enter_pin(debug, pin=TEST_PIN):
    """Wait for an empty PIN keyboard and submit ``pin``."""
    debug.wait_for(lambda s: s.component == "PinKeyboard" and s.data.get("pin") == "")
    debug.input(pin)
    time.sleep(0.8)  # let the next layout (possibly another PIN keyboard) come up


@pytest.fixture
def ready(emu, debug):
    """An initialised, unlocked device showing the home menu."""
    onboard(debug)
    debug.wait_title("feuristic")
    return debug
