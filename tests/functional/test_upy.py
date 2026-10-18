# SPDX-License-Identifier: GPL-3.0-only
"""Run the MicroPython unit tests (tests/upy) inside the emulator binary."""

import os
import subprocess
import tempfile
from pathlib import Path

import pytest
from harness.emulator import CORE, binary_path

UPY = Path(__file__).resolve().parent.parent / "upy"
TESTS = sorted(p for p in UPY.glob("test_*.py"))


@pytest.mark.parametrize("path", TESTS, ids=[p.stem for p in TESTS])
def test_upy(path):
    with tempfile.TemporaryDirectory() as prof:
        env = dict(os.environ, TREZOR_PROFILE_DIR=prof, SDL_VIDEODRIVER="dummy", MICROPYPATH=f":{UPY}:.")
        # the emulator executes the file with core/src as the working directory
        r = subprocess.run(
            [str(binary_path()), "-O0", "-X", "heapsize=20M", str(path)],
            cwd=CORE / "src",
            env=env,
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
    out = r.stdout + r.stderr
    assert "UPYTEST OK" in out, out[-4000:]
