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
        arguments = [str(path)]
        if env.get("FEURISTIC_EMU_FROZEN") == "1":
            # Frozen builds have no filesystem mounted. Inject only test code;
            # all application imports must resolve from the firmware image.
            arguments = [
                "-c",
                'import sys; sys.path[:] = [".frozen"];\n'
                "class _TestSupport: pass\n"
                "_support = _TestSupport()\n_namespace = {}\n"
                + "exec("
                + repr((UPY / "upytest.py").read_text())
                + ", _namespace)\n"
                + "for _name, _value in _namespace.items():\n"
                "    setattr(_support, _name, _value)\n"
                'sys.modules["upytest"] = _support\n' + path.read_text(),
            ]
            # External test source necessarily adds runtime QSTRs. Keep the
            # upstream no-dynamic-QSTR assertion active in full application
            # tests, where main and every application module are frozen.
            arguments[1] = arguments[1].replace(
                'sys.modules["upytest"] = _support\n',
                'sys.modules["upytest"] = _support\n'
                "from trezor import utils\nutils.check_heap_fragmentation = lambda: None\n",
            )
        # the emulator executes the file with core/src as the working directory
        r = subprocess.run(
            [str(binary_path()), "-O0", "-X", "heapsize=20M", *arguments],
            cwd=CORE / "src",
            env=env,
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
    out = r.stdout + r.stderr
    assert "UPYTEST OK" in out, out[-4000:]
