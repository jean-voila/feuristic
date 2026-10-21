#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Build the editable Sketch document and web exports with the installed Sketch app."""

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKETCH = Path("/Applications/Sketch.app/Contents/MacOS/sketchtool")

if __name__ == "__main__":
    script = f"require({json.dumps(str(ROOT / 'tools/artwork.js'))})({json.dumps(str(ROOT))})"
    result = subprocess.run(
        [str(SKETCH), "run-script", script, "--without-activating"],
        capture_output=True,
        text=True,
        check=True,
    )
    if "Saved editable Feuristic artwork." not in result.stdout:
        raise RuntimeError(result.stdout + result.stderr)
    print(result.stdout.strip())
