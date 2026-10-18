#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Every feuristic-owned source file must carry an SPDX licence identifier."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXTS = {".py", ".c", ".h", ".rs", ".sh", ".md", ".toml", ".yml", ".yaml"}
SKIP_PREFIXES = (
    "lib/third_party/",
    "tests/vectors/",
    "tests/c/fqr/vectors/",
    "tests/c/fimg/vectors/",
    "tests/fuzz/corpus/",
    "docs/spec/",
    "patches/",
)
SKIP_FILES = {"LICENSE", "uv.lock", "README.md", "CHANGELOG.md"}


def main() -> int:
    files = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.split()
    missing = []
    for f in files:
        p = Path(f)
        if p.suffix not in EXTS or f.startswith(SKIP_PREFIXES) or p.name in SKIP_FILES:
            continue
        if p.suffix == ".md" and not f.startswith(("docs/", "tests/", "firmware/", "lib/")):
            continue
        try:
            head = (ROOT / f).read_text(errors="replace")[:600]
        except (FileNotFoundError, IsADirectoryError):
            continue
        if "SPDX-License-Identifier" not in head:
            missing.append(f)
    for f in missing:
        print(f"missing SPDX header: {f}")
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
