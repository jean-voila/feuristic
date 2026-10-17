#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Check that src/feuristic is valid for the device MicroPython.

1. Static checks (AST): forbidden stdlib imports and constructs listed in
   docs/developer/micropython-compat.md.
2. Compilation with upstream's ``mpy-cross`` (the exact compiler used to
   freeze the firmware), if it has been built (``make emu`` builds it).

Exit status is non-zero on any finding. Host-only modules are skipped.
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "feuristic"
MPY_CROSS = ROOT / "upstream/trezor-firmware/core/build-xtask/mpy-cross/mpy-cross"

HOST_ONLY = {"platform/_host_crypto.py", "platform/testing.py"}
FORBIDDEN_MODULES = {
    "struct", "collections", "math", "re", "json", "binascii", "hashlib", "os", "io", "time",
    "random", "dataclasses", "enum", "abc", "functools", "itertools", "contextlib", "typing_extensions",
}
# modules that only exist on the device (allowed)
DEVICE_MODULES = {"micropython", "trezor", "trezorui_api", "trezorio", "trezorcrypto", "trezortranslate",
                  "trezorconfig", "trezorutils", "utime", "feuristic_native", "storage", "apps", "typing"}


def static_check(path: Path, rel: str) -> list[str]:
    errors = []
    tree = ast.parse(path.read_text(), str(path))
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""]
            if isinstance(node, ast.ImportFrom) and node.level:
                continue
            for name in names:
                top = name.split(".")[0]
                if top in FORBIDDEN_MODULES:
                    errors.append(f"{rel}:{node.lineno}: forbidden import '{name}'")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "pow" and len(node.args) == 3:
                errors.append(f"{rel}:{node.lineno}: three-argument pow()")
            if node.func.id == "frozenset":
                errors.append(f"{rel}:{node.lineno}: frozenset")
            if node.func.id == "const" and node.args:
                if not _is_const_expr(node.args[0]):
                    errors.append(f"{rel}:{node.lineno}: const() argument must be a literal expression")
        elif isinstance(node, ast.Attribute) and node.attr in ("bit_length", "splitlines", "center"):
            errors.append(f"{rel}:{node.lineno}: unsupported method '.{node.attr}'")
        elif isinstance(node, ast.keyword) and node.arg == "signed":
            errors.append(f"{rel}:{getattr(node, 'lineno', 0)}: int.to/from_bytes(signed=) unsupported")
    return errors


def _is_const_expr(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return isinstance(node.value, (int, bool))
    if isinstance(node, ast.UnaryOp):
        return _is_const_expr(node.operand)
    if isinstance(node, ast.BinOp):
        return _is_const_expr(node.left) and _is_const_expr(node.right)
    # MicroPython folds names of const() values defined earlier in the same
    # module; attributes of other modules are not constants (mpy-cross also
    # rejects them, this check just gives a clearer message without mpy-cross)
    return isinstance(node, ast.Name)


def mpy_compile(path: Path, rel: str, tmp: str) -> list[str]:
    out = os.path.join(tmp, "out.mpy")
    r = subprocess.run(
        [str(MPY_CROSS), "-o", out, "-s", rel, str(path)], capture_output=True, text=True, check=False
    )
    if r.returncode != 0:
        msg = (r.stderr or r.stdout).strip().splitlines()
        return [f"{rel}: mpy-cross: {' | '.join(msg[-2:])}"]
    return []


def main() -> int:
    files = sorted(SRC.rglob("*.py"))
    errors: list[str] = []
    have_mpy = MPY_CROSS.exists()
    with tempfile.TemporaryDirectory() as tmp:
        for f in files:
            rel = f.relative_to(SRC).as_posix()
            if rel in HOST_ONLY:
                continue
            errors += static_check(f, rel)
            if have_mpy:
                errors += mpy_compile(f, rel, tmp)
    for e in errors:
        print(e)
    if not have_mpy:
        print(f"note: {MPY_CROSS} not built, only static checks were run", file=sys.stderr)
    print(f"checked {len(files)} files, {len(errors)} finding(s)", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
