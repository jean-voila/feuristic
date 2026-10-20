# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Every absolute module name and parent attribute must already exist in ROM."""

import ast
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("generate_frozen_qstr", ROOT / "tools/generate_frozen_qstr.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_all_import_names_are_frozen_without_eager_application_imports():
    source = MODULE.DESTINATION.read_text()
    assert source == MODULE.render()
    tree = ast.parse(source)
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef))
    absolute = {alias.name for node in function.body if isinstance(node, ast.Import) for alias in node.names}
    leaves = {
        (node.module, alias.name)
        for node in function.body
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    }
    expected = set(MODULE.modules())
    assert absolute == expected
    assert leaves == {tuple(name.rsplit(".", 1)) for name in expected if "." in name}
    characters = {
        node.value.value
        for node in function.body
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
    }
    assert characters == {chr(code) for code in range(32, 127)}
    assert not any(isinstance(node, (ast.Import, ast.ImportFrom, ast.Call)) for node in tree.body)
