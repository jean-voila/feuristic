# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Memory evidence must execute its checks even in optimized frozen builds."""

import ast
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("memory_probe_source", ROOT / "tools/memory_probe_source.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


@pytest.mark.parametrize("optimize", [0, 1, 2])
def test_side_effects_and_lazy_failure_message_survive_optimization(optimize):
    source = MODULE.checked_script(
        'events=[]\nassert events.append("unlock") is None, events.append("unused")\n'
        'try:\n assert events.append("write") is not None, "write failed"\n'
        "except AssertionError as error:\n message=str(error)\n"
    )
    scope = {}
    exec(compile(source, "probe", "exec", optimize=optimize), scope)
    assert scope["events"] == ["unlock", "write"]
    assert scope["message"] == "write failed"
    assert not any(isinstance(node, ast.Assert) for node in ast.walk(ast.parse(source)))


@pytest.mark.parametrize("filename", ["probe_normal_memory32.py", "probe_restore_memory.py"])
def test_production_probe_source_contains_no_optimizable_checks(filename):
    tree = ast.parse((ROOT / "tools" / filename).read_text())
    script = next(
        ast.literal_eval(node.value)
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "SCRIPT" for target in node.targets)
    )
    assert "assert " in script
    checked = MODULE.checked_script(script)
    assert not any(isinstance(node, ast.Assert) for node in ast.walk(ast.parse(checked)))
    assert "config.unlock" in checked
