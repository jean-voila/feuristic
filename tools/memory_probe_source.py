# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Keep diagnostic checks executable when firmware freezes Python with -O3."""

import ast


class _Checks(ast.NodeTransformer):
    def visit_Assert(self, node):
        self.generic_visit(node)
        return ast.copy_location(
            ast.If(
                test=ast.UnaryOp(op=ast.Not(), operand=node.test),
                body=[
                    ast.Raise(
                        exc=ast.Call(
                            func=ast.Name(id="AssertionError", ctx=ast.Load()),
                            args=[node.msg or ast.Constant(value="memory probe check failed")],
                            keywords=[],
                        ),
                        cause=None,
                    )
                ],
                orelse=[],
            ),
            node,
        )


def checked_script(source: str) -> str:
    """Preserve check ordering, lazy messages and side effects at every opt level."""
    tree = ast.fix_missing_locations(_Checks().visit(ast.parse(source)))
    return ast.unparse(tree) + "\n"
