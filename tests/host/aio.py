# SPDX-License-Identifier: GPL-3.0-only
"""Minimal coroutine driver for shared async code (no asyncio dependency)."""


def run(coro):
    """Drive ``coro`` to completion. Shared code only awaits coroutines that
    complete synchronously on the host, so any yielded value is a bug."""
    try:
        while True:
            yielded = coro.send(None)
            raise AssertionError(f"shared coroutine yielded unexpectedly: {yielded!r}")
    except StopIteration as e:
        return e.value
