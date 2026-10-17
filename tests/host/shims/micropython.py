# SPDX-License-Identifier: GPL-3.0-only
"""CPython shim for the MicroPython ``micropython`` module."""


def const(x):
    return x


def mem_info(*_args):  # pragma: no cover
    pass
