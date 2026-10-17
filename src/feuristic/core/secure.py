# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Helpers for handling secret material."""


def wipe(buf) -> None:
    """Overwrite a mutable buffer (``bytearray`` / ``memoryview``) with zeros."""
    if buf is None:
        return
    for i in range(len(buf)):
        buf[i] = 0
