# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Backend detection (firmware vs. host)."""

try:
    import trezor  # noqa: F401  (only importable on the device / emulator)

    FIRMWARE = True
except ImportError:
    FIRMWARE = False
