# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Debug logging. Compiled out of release builds (``__debug__`` is False with pyopt)."""

from . import _backend

if _backend.FIRMWARE:
    from trezor import log as _log

    def debug(mod: str, msg: str, *args) -> None:
        if __debug__:
            _log.debug(mod, msg, *args)

    def warning(mod: str, msg: str, *args) -> None:
        if __debug__:
            _log.warning(mod, msg, *args)

else:
    import logging as _logging

    def debug(mod: str, msg: str, *args) -> None:
        _logging.getLogger(mod).debug(msg, *args)

    def warning(mod: str, msg: str, *args) -> None:
        _logging.getLogger(mod).warning(msg, *args)
