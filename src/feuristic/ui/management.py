# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Shared, bounded input and error handling for on-device management."""

from ..core.errors import (
    FeuristicError,
    InvalidInput,
    NotFound,
    PinBlocked,
    PinInvalid,
    PolicyDenied,
    StorageFull,
    UserCancelled,
    UserTimeout,
)
from ..core.i18n import t
from ..platform import crypto
from . import screens

TIMEOUT_MS = 60_000


async def info(title, fields) -> None:
    await screens.confirm_fields(
        title,
        [(t(k), str(v), False) for k, v in fields],
        verb=t("ui.ok"),
        close_others=False,
    )


async def done(key="manage.changed") -> None:
    await screens.show_info(t(key), timeout_ms=1500, close_others=False)


async def confirm(title, text="", hold=True) -> bool:
    return await screens.confirm(
        t(title),
        t(text) if text else "",
        hold=hold,
        timeout_ms=TIMEOUT_MS,
        close_others=False,
    )


async def new_pin(title, minimum, maximum=50):
    """Return a mutable digit PIN, or None on any cancellation."""
    while True:
        first = await screens.request_pin(t(title))
        if first is None:
            return None
        if not minimum <= len(first) <= maximum or not all("0" <= c <= "9" for c in first):
            await screens.show_error(t("manage.pin_length", minimum, maximum))
            continue
        second = await screens.request_pin(t("manage.pin_repeat"))
        if second is None:
            return None
        if first != second:
            await screens.show_error(t("pin.mismatch"))
            continue
        return bytearray(first.encode())


async def run(action):
    """Keep a cancelled/failed management action inside its caller's menu.

    Typed errors are translated without displaying exception messages or secrets.
    Unexpected exceptions remain visible to the firmware supervisor in debug logs.
    """
    try:
        return await action
    except (UserCancelled, UserTimeout):
        return None
    except PinInvalid as e:
        key, args = "fido2.pin.wrong", (e.retries,)
    except PinBlocked:
        key, args = "fido2.pin.blocked", ()
    except StorageFull:
        key, args = "ui.storage_full", ()
    except InvalidInput:
        key, args = "manage.invalid", ()
    except NotFound:
        key, args = "manage.missing", ()
    except PolicyDenied:
        key, args = "manage.denied", ()
    except MemoryError:
        key, args = "manage.memory", ()
    except (FeuristicError, crypto.CryptoError):
        key, args = "ui.error", ()
    await screens.show_error(t(key, *args))
    return None
