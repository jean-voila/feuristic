# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Execution context handed to the FIDO2 protocol handlers by the firmware glue.

* :class:`Context` — device master secret ``ms`` (32 bytes, from ``SYS``),
  the :class:`~feuristic.core.interaction.Interaction` used for user
  presence, and the tick value at power-up (authenticatorReset is only
  allowed during the first 10 s, CTAP 2.1 §6.6).
* :class:`Channel` — per-request hooks of the transport: ``set_status``
  selects the CTAPHID keepalive status (CTAP 2.1 §11.2.9.1.4) and
  ``cancelled`` becomes true when the host sent CTAPHID_CANCEL. The CTAPHID
  :class:`~.ctaphid.Transaction` implements this interface;
  :data:`NULL_CHANNEL` is used for local calls.
"""

from micropython import const

from ...platform import time as ptime

STATUS_PROCESSING = const(1)
STATUS_UPNEEDED = const(2)

FIRMWARE_VERSION = const(0x000100)  # 0.1.0, reported in authenticatorGetInfo


class Context:
    def __init__(self, ms: bytes, ui, power_up_ms=None, firmware_version: int = FIRMWARE_VERSION) -> None:
        if not isinstance(ms, (bytes, bytearray)) or len(ms) != 32:
            raise ValueError("master secret must be 32 bytes")
        self.ms = bytes(ms)
        self.ui = ui
        self.power_up_ms = ptime.ticks_ms() if power_up_ms is None else power_up_ms
        self.firmware_version = firmware_version

    @staticmethod
    def now() -> int:
        return ptime.ticks_ms()

    def ms_since_power_up(self) -> int:
        return ptime.ticks_diff(ptime.ticks_ms(), self.power_up_ms)


class Channel:
    """Transport hooks of one request (interface; see ctaphid.Transaction)."""

    cancelled = False

    def set_status(self, status: int) -> None:
        return


NULL_CHANNEL = Channel()
