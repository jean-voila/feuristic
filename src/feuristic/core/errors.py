# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Typed errors shared by all feuristic applications.

Messages never contain secret material. Protocol layers map these to their
wire status codes (CTAP2 status, ISO 7816 SW, ...).
"""


class FeuristicError(Exception):
    """Base class of every feuristic error."""


class InvalidInput(FeuristicError):
    """Malformed, out-of-range or oversized input from an untrusted source."""


class NotFound(FeuristicError):
    """The requested object does not exist."""


class StorageFull(FeuristicError):
    """Not enough persistent storage (or the quota reserve would be violated)."""


class StorageCorrupted(FeuristicError):
    """A persistent record failed validation."""


class UserCancelled(FeuristicError):
    """The user refused or cancelled the operation on the device."""


class UserTimeout(FeuristicError):
    """The user did not answer before the timeout."""


class PolicyDenied(FeuristicError):
    """The security policy forbids the operation in the current state."""


class Locked(FeuristicError):
    """The device storage is locked (device PIN required)."""


class PinBlocked(FeuristicError):
    """The PIN retry counter is exhausted."""


class PinInvalid(FeuristicError):
    """Wrong PIN. ``retries`` is the number of remaining attempts."""

    def __init__(self, retries: int) -> None:
        super().__init__("wrong PIN")
        self.retries = retries
