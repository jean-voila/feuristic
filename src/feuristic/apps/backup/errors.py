# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Typed errors of the QR backup subsystem (spec §8).

Every error derives from :mod:`feuristic.core.errors` so protocol and UI
layers can handle them generically. Messages are short English diagnostics
for logs; the UI maps error *classes* to i18n keys (``ERROR_KEYS`` in
:mod:`feuristic.apps.backup.strings`). No message ever contains secret
material (passphrase, key, plaintext).
"""

from ...core.errors import FeuristicError, InvalidInput


class BackupFormatError(InvalidInput):
    """The envelope header is malformed (checked *before* authentication)."""


class UnsupportedVersion(BackupFormatError):
    """Unknown envelope magic/version (e.g. a backup from a newer firmware)."""


class UnsupportedParameters(BackupFormatError):
    """KDF/AEAD algorithm or iteration count not allowed by format v1."""


class AuthenticationFailed(FeuristicError):
    """The AES-GCM tag did not verify: wrong passphrase **or** altered backup.

    The two cases are cryptographically indistinguishable; the UI says
    "wrong passphrase or damaged backup". Nothing was decrypted or written.
    """


class PlaintextError(InvalidInput):
    """The authenticated plaintext violates the v1 schema (or is not
    canonical CBOR). Only possible with a buggy or malicious *encoder* that
    knew the passphrase."""


class WeakPassphrase(InvalidInput):
    """The passphrase violates the policy (≥ 12 printable ASCII characters)."""


class UnsupportedItem(InvalidInput):
    """An item's ``type`` has no registered provider on this firmware."""


class FrameError(InvalidInput):
    """Base class of QR frame transport errors."""


class FrameFormatError(FrameError):
    """Not a valid ``FB1:`` frame (prefix, Base45, length, index/total range)."""


class FrameChecksumError(FrameError):
    """The frame CRC-32 does not match (damaged image / misread QR)."""


class FrameIdMismatch(FrameError):
    """The frame belongs to another backup than the one being reassembled."""


class FrameTotalMismatch(FrameError):
    """The frame announces a different frame count for the same backup id."""


class FrameConflict(FrameError):
    """Same backup id and index as an already received frame, different content."""


class FrameLimitExceeded(FrameError):
    """Too many frames, too many bytes or too many backups in one session."""


class FrameIncomplete(FrameError):
    """Reassembly requested while frames are missing. ``missing`` lists the
    1-based indices of the missing frames."""

    def __init__(self, missing) -> None:
        super().__init__("frames missing")
        self.missing = list(missing)
