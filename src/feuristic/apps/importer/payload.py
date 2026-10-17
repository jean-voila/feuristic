# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Classification of a decoded QR payload (spec §3.3, §10.4).

The firmware glue decodes exactly one QR code per imported image
(``feuristic_import``) and hands its raw payload bytes to :func:`classify`.
The QR content must be either

* an ``otpauth://`` key URI (scheme matched case-insensitively, RFC 3986
  §3.1) → OTP import path (parsed by ``feuristic.apps.otp.uri``);
* a versioned feuristic backup frame ``FB1:<Base45>`` → backup path
  (parsed by :mod:`feuristic.apps.backup.frames`);

anything else is reported as unsupported QR content. Classification never
interprets the content beyond these strict, bounded checks; in particular
nothing in a payload is ever treated as a command.
"""

from micropython import const

from ...core import base45
from ..backup import frames

KIND_UNSUPPORTED = const(0)
KIND_OTPAUTH = const(1)
KIND_BACKUP_FRAME = const(2)
#: ``FB<n>:`` with n ≠ 1: a backup frame from another format version
KIND_BACKUP_UNSUPPORTED_VERSION = const(3)
KIND_TOO_LARGE = const(4)

#: largest QR payload (version 40-L, byte mode)
MAX_PAYLOAD_LEN = const(2953)
#: largest accepted otpauth URI (OTP record caps make longer URIs useless)
MAX_OTPAUTH_LEN = const(1024)

_OTPAUTH = b"otpauth://"

# reasons for KIND_UNSUPPORTED (i18n keys)
REASON_UNKNOWN = "importer.err.unsupported"
REASON_EMPTY = "importer.err.empty"
REASON_NOT_PRINTABLE = "importer.err.not_printable"
REASON_OTP_TOO_LONG = "importer.err.otp_too_long"
REASON_FRAME_CHARS = "importer.err.frame_chars"
REASON_FRAME_TOO_LONG = "importer.err.frame_too_long"
REASON_TOO_LARGE = "importer.err.too_large"
REASON_BACKUP_VERSION = "importer.err.backup_version"


class Payload:
    """Result of :func:`classify`. ``data`` is the payload (bytes) for the
    accepted kinds; ``reason`` an i18n key explaining a rejection."""

    def __init__(self, kind: int, data=None, reason=None) -> None:
        self.kind = kind
        self.data = data
        self.reason = reason

    def __repr__(self) -> str:
        return f"Payload({self.kind}, reason={self.reason!r})"


def _lower_ascii(b: int) -> int:
    return b + 32 if 0x41 <= b <= 0x5A else b


def _starts_with_ci(data: bytes, prefix: bytes) -> bool:
    if len(data) < len(prefix):
        return False
    return all(_lower_ascii(data[i]) == prefix[i] for i in range(len(prefix)))


def is_printable_ascii(data) -> bool:
    """True if every byte is in ``0x20..0x7E``."""
    return all(0x20 <= b <= 0x7E for b in data)


def _backup_version_prefix(data: bytes):
    """Return the length of an ``FB<digits>:`` prefix (1–3 digits) or 0."""
    if len(data) < 4 or data[0] != 0x46 or data[1] != 0x42:  # "FB"
        return 0
    i = 2
    while i < len(data) and i < 5 and 0x30 <= data[i] <= 0x39:
        i += 1
    if i == 2 or i >= len(data) or data[i] != 0x3A:  # ":"
        return 0
    return i + 1


def classify(data) -> Payload:
    """Classify a raw QR payload. Never raises for content errors."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("payload must be bytes")
    n = len(data)
    if n == 0:
        return Payload(KIND_UNSUPPORTED, reason=REASON_EMPTY)
    if n > MAX_PAYLOAD_LEN:
        return Payload(KIND_TOO_LARGE, reason=REASON_TOO_LARGE)
    data = bytes(data)

    if _starts_with_ci(data, _OTPAUTH):
        if n > MAX_OTPAUTH_LEN:
            return Payload(KIND_UNSUPPORTED, reason=REASON_OTP_TOO_LONG)
        if not is_printable_ascii(data):
            return Payload(KIND_UNSUPPORTED, reason=REASON_NOT_PRINTABLE)
        return Payload(KIND_OTPAUTH, data)

    plen = _backup_version_prefix(data)
    if plen:
        if data[:plen] != frames.PREFIX.encode():
            return Payload(KIND_BACKUP_UNSUPPORTED_VERSION, reason=REASON_BACKUP_VERSION)
        if n > frames.MAX_FRAME_TEXT:
            return Payload(KIND_UNSUPPORTED, reason=REASON_FRAME_TOO_LONG)
        if not base45.is_alphabet(data[plen:]):
            return Payload(KIND_UNSUPPORTED, reason=REASON_FRAME_CHARS)
        return Payload(KIND_BACKUP_FRAME, data)

    return Payload(KIND_UNSUPPORTED, reason=REASON_UNKNOWN)
