# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""CTAP status codes (CTAP 2.1 §8.2 "Status codes") and the protocol error type.

Every CTAP2 handler signals failures by raising :class:`CtapError` with one
of the constants below; the dispatcher turns it into the one-byte status of
the CTAPHID_CBOR response. CTAPHID transport errors (CTAP 2.1 §11.2.9.1.6)
reuse the CTAP1 values (``ERR_INVALID_CMD`` = ``CTAP1_ERR_INVALID_COMMAND``...).
"""

from micropython import const

CTAP2_OK = const(0x00)
CTAP1_ERR_INVALID_COMMAND = const(0x01)
CTAP1_ERR_INVALID_PARAMETER = const(0x02)
CTAP1_ERR_INVALID_LENGTH = const(0x03)
CTAP1_ERR_INVALID_SEQ = const(0x04)
CTAP1_ERR_TIMEOUT = const(0x05)
CTAP1_ERR_CHANNEL_BUSY = const(0x06)
CTAP1_ERR_LOCK_REQUIRED = const(0x0A)
CTAP1_ERR_INVALID_CHANNEL = const(0x0B)
CTAP2_ERR_CBOR_UNEXPECTED_TYPE = const(0x11)
CTAP2_ERR_INVALID_CBOR = const(0x12)
CTAP2_ERR_MISSING_PARAMETER = const(0x14)
CTAP2_ERR_LIMIT_EXCEEDED = const(0x15)
CTAP2_ERR_LARGE_BLOB_STORAGE_FULL = const(0x18)
CTAP2_ERR_CREDENTIAL_EXCLUDED = const(0x19)
CTAP2_ERR_PROCESSING = const(0x21)
CTAP2_ERR_INVALID_CREDENTIAL = const(0x22)
CTAP2_ERR_UNSUPPORTED_ALGORITHM = const(0x26)
CTAP2_ERR_OPERATION_DENIED = const(0x27)
CTAP2_ERR_KEY_STORE_FULL = const(0x28)
CTAP2_ERR_UNSUPPORTED_OPTION = const(0x2B)
CTAP2_ERR_INVALID_OPTION = const(0x2C)
CTAP2_ERR_KEEPALIVE_CANCEL = const(0x2D)
CTAP2_ERR_NO_CREDENTIALS = const(0x2E)
CTAP2_ERR_USER_ACTION_TIMEOUT = const(0x2F)
CTAP2_ERR_NOT_ALLOWED = const(0x30)
CTAP2_ERR_PIN_INVALID = const(0x31)
CTAP2_ERR_PIN_BLOCKED = const(0x32)
CTAP2_ERR_PIN_AUTH_INVALID = const(0x33)
CTAP2_ERR_PIN_AUTH_BLOCKED = const(0x34)
CTAP2_ERR_PIN_NOT_SET = const(0x35)
CTAP2_ERR_PUAT_REQUIRED = const(0x36)
CTAP2_ERR_PIN_POLICY_VIOLATION = const(0x37)
CTAP2_ERR_REQUEST_TOO_LARGE = const(0x39)
CTAP2_ERR_ACTION_TIMEOUT = const(0x3A)
CTAP2_ERR_UP_REQUIRED = const(0x3B)
CTAP2_ERR_INTEGRITY_FAILURE = const(0x3D)
CTAP2_ERR_INVALID_SUBCOMMAND = const(0x3E)
CTAP2_ERR_UNAUTHORIZED_PERMISSION = const(0x40)
CTAP1_ERR_OTHER = const(0x7F)


class CtapError(Exception):
    """A CTAP2 request failed with status ``code`` (never carries secrets)."""

    def __init__(self, code: int) -> None:
        super().__init__(code)
        self.code = code

    def __repr__(self) -> str:
        return f"CtapError(0x{self.code:02x})"
