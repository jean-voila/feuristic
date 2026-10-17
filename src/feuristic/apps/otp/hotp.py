# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""HOTP — HMAC-based one-time password (RFC 4226).

* RFC 4226 §5.3: ``HOTP(K, C) = Truncate(HMAC-SHA-1(K, C))`` where ``C`` is
  the 8-byte big-endian moving factor;
* RFC 4226 §5.4: dynamic truncation (offset = low nibble of the last MAC
  byte, 31-bit big-endian value at that offset), then ``mod 10^Digit``;
* RFC 6238 §1.2 / §4: the same construction with HMAC-SHA-256 and
  HMAC-SHA-512 (used by TOTP and by ``algorithm=`` in otpauth URIs).

Codes are returned as zero-padded decimal strings of 6, 7 or 8 digits.
"""

from micropython import const

from ...core.errors import InvalidInput
from ...platform import crypto

SHA1 = "SHA1"
SHA256 = "SHA256"
SHA512 = "SHA512"
ALGORITHMS = (SHA1, SHA256, SHA512)
DIGITS = (6, 7, 8)

MAX_SECRET_LEN = const(64)  # docs/architecture.md §6.3
MAX_COUNTER = 0xFFFFFFFFFFFFFFFF

_MAC_LEN = {SHA1: 20, SHA256: 32, SHA512: 64}
_HMAC_NAME = {SHA1: "sha1", SHA256: "sha256", SHA512: "sha512"}
_MODULUS = {6: 1_000_000, 7: 10_000_000, 8: 100_000_000}


def check_params(secret, digits: int, algorithm: str) -> None:
    """Validate the common HOTP/TOTP parameters (raises :class:`InvalidInput`)."""
    if not isinstance(secret, (bytes, bytearray)) or not 1 <= len(secret) <= MAX_SECRET_LEN:
        raise InvalidInput("secret length")
    if isinstance(digits, bool) or digits not in DIGITS:
        raise InvalidInput("digits")
    if algorithm not in ALGORITHMS:
        raise InvalidInput("algorithm")


def dynamic_truncate(mac: bytes) -> int:
    """RFC 4226 §5.4 ``DT``: 31-bit value selected by the low nibble of the last byte."""
    if len(mac) < 20:
        raise InvalidInput("MAC too short")
    offset = mac[-1] & 0x0F
    return ((mac[offset] & 0x7F) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3]


def format_code(value: int, digits: int) -> str:
    """Zero-pad ``value mod 10^digits`` to ``digits`` characters."""
    s = str(value % _MODULUS[digits])
    return "0" * (digits - len(s)) + s


def hotp(secret, counter: int, digits: int = 6, algorithm: str = SHA1) -> str:
    """Compute the HOTP value for ``counter`` (RFC 4226 §5.3)."""
    check_params(secret, digits, algorithm)
    if isinstance(counter, bool) or not isinstance(counter, int) or not 0 <= counter <= MAX_COUNTER:
        raise InvalidInput("counter")
    mac = crypto.hmac(_HMAC_NAME[algorithm], bytes(secret), counter.to_bytes(8, "big"))
    if len(mac) != _MAC_LEN[algorithm]:  # pragma: no cover - backend sanity check
        raise InvalidInput("HMAC length")
    return format_code(dynamic_truncate(mac), digits)
