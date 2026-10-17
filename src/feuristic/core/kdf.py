# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Domain-separated key derivation from the device master secret.

``derive(ms, label, length)`` = HKDF-SHA256(IKM=ms, salt=SALT, info=label || context).

Every label used anywhere in feuristic **must** be declared in
:data:`LABELS`; :func:`derive` rejects unknown labels so that two
applications can never accidentally share a key.
"""

from ..platform import crypto
from .errors import InvalidInput

SALT = b"feuristic/v1"

# label -> short description (documentation and uniqueness check)
LABELS = {
    b"fido2/cred-wrap": "AES-256-GCM key wrapping non-discoverable credential IDs",
    b"fido2/largeblob-key": "per-credential largeBlobKey derivation",
    b"fido2/cred-random": "hmac-secret CredRandom derivation (with/without UV)",
    b"fido2/u2f-wrap": "AES-256-GCM key wrapping U2F key handles",
    b"card/aes-nonce-prefix": "per-device prefix mixed into AES-GCM nonces",
    b"card/serial": "OpenPGP/PIV card serial number derivation",
    b"backup/id": "backup identifier derivation",
    b"device/usb-serial": "USB serial number string",
}


def derive(ms: bytes, label: bytes, length: int = 32, context: bytes = b"") -> bytes:
    """Derive ``length`` bytes for ``label`` (+ optional public ``context``)."""
    if label not in LABELS:
        raise InvalidInput("unknown KDF label")
    if len(ms) != 32:
        raise InvalidInput("master secret must be 32 bytes")
    return crypto.hkdf_sha256(ms, SALT, label + b"\x00" + bytes(context), length)
