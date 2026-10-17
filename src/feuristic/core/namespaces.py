# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Storage namespace (norcow APP id) allocation — see docs/architecture.md §6.1.

Protected and public namespaces may share the same numeric id (e.g. ``SYS``
and ``SYS_PUBLIC`` are both 0x10): the storage layer adds the 0x80 public
flag, so they are distinct norcow namespaces.

``public=True`` namespaces are passed to :mod:`feuristic.platform.kv` with
``public=True`` (the 0x80 flag is added by the storage layer).
"""

from micropython import const

# upstream namespace kept for retained upstream internals (device id, ...)
APP_UPSTREAM_DEVICE = const(0x01)

SYS = const(0x10)  # protected: master secret, protected settings
SYS_PUBLIC = const(0x10)  # public flag: language, init flag, schema version
OTP = const(0x11)  # protected: OTP account records
OTP_COUNTERS = const(0x11)  # public flag: HOTP redundant counters
FIDO_CREDS = const(0x12)  # protected: discoverable credentials
FIDO_STATE = const(0x13)  # protected: clientPIN state, largeBlob, misc
CARD = const(0x14)  # protected: OpenPGP / PIV / AES records
CARD_COUNTERS = const(0x14)  # public flag: AES nonce reservation, PIN retries

# --- keys inside SYS (protected) ---
SYS_MASTER_SECRET = const(0x00)
SYS_SETTINGS = const(0x01)  # Blob A/B: 0x01, 0x02

# --- keys inside SYS_PUBLIC (public) ---
SYS_PUB_SCHEMA = const(0x00)
SYS_PUB_INITIALIZED = const(0x01)
SYS_PUB_LANGUAGE = const(0x02)
SYS_PUB_AUTOLOCK = const(0x03)
SYS_PUB_USB_SERIAL = const(0x04)

# --- keys inside FIDO_STATE (protected) ---
FIDO_STATE_CLIENTPIN = const(0x00)  # Blob A/B: 0x00, 0x01
FIDO_STATE_LARGEBLOB = const(0x02)  # Blob A/B: 0x02, 0x03

# --- keys inside CARD_COUNTERS (public) ---
CARD_CTR_AES_NONCE_A = const(0x00)
CARD_CTR_AES_NONCE_B = const(0x01)
CARD_CTR_PIN_BASE = const(0x10)  # 0x10.. app PIN retry counters (pairs)

# --- keys inside OTP_COUNTERS (public) ---
# HOTP account with stable counter index i (0..32) uses keys 2*i and 2*i+1
