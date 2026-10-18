# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""PIV identifiers (NIST SP 800-73-4 Part 1 §3, Part 2 §3; SP 800-78-4 Table 6-2)."""

from micropython import const

# --- application identifier (SP 800-73-4 Part 1 §2.2) -----------------------
AID = bytes.fromhex("A000000308000010000100")
PIX = bytes.fromhex("000010000100")
RID_NIST = bytes.fromhex("A000000308")
LABEL = b"feuristic PIV"

# --- key references (SP 800-73-4 Part 1 Table 4b) ---------------------------
SLOT_AUTH = const(0x9A)  # PIV Authentication
SLOT_MGMT = const(0x9B)  # PIV Card Application Administration Key
SLOT_SIGN = const(0x9C)  # Digital Signature
SLOT_KEYMGMT = const(0x9D)  # Key Management
SLOT_CARDAUTH = const(0x9E)  # Card Authentication
KEY_SLOTS = (SLOT_AUTH, SLOT_SIGN, SLOT_KEYMGMT, SLOT_CARDAUTH)

REF_PIN = const(0x80)  # PIV Card Application PIN
REF_PUK = const(0x81)  # PIN Unblocking Key

# --- algorithm identifiers (SP 800-78-4 Table 6-2) --------------------------
ALG_3DES = const(0x03)
ALG_RSA2048 = const(0x07)
ALG_AES128 = const(0x08)
ALG_AES192 = const(0x0A)
ALG_AES256 = const(0x0C)
ALG_P256 = const(0x11)
ASYM_ALGS = (ALG_P256, ALG_RSA2048)
# administration key algorithm -> key length
MGMT_ALGS = {ALG_3DES: 24, ALG_AES128: 16, ALG_AES192: 24, ALG_AES256: 32}
# advertised in the APT (SELECT response) in this order
APT_ALGS = (ALG_3DES, ALG_AES128, ALG_AES192, ALG_AES256, ALG_RSA2048, ALG_P256)

RSA_BITS = const(2048)
RSA_BYTES = const(256)
RSA_E = 65537

# --- PIN / touch policies (YubiKey PIV extension values) --------------------
PIN_POLICY_DEFAULT = const(0)
PIN_POLICY_NEVER = const(1)
PIN_POLICY_ONCE = const(2)
PIN_POLICY_ALWAYS = const(3)
TOUCH_POLICY_DEFAULT = const(0)
TOUCH_POLICY_NEVER = const(1)
TOUCH_POLICY_ALWAYS = const(2)
TOUCH_POLICY_CACHED = const(3)

# product policy per slot (task / spec §6.3): 9A once, 9C always, 9D once, 9E never
DEFAULT_PIN_POLICY = {
    SLOT_AUTH: PIN_POLICY_ONCE,
    SLOT_SIGN: PIN_POLICY_ALWAYS,
    SLOT_KEYMGMT: PIN_POLICY_ONCE,
    SLOT_CARDAUTH: PIN_POLICY_NEVER,
}

# key origin (YubiKey metadata tag 03)
ORIGIN_GENERATED = const(1)
ORIGIN_IMPORTED = const(2)  # restored from a feuristic backup

# --- data objects (SP 800-73-4 Part 1 Table 3) ------------------------------
OBJ_CERT_9E = const(0x5FC101)
OBJ_CHUID = const(0x5FC102)
OBJ_CERT_9A = const(0x5FC105)
OBJ_SECURITY = const(0x5FC106)
OBJ_CCC = const(0x5FC107)
OBJ_PRINTED = const(0x5FC109)
OBJ_CERT_9C = const(0x5FC10A)
OBJ_CERT_9D = const(0x5FC10B)
OBJ_KEY_HISTORY = const(0x5FC10C)
OBJ_DISCOVERY = const(0x7E)

CERT_OBJECTS = {
    OBJ_CERT_9A: SLOT_AUTH,
    OBJ_CERT_9C: SLOT_SIGN,
    OBJ_CERT_9D: SLOT_KEYMGMT,
    OBJ_CERT_9E: SLOT_CARDAUTH,
}
SLOT_CERT_OBJECT = {v: k for k, v in CERT_OBJECTS.items()}

# writable non-certificate objects and their maximum value size (bytes of
# the 53 template content). Discovery is generated and read-only.
DATA_OBJECT_CAPS = {
    OBJ_CHUID: 960,
    OBJ_CCC: 128,
    OBJ_PRINTED: 256,
    OBJ_SECURITY: 768,
    OBJ_KEY_HISTORY: 128,
}

MAX_CERT_LEN = const(2048)  # docs/architecture.md §6.3

# i18n keys of the slot roles (spec §6.3 "rôle de la clé")
SLOT_ROLE_KEYS = {
    SLOT_AUTH: "piv.role.auth",
    SLOT_SIGN: "piv.role.sign",
    SLOT_KEYMGMT: "piv.role.keymgmt",
    SLOT_CARDAUTH: "piv.role.cardauth",
}
ALG_NAME = {ALG_P256: "ECC P-256", ALG_RSA2048: "RSA 2048"}
MGMT_ALG_NAME = {ALG_3DES: "3DES", ALG_AES128: "AES-128", ALG_AES192: "AES-192", ALG_AES256: "AES-256"}

# factory defaults (used only until the user sets their own values)
DEFAULT_PIN = b"123456"
DEFAULT_PUK = b"12345678"
DEFAULT_MGMT_ALG = ALG_AES192
DEFAULT_MGMT_KEY = bytes.fromhex("010203040506070801020304050607080102030405060708")
DEFAULT_PIN_RETRIES = const(3)
DEFAULT_PUK_RETRIES = const(3)
