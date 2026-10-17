# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Constants of the OpenPGP Card application v3.4 (feuristic profile).

References are to "Functional Specification of the OpenPGP application on
ISO Smart Card Operating Systems", version 3.4.1 (OpenPGP Card 3.4).
"""

from micropython import const

# --- AID (§4.2.1) -------------------------------------------------------------
RID = b"\xd2\x76\x00\x01\x24"
PIX_APP = b"\x01"  # OpenPGP application
VERSION = b"\x03\x04"  # 3.4
#: Manufacturer ID from the range FF00–FFFE "reserved for randomly assigned
#: serial numbers" (§4.2.1, GnuPG: "unmanaged S/N range"). Never a vendor ID.
MANUFACTURER = b"\xff\x7e"
AID_PREFIX = RID + PIX_APP + VERSION + MANUFACTURER  # 10 bytes, then serial(4) + RFU 00 00
AID_RFU = b"\x00\x00"
SERIAL_CONTEXT = b"openpgp"

# --- key roles ------------------------------------------------------------------
SIG = const(0)
DEC = const(1)
AUT = const(2)
ROLES = (SIG, DEC, AUT)
ROLE_NAMES = ("sig", "dec", "aut")
CRT_TAGS = (0xB6, 0xB8, 0xA4)  # control reference templates (§7.2.14)
ATTR_TAGS = (0xC1, 0xC2, 0xC3)
FPR_TAGS = (0xC7, 0xC8, 0xC9)
CA_FPR_TAGS = (0xCA, 0xCB, 0xCC)
DATE_TAGS = (0xCE, 0xCF, 0xD0)
UIF_TAGS = (0xD6, 0xD7, 0xD8)

# key origin (DE key information, §4.4.3.12)
ORIGIN_NONE = const(0)
ORIGIN_GENERATED = const(1)
ORIGIN_IMPORTED = const(2)

# --- algorithms (§4.4.3.9) -------------------------------------------------------
ALGO_RSA = const(0x01)
ALGO_ECDH = const(0x12)
ALGO_EDDSA = const(0x16)

OID_ED25519 = b"\x2b\x06\x01\x04\x01\xda\x47\x0f\x01"  # 1.3.6.1.4.1.11591.15.1
OID_CV25519 = b"\x2b\x06\x01\x04\x01\x97\x55\x01\x05\x01"  # 1.3.6.1.4.1.3029.1.5.1

ATTR_ED25519 = bytes((ALGO_EDDSA,)) + OID_ED25519
ATTR_X25519 = bytes((ALGO_ECDH,)) + OID_CV25519
#: RSA-2048, public exponent length 32 bits (as written by GnuPG), standard
#: import format (irrelevant: key import is not supported)
ATTR_RSA2048 = b"\x01\x08\x00\x00\x20\x00"

KIND_ED25519 = "ed25519"
KIND_X25519 = "x25519"
KIND_RSA2048 = "rsa2048"

DEFAULT_ATTRS = (ATTR_ED25519, ATTR_X25519, ATTR_ED25519)

RSA_BITS = const(2048)
RSA_BYTES = const(256)
RSA_E = 65537

# --- PINs (§4.3) ------------------------------------------------------------------
PW1 = const(0)
PW3 = const(1)
RC = const(2)
PW_NAMES = ("pw1", "pw3", "rc")
PW_MIN = (6, 8, 8)
PW_MAX = const(127)
PW_RETRIES = const(3)
DEFAULT_PW1 = b"123456"
DEFAULT_PW3 = b"12345678"
#: PW1 status byte default: 01 = PW1 valid for several PSO:CDS. Every
#: signature is confirmed on the device anyway (spec §6.3).
DEFAULT_PW1_STATUS = const(0x01)

# --- data object limits -----------------------------------------------------------
MAX_NAME = const(39)
MAX_LANG = const(8)
MAX_SPECIAL_DO = const(254)  # URL, login data, private DOs (advertised in C0)
MAX_CERT = const(2048)
MAX_CHALLENGE = const(32)  # product spec §7
MAX_CMD_DATA = const(4096)  # 7F66
MAX_RSP_DATA = const(4096)  # 7F66

# --- extended capabilities C0 (§4.4.3.7) -------------------------------------------
# byte 1: b7 GET CHALLENGE, b5 PW status changeable, b4 private DOs,
#         b3 algorithm attributes changeable. No SM, no key import, no AES,
#         no KDF-DO.
EXT_CAP_FLAGS = const(0x40 | 0x10 | 0x08 | 0x04)
#: 10 bytes: flags, SM algorithm (none), max GET CHALLENGE length (32), max
#: cardholder certificate length (2048), max special DO length (254), PIN
#: block 2 format (no), MSE for DEC/AUT keys (no)
EXTENDED_CAPABILITIES = b"\x5c\x00\x00\x20\x08\x00\x00\xfe\x00\x00"

#: User interaction flag: 02 = permanently enabled, 20 = button (general
#: feature management): every operation is confirmed on the device.
UIF_VALUE = b"\x02\x20"
#: General feature management (7F74 / 81): display (0x80) + button (0x20)
GENERAL_FEATURES = b"\x81\x01\xa0"

# --- life cycle -------------------------------------------------------------------------
LCS_OPERATIONAL = const(0x05)
LCS_TERMINATED = const(0x03)

# --- instructions -------------------------------------------------------------------
INS_SELECT_DATA = const(0xA5)
INS_GET_DATA = const(0xCA)
INS_GET_NEXT_DATA = const(0xCC)
INS_PUT_DATA = const(0xDA)
INS_PUT_DATA_ODD = const(0xDB)
INS_VERIFY = const(0x20)
INS_CHANGE_REFERENCE_DATA = const(0x24)
INS_RESET_RETRY_COUNTER = const(0x2C)
INS_GENERATE = const(0x47)
INS_PSO = const(0x2A)
INS_INTERNAL_AUTHENTICATE = const(0x88)
INS_GET_CHALLENGE = const(0x84)
INS_TERMINATE_DF = const(0xE6)
INS_ACTIVATE_FILE = const(0x44)
INS_MSE = const(0x22)

# --- CARD_COUNTERS keys (public namespace 0x94), OpenPGP range 0x10–0x1F ----------
#: per PIN: "fail" redundant counter (A, B) then "ok mark" counter (A, B);
#: remaining tries = 3 - (fail - ok_mark)
CTR_PW1 = const(0x10)  # 0x10..0x13
CTR_PW3 = const(0x14)  # 0x14..0x17
CTR_RC = const(0x18)  # 0x18..0x1B
CTR_DSC = const(0x1C)  # 0x1C..0x1D digital signature counter
CTR_BASES = (CTR_PW1, CTR_PW3, CTR_RC)

# --- CARD record store keys (protected namespace 0x14), OpenPGP range 0x00–0x0F -----
STORE_CAPACITY = const(3)  # identity + 2 alternating aux records → keys 0x00..0x03
STORE_RTYPE = const(0x50)
MAX_IDENTITY_PAYLOAD = const(1536)  # docs/architecture.md §6.3
MAX_AUX_PAYLOAD = const(3712)  # cert 2048 + 6 special DOs + CBOR overhead
UID_IDENTITY = b"OPGP-ID\x00"
UID_AUX = (b"OPGP-AXA", b"OPGP-AXB")
