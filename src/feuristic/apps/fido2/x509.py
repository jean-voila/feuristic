# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Minimal DER X.509 v3 builder for self-signed P-256 certificates (RFC 5280).

Used for the U2F registration attestation certificate (FIDO U2F Raw
Message Formats v1.2 §4.3). feuristic has no vendor attestation key (the
Optiga attestation objects are lost when the bootloader is unlocked,
docs/architecture.md §4) and never impersonates a vendor, so the
certificate is a *self attestation* certificate: its subject key is the
newly registered credential key and it is signed by that same key. This
keeps U2F registrations unlinkable across relying parties (a per-device
certificate would be a global tracking identifier) and mirrors CTAP2
``packed`` self attestation.

Output size is bounded (≈ 330 bytes): fixed names, one extension
(basicConstraints CA:FALSE, critical), 16-byte serial derived from the
public key, validity 2026-01-01 → 9999-12-31 ("no well-defined expiration",
RFC 5280 §4.1.2.5).
"""

from ...platform import crypto

_OID_ECDSA_SHA256 = b"\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02"
_OID_EC_PUBLIC_KEY = b"\x06\x07\x2a\x86\x48\xce\x3d\x02\x01"
_OID_P256 = b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"
_OID_CN = b"\x06\x03\x55\x04\x03"
_OID_O = b"\x06\x03\x55\x04\x0a"
_OID_OU = b"\x06\x03\x55\x04\x0b"
_OID_BASIC_CONSTRAINTS = b"\x06\x03\x55\x1d\x13"

SUBJECT_CN = "feuristic self attestation"
SUBJECT_O = "feuristic project"
SUBJECT_OU = "Authenticator Attestation"
NOT_BEFORE = b"260101000000Z"  # UTCTime
NOT_AFTER = b"99991231235959Z"  # GeneralizedTime


def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes((n,))
    if n < 0x100:
        return bytes((0x81, n))
    if n < 0x10000:
        return bytes((0x82, n >> 8, n & 0xFF))
    raise ValueError("DER length")


def tlv(tag: int, content: bytes) -> bytes:
    return bytes((tag,)) + _len(len(content)) + content


def seq(*parts) -> bytes:
    return tlv(0x30, b"".join(parts))


def der_uint(value: bytes) -> bytes:
    """DER INTEGER of the unsigned big-endian ``value``."""
    v = bytes(value).lstrip(b"\x00") or b"\x00"
    if v[0] & 0x80:
        v = b"\x00" + v
    return tlv(0x02, v)


def _name() -> bytes:
    def rdn(oid: bytes, text: str) -> bytes:
        return tlv(0x31, seq(oid, tlv(0x0C, text.encode())))

    return seq(rdn(_OID_O, SUBJECT_O), rdn(_OID_OU, SUBJECT_OU), rdn(_OID_CN, SUBJECT_CN))


def tbs_certificate(public_key: bytes) -> bytes:
    if len(public_key) != 65 or public_key[0] != 0x04:
        raise ValueError("P-256 public key")
    serial = bytearray(crypto.sha256(b"feuristic/x509-serial" + public_key)[:16])
    serial[0] = (serial[0] & 0x7F) | 0x40  # positive, 16 significant bytes
    name = _name()
    spki = seq(seq(_OID_EC_PUBLIC_KEY, _OID_P256), tlv(0x03, b"\x00" + public_key))
    ext = seq(seq(_OID_BASIC_CONSTRAINTS, b"\x01\x01\xff", tlv(0x04, seq())))
    return seq(
        b"\xa0\x03\x02\x01\x02",  # [0] EXPLICIT version v3
        der_uint(bytes(serial)),
        seq(_OID_ECDSA_SHA256),
        name,
        seq(tlv(0x17, NOT_BEFORE), tlv(0x18, NOT_AFTER)),
        name,
        spki,
        tlv(0xA3, ext),
    )


def self_signed_p256(private_key: bytes) -> bytes:
    """DER certificate for ``private_key``'s public key, signed by itself."""
    pub = crypto.p256_public(private_key)
    tbs = tbs_certificate(pub)
    sig = crypto.ecdsa_sig_to_der(crypto.p256_sign_digest(private_key, crypto.sha256(tbs)))
    return seq(tbs, seq(_OID_ECDSA_SHA256), tlv(0x03, b"\x00" + sig))
