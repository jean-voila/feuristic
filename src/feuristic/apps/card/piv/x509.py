# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Minimal, bounded DER helpers for PIV (display and fingerprints only).

* :func:`spki_p256` / :func:`spki_rsa` build the X.509 ``SubjectPublicKeyInfo``
  (RFC 5280 §4.1.2.7, RFC 5480, RFC 8017 App. A.1.1) of a slot key, so that
  the fingerprint shown on the device (:func:`fingerprint`, SHA-256 over the
  SPKI DER) can be compared with the host:
  ``openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum``.
* :func:`summarize` extracts subject CN, issuer CN, validity dates and serial
  number from a DER certificate for the "PIV → certificats" menu. It is a
  **display-only** parser: no signature, extension or path validation is
  performed and nothing it returns is used for a security decision. Input is
  bounded (:data:`MAX_CERT_LEN`), recursion-free, and every length is
  checked against its enclosing element.
"""

from micropython import const

from ....core.errors import InvalidInput
from ....platform import crypto

MAX_CERT_LEN = const(2048)  # docs/architecture.md §6.3
MAX_CN_CHARS = const(64)
FP_DISPLAY_BYTES = const(8)

_SPKI_P256_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
_RSA_ALG_ID = bytes.fromhex("300d06092a864886f70d0101010500")
_OID_CN = b"\x55\x04\x03"


class CertParseError(InvalidInput):
    """The certificate could not be summarised (malformed or unsupported)."""


# ---------------------------------------------------------------------------
# DER encoding
# ---------------------------------------------------------------------------


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes((n,))
    if n <= 0xFF:
        return bytes((0x81, n))
    if n <= 0xFFFF:
        return b"\x82" + n.to_bytes(2, "big")
    raise InvalidInput("DER length")


def _der(tag: int, value: bytes) -> bytes:
    return bytes((tag,)) + _der_len(len(value)) + value


def _der_uint(v: bytes) -> bytes:
    v = bytes(v).lstrip(b"\x00") or b"\x00"
    if v[0] & 0x80:
        v = b"\x00" + v
    return _der(0x02, v)


def spki_p256(point: bytes) -> bytes:
    if len(point) != 65 or point[0] != 0x04:
        raise InvalidInput("P-256 point")
    return _SPKI_P256_PREFIX + bytes(point)


def spki_rsa(n: bytes, e: int) -> bytes:
    e_bytes = e.to_bytes(4, "big")
    rsa_pub = _der(0x30, _der_uint(n) + _der_uint(e_bytes))
    return _der(0x30, _RSA_ALG_ID + _der(0x03, b"\x00" + rsa_pub))


def fingerprint(spki: bytes) -> bytes:
    """SHA-256 of the SubjectPublicKeyInfo DER (32 bytes)."""
    return crypto.sha256(spki)


def display_fingerprint(spki: bytes) -> str:
    """Upper-case hex of the first :data:`FP_DISPLAY_BYTES` bytes of :func:`fingerprint`."""
    return fingerprint(spki)[:FP_DISPLAY_BYTES].hex().upper()


# ---------------------------------------------------------------------------
# DER decoding (display only)
# ---------------------------------------------------------------------------


def _read(buf, pos: int, end: int):
    """Return ``(tag, value_start, value_end)`` of the element at ``pos``."""
    if pos + 2 > end:
        raise CertParseError("truncated")
    tag = buf[pos]
    if tag & 0x1F == 0x1F:
        raise CertParseError("high tag number")
    first = buf[pos + 1]
    pos += 2
    if first < 0x80:
        n = first
    elif first == 0x81:
        if pos + 1 > end:
            raise CertParseError("truncated")
        n = buf[pos]
        pos += 1
    elif first == 0x82:
        if pos + 2 > end:
            raise CertParseError("truncated")
        n = (buf[pos] << 8) | buf[pos + 1]
        pos += 2
    else:
        raise CertParseError("length form")
    if pos + n > end:
        raise CertParseError("overrun")
    return tag, pos, pos + n


def _expect(buf, pos: int, end: int, tag: int):
    t, s, e = _read(buf, pos, end)
    if t != tag:
        raise CertParseError("unexpected tag")
    return s, e


def _text(tag: int, raw: bytes) -> str:
    if tag == 0x1E:  # BMPString (UTF-16BE): keep the BMP-ASCII subset
        if len(raw) % 2:
            raise CertParseError("BMPString")
        raw = bytes(raw[i + 1] if raw[i] == 0 else 0x3F for i in range(0, len(raw), 2))
    elif tag not in (0x0C, 0x13, 0x14, 0x16, 0x1C):
        raise CertParseError("string type")
    try:
        s = bytes(raw).decode()
    except Exception:
        s = "".join(chr(b) if 0x20 <= b < 0x7F else "?" for b in raw)
    s = "".join(ch if ch >= " " and ch != "\x7f" else "?" for ch in s)
    if len(s) > MAX_CN_CHARS:
        s = s[: MAX_CN_CHARS - 1] + "…"
    return s


def _common_name(buf, start: int, end: int) -> str:
    """Last CN attribute of an RDNSequence (most specific), or ``""``."""
    cn = ""
    pos = start
    while pos < end:
        s_set, e_set = _expect(buf, pos, end, 0x31)
        pos = e_set
        p2 = s_set
        while p2 < e_set:
            s_atv, e_atv = _expect(buf, p2, e_set, 0x30)
            p2 = e_atv
            s_oid, e_oid = _expect(buf, s_atv, e_atv, 0x06)
            vt, vs, ve = _read(buf, e_oid, e_atv)
            if ve != e_atv:
                raise CertParseError("attribute")
            if bytes(buf[s_oid:e_oid]) == _OID_CN:
                cn = _text(vt, buf[vs:ve])
    return cn


def _time(tag: int, raw: bytes) -> str:
    """``YYYY-MM-DD`` from UTCTime (RFC 5280 §4.1.2.5.1) / GeneralizedTime."""
    try:
        s = bytes(raw).decode()
    except Exception:
        raise CertParseError("time")
    if tag == 0x17:
        if len(s) < 11 or not s[:6].isdigit():
            raise CertParseError("UTCTime")
        yy = int(s[0:2])
        year = 1900 + yy if yy >= 50 else 2000 + yy
        rest = s[2:6]
    elif tag == 0x18:
        if len(s) < 13 or not s[:8].isdigit():
            raise CertParseError("GeneralizedTime")
        year = int(s[0:4])
        rest = s[4:8]
    else:
        raise CertParseError("time type")
    month, day = int(rest[0:2]), int(rest[2:4])
    if not (1 <= month <= 12 and 1 <= day <= 31):
        raise CertParseError("date")
    return f"{year:04d}-{month:02d}-{day:02d}"


class CertSummary:
    def __init__(self, subject_cn, issuer_cn, not_before, not_after, serial_hex, sha256_hex) -> None:
        self.subject_cn = subject_cn
        self.issuer_cn = issuer_cn
        self.not_before = not_before
        self.not_after = not_after
        self.serial_hex = serial_hex
        #: first 8 bytes of SHA-256(certificate DER), upper-case hex
        self.sha256_hex = sha256_hex

    def __repr__(self) -> str:
        return f"CertSummary({self.subject_cn!r}, {self.issuer_cn!r}, {self.not_before}..{self.not_after})"


def summarize(der: bytes) -> CertSummary:
    """Summarise an X.509 v1/v3 certificate (raises :class:`CertParseError`)."""
    der = bytes(der)
    if not 0 < len(der) <= MAX_CERT_LEN:
        raise CertParseError("certificate size")
    buf = memoryview(der)
    s_cert, e_cert = _expect(buf, 0, len(der), 0x30)
    if e_cert != len(der):
        raise CertParseError("trailing data")
    s_tbs, e_tbs = _expect(buf, s_cert, e_cert, 0x30)
    pos = s_tbs
    tag, s, e = _read(buf, pos, e_tbs)
    if tag == 0xA0:  # [0] EXPLICIT Version
        pos = e
        tag, s, e = _read(buf, pos, e_tbs)
    if tag != 0x02:
        raise CertParseError("serial")
    serial = bytes(buf[s:e])[:16].hex().upper()
    pos = e
    _, pos = _expect(buf, pos, e_tbs, 0x30)  # signature AlgorithmIdentifier
    s_iss, e_iss = _expect(buf, pos, e_tbs, 0x30)
    issuer = _common_name(buf, s_iss, e_iss)
    s_val, e_val = _expect(buf, e_iss, e_tbs, 0x30)
    t1, s1, e1 = _read(buf, s_val, e_val)
    t2, s2, e2 = _read(buf, e1, e_val)
    if e2 != e_val:
        raise CertParseError("validity")
    not_before = _time(t1, buf[s1:e1])
    not_after = _time(t2, buf[s2:e2])
    s_sub, e_sub = _expect(buf, e_val, e_tbs, 0x30)
    subject = _common_name(buf, s_sub, e_sub)
    digest = crypto.sha256(der)[:FP_DISPLAY_BYTES].hex().upper()
    return CertSummary(subject, issuer, not_before, not_after, serial, digest)
