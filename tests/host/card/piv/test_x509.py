# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Display-only certificate summary and SPKI fingerprints."""

import contextlib
import datetime
import hashlib

import pytest
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from hypothesis import given, settings
from hypothesis import strategies as st

from feuristic.apps.card.piv import x509


def make_cert(subject_cn="alice", issuer_cn="Example CA", not_before=None, not_after=None, extra_attrs=()):
    key = ec.generate_private_key(ec.SECP256R1())
    subj = [cx509.NameAttribute(NameOID.ORGANIZATION_NAME, "Org"), *extra_attrs]
    if subject_cn is not None:
        subj.append(cx509.NameAttribute(NameOID.COMMON_NAME, subject_cn))
    iss = [cx509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)]
    nb = not_before or datetime.datetime(2026, 1, 2, tzinfo=datetime.UTC)
    na = not_after or datetime.datetime(2027, 3, 4, tzinfo=datetime.UTC)
    cert = (
        cx509.CertificateBuilder()
        .subject_name(cx509.Name(subj))
        .issuer_name(cx509.Name(iss))
        .public_key(key.public_key())
        .serial_number(0x1234ABCD)
        .not_valid_before(nb)
        .not_valid_after(na)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER), key


def test_summary_fields():
    der, _ = make_cert()
    s = x509.summarize(der)
    assert s.subject_cn == "alice"
    assert s.issuer_cn == "Example CA"
    assert s.not_before == "2026-01-02"
    assert s.not_after == "2027-03-04"
    assert s.serial_hex == "1234ABCD"
    assert s.sha256_hex == hashlib.sha256(der).digest()[:8].hex().upper()
    assert "alice" in repr(s)


def test_generalized_time_after_2049():
    der, _ = make_cert(not_after=datetime.datetime(2060, 12, 31, tzinfo=datetime.UTC))
    assert x509.summarize(der).not_after == "2060-12-31"


def test_utctime_before_2000():
    der, _ = make_cert(not_before=datetime.datetime(1999, 5, 6, tzinfo=datetime.UTC))
    assert x509.summarize(der).not_before == "1999-05-06"


def test_no_common_name():
    der, _ = make_cert(subject_cn=None)
    assert x509.summarize(der).subject_cn == ""


def test_unicode_and_control_characters():
    der, _ = make_cert(subject_cn="Élodie\x07Ünïcode")
    assert x509.summarize(der).subject_cn == "Élodie?Ünïcode"


def test_long_cn_truncated():
    der, _ = make_cert(subject_cn="x" * 64, extra_attrs=())
    assert len(x509.summarize(der).subject_cn) == 64
    # 64 is the limit for CN in RFC 5280 upper bounds; longer via raw bytes:
    assert x509._text(0x0C, b"y" * 100) == "y" * 63 + "…"


def test_bmpstring():
    assert x509._text(0x1E, "AB".encode("utf-16-be")) == "AB"
    with pytest.raises(x509.CertParseError):
        x509._text(0x1E, b"\x00")


@pytest.mark.parametrize(
    "der", [b"", b"\x30", b"\x30\x00", b"\x31\x00", b"\x30\x83\x00\x00\x00", bytes(2049)]
)
def test_malformed(der):
    with pytest.raises(x509.CertParseError):
        x509.summarize(der)


def test_trailing_data_rejected():
    der, _ = make_cert()
    with pytest.raises(x509.CertParseError):
        x509.summarize(der + b"\x00")


def test_truncations_never_crash():
    der, _ = make_cert()
    for n in range(len(der)):
        with pytest.raises(x509.CertParseError):
            x509.summarize(der[:n])


@settings(max_examples=300, deadline=None)
@given(st.binary(max_size=600))
def test_fuzz_random_input(data):
    with contextlib.suppress(x509.CertParseError):
        x509.summarize(data)


@settings(max_examples=300, deadline=None)
@given(st.integers(min_value=0, max_value=10_000), st.integers(min_value=0, max_value=255))
def test_fuzz_byte_flips(pos, value):
    der = bytearray(FIXED_CERT)
    der[pos % len(der)] = value
    with contextlib.suppress(x509.CertParseError):
        x509.summarize(bytes(der))


FIXED_CERT = make_cert()[0]


def test_spki_matches_cryptography():
    key = ec.generate_private_key(ec.SECP256R1()).public_key()
    point = key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert x509.spki_p256(point) == der
    assert x509.display_fingerprint(der) == hashlib.sha256(der).digest()[:8].hex().upper()


def test_spki_rsa_matches_cryptography(rsa_private_key):
    pub = rsa_private_key.public_key()
    n = pub.public_numbers().n.to_bytes(256, "big")
    der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert x509.spki_rsa(n, 65537) == der


def test_spki_p256_rejects_bad_point():
    with pytest.raises(Exception):  # noqa: B017
        x509.spki_p256(bytes(64))
