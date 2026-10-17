# SPDX-License-Identifier: GPL-3.0-only
import pytest
from hypothesis import given
from hypothesis import strategies as st

from feuristic.apps.backup import frames
from feuristic.apps.importer import payload as pl

FRAME = frames.encode_frame(b"\x01" * 8, 1, 1, b"hello").encode()


@pytest.mark.parametrize(
    "data",
    [
        b"otpauth://totp/ACME:alice?secret=JBSWY3DPEHPK3PXP&issuer=ACME",
        b"OTPAUTH://hotp/x?secret=AAAA&counter=1",
        b"OtpAuth://totp/with space?secret=AAAA",
        b"otpauth://",
        bytearray(b"otpauth://totp/a?secret=A"),
        memoryview(b"otpauth://totp/a?secret=A"),
    ],
)
def test_otpauth(data):
    p = pl.classify(data)
    assert p.kind == pl.KIND_OTPAUTH
    assert p.data == bytes(data) and isinstance(p.data, bytes)


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        (b"otpauth://totp/a?secret=A\n", pl.REASON_NOT_PRINTABLE),
        (b"otpauth://totp/\x00", pl.REASON_NOT_PRINTABLE),
        ("otpauth://totp/été".encode(), pl.REASON_NOT_PRINTABLE),
        (b"otpauth://" + b"a" * 1015, pl.REASON_OTP_TOO_LONG),
    ],
)
def test_otpauth_rejected(data, reason):
    p = pl.classify(data)
    assert p.kind == pl.KIND_UNSUPPORTED and p.reason == reason and p.data is None


def test_otpauth_length_bound():
    assert pl.classify(b"otpauth://" + b"a" * 1014).kind == pl.KIND_OTPAUTH


def test_backup_frame():
    p = pl.classify(FRAME)
    assert p.kind == pl.KIND_BACKUP_FRAME and p.data == FRAME
    # classification does not verify the CRC (the session does)
    p = pl.classify(b"FB1:000")
    assert p.kind == pl.KIND_BACKUP_FRAME


@pytest.mark.parametrize("data", [b"FB2:000", b"FB0:ABC", b"FB12:AA", b"FB999:"])
def test_backup_other_version(data):
    p = pl.classify(data)
    assert p.kind == pl.KIND_BACKUP_UNSUPPORTED_VERSION and p.reason == pl.REASON_BACKUP_VERSION


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        (b"FB1:abc", pl.REASON_FRAME_CHARS),
        (b"FB1:AB\x00", pl.REASON_FRAME_CHARS),
        (b"FB1:" + b"0" * 1021, pl.REASON_FRAME_TOO_LONG),
    ],
)
def test_backup_frame_rejected(data, reason):
    p = pl.classify(data)
    assert p.kind == pl.KIND_UNSUPPORTED and p.reason == reason


@pytest.mark.parametrize(
    "data",
    [
        b"https://example.com",
        b"WIFI:S:net;T:WPA;P:pw;;",
        b"fb1:000",
        b"FB:000",
        b"FBX:000",
        b"FB1234:00",
        b"FB",
        b"otpauth:/totp",
        b"\xef\xbb\xbfotpauth://totp/a",  # BOM
        b" otpauth://totp/a",
        b"FEBK\x01binary",
    ],
)
def test_unsupported(data):
    p = pl.classify(data)
    assert p.kind == pl.KIND_UNSUPPORTED and p.reason == pl.REASON_UNKNOWN


def test_empty_and_too_large():
    assert pl.classify(b"").reason == pl.REASON_EMPTY
    p = pl.classify(b"otpauth://" + b"a" * 3000)
    assert p.kind == pl.KIND_TOO_LARGE and p.reason == pl.REASON_TOO_LARGE
    assert pl.classify(b"x" * 2953).kind == pl.KIND_UNSUPPORTED


def test_type_error():
    with pytest.raises(TypeError):
        pl.classify("otpauth://totp/a")


def test_helpers():
    assert pl.is_printable_ascii(b" ~")
    assert not pl.is_printable_ascii(b"\x7f")
    assert "reason" in repr(pl.classify(b""))


@given(st.binary(max_size=3100))
def test_fuzz_never_raises(data):
    p = pl.classify(data)
    assert p.kind in (
        pl.KIND_UNSUPPORTED,
        pl.KIND_OTPAUTH,
        pl.KIND_BACKUP_FRAME,
        pl.KIND_BACKUP_UNSUPPORTED_VERSION,
        pl.KIND_TOO_LARGE,
    )
    if p.kind in (pl.KIND_OTPAUTH, pl.KIND_BACKUP_FRAME):
        assert pl.is_printable_ascii(p.data)
