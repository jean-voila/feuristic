# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
import contextlib
import urllib.parse

import pytest
from hypothesis import given
from hypothesis import strategies as st

from feuristic.apps.otp import uri
from feuristic.core import base32
from feuristic.core.errors import InvalidInput

SECRET_B32 = "JBSWY3DPEHPK3PXP"
SECRET = b"Hello!\xde\xad\xbe\xef"
SECRET20_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # "12345678901234567890"


# -- Google Key Uri Format examples ------------------------------------------


def test_google_totp_example():
    p = uri.parse("otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example")
    assert (p.kind, p.issuer, p.account, p.secret) == ("totp", "Example", "alice@google.com", SECRET)
    assert (p.algorithm, p.digits, p.period, p.counter) == ("SHA1", 6, 30, None)
    assert not p.weak_secret  # exactly 80 bits
    assert p.label() == "Example: alice@google.com"
    assert uri.parse("otpauth://totp/me?secret=JBSWY3DPEHPK3PI").weak_secret  # 9 bytes
    assert "Hello" not in repr(p)


def test_google_full_example():
    p = uri.parse(
        "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ"
        "&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30"
    )
    assert p.issuer == "ACME Co"
    assert p.account == "john.doe@email.com"
    assert len(p.secret) == 20
    assert not p.weak_secret


def test_hotp_example():
    p = uri.parse(f"otpauth://hotp/Corp:bob?secret={SECRET20_B32}&counter=42&digits=8&algorithm=sha256")
    assert (p.kind, p.counter, p.digits, p.algorithm, p.period) == ("hotp", 42, 8, "SHA256", None)
    assert p.secret == b"12345678901234567890"


def test_label_variants():
    p = uri.parse(f"otpauth://totp/alice?secret={SECRET_B32}")
    assert (p.issuer, p.account) == ("", "alice")
    assert p.label() == "alice"
    p = uri.parse(f"otpauth://totp/Big%20Corp%3Aalice?secret={SECRET_B32}")
    assert (p.issuer, p.account) == ("Big Corp", "alice")
    p = uri.parse(f"otpauth://totp/Big%20Corp:%20%20alice?secret={SECRET_B32}")
    assert p.account == "alice"
    p = uri.parse(f"otpauth://totp/:alice?secret={SECRET_B32}&issuer=X")
    assert (p.issuer, p.account) == ("X", "alice")
    p = uri.parse(f"otpauth://totp/alice?secret={SECRET_B32}&issuer=Only%20Param")
    assert p.issuer == "Only Param"
    p = uri.parse(f"otpauth://totp/a+b@x.com?secret={SECRET_B32}")
    assert p.account == "a+b@x.com"  # '+' literal in the path


def test_case_insensitive_scheme_type_params():
    p = uri.parse(f"OTPAUTH://TOTP/x:y?SECRET={SECRET_B32.lower()}&Algorithm=sha512&DIGITS=7&Period=60")
    assert (p.kind, p.algorithm, p.digits, p.period, p.secret) == ("totp", "SHA512", 7, 60, SECRET)


def test_unicode_labels():
    p = uri.parse(
        "otpauth://totp/Soci%C3%A9t%C3%A9%20G%C3%A9n%C3%A9rale:j%C3%BCrgen%40exemple.fr"
        f"?secret={SECRET_B32}&issuer=Soci%C3%A9t%C3%A9%20G%C3%A9n%C3%A9rale"
    )
    assert p.issuer == "Société Générale"
    assert p.account == "jürgen@exemple.fr"
    # raw (not percent-encoded) UTF-8 is tolerated
    p = uri.parse(f"otpauth://totp/日本:太郎?secret={SECRET_B32}".encode())
    assert (p.issuer, p.account) == ("日本", "太郎")
    p = uri.parse(f"otpauth://totp/%F0%9F%94%91:key?secret={SECRET_B32}")
    assert p.issuer == "\U0001f511"


def test_plus_is_space_in_query_and_raw_space():
    p = uri.parse(f"otpauth://totp/ACME%20Co:me?secret={SECRET_B32}&issuer=ACME+Co")
    assert p.issuer == "ACME Co"
    p = uri.parse(f"otpauth://totp/ACME Co:me?secret={SECRET_B32}&issuer=ACME%20Co")
    assert p.issuer == "ACME Co"
    p = uri.parse(f"otpauth://totp/me?secret={SECRET_B32}&issuer=C%2B%2B")
    assert p.issuer == "C++"


def test_secret_forms():
    for s in ("JBSW%20Y3DP%20EHPK%203PXP", "jbsw-y3dp-ehpk-3pxp", "JBSWY3DPEHPK3PXP", "JBSW+Y3DP"):
        p = uri.parse(f"otpauth://totp/me?secret={s}")
        assert p.secret.startswith(b"Hello")
    assert uri.parse("otpauth://totp/me?secret=MZXW6YQ%3D").secret == b"foob"
    assert uri.parse("otpauth://totp/me?secret=MZXW6YQ=").secret == b"foob"
    with pytest.raises(InvalidInput):
        uri.parse("otpauth://totp/me?secret=JBSWY3DPEHPK3PXP%3D%3D%3D")
    # random base32 character strings (non canonical length) are accepted
    p = uri.parse("otpauth://totp/me?secret=JBSWY3DPEHPK3PXPA")
    assert p.secret == SECRET
    p = uri.parse("otpauth://totp/me?secret=MB")  # 1 byte: accepted but weak
    assert p.secret == b"\x60" and p.weak_secret


def test_unknown_params_ignored_and_empty_parts():
    p = uri.parse(
        f"otpauth://totp/me?secret={SECRET_B32}&image=https%3A%2F%2Fx%2Fa.png&color=red&&flag&issuer="
    )
    assert p.secret == SECRET
    assert p.issuer == ""


def test_period_ignored_for_hotp_counter_ignored_for_totp():
    p = uri.parse(f"otpauth://hotp/me?secret={SECRET_B32}&counter=0&period=30")
    assert p.period is None and p.counter == 0
    p = uri.parse(f"otpauth://totp/me?secret={SECRET_B32}&counter=5")
    assert p.counter is None and p.period == 30


def test_limits_accepted_at_boundary():
    issuer = "i" * 32
    account = "a" * 64
    secret = base32.encode(bytes(range(64)), pad=False)
    p = uri.parse(f"otpauth://hotp/{issuer}:{account}?secret={secret}&counter=18446744073709551615")
    assert (len(p.issuer), len(p.account), len(p.secret), p.counter) == (32, 64, 64, 2**64 - 1)
    p = uri.parse(f"otpauth://totp/me?secret={SECRET_B32}&period=15")
    assert p.period == 15
    p = uri.parse(f"otpauth://totp/me?secret={SECRET_B32}&period=300")
    assert p.period == 300


INVALID = [
    ("", "empty"),
    ("https://example.com/?secret=JBSWY3DPEHPK3PXP", "scheme"),
    ("otpauth:/totp/me?secret=JBSWY3DPEHPK3PXP", "scheme"),
    ("otpauth://totp?secret=JBSWY3DPEHPK3PXP", "no label"),
    ("otpauth://totp/me", "no params"),
    ("otpauth://totp/?secret=JBSWY3DPEHPK3PXP", "empty account"),
    ("otpauth://totp/Issuer:?secret=JBSWY3DPEHPK3PXP", "empty account"),
    ("otpauth://totp/Issuer:%20%20?secret=JBSWY3DPEHPK3PXP", "blank account"),
    ("otpauth://motp/me?secret=JBSWY3DPEHPK3PXP", "type"),
    ("otpauth://steam/me?secret=JBSWY3DPEHPK3PXP", "type"),
    ("otpauth://totp/me?issuer=X", "missing secret"),
    ("otpauth://totp/me?secret=", "empty secret"),
    ("otpauth://totp/me?secret", "secret without value"),
    ("otpauth://totp/me?secret=JBSWY3DPEHPK3PX1", "bad base32"),
    ("otpauth://totp/me?secret=JBSWY3DP%00", "bad base32 nul"),
    ("otpauth://totp/me?secret=A", "base32 too short"),
    ("otpauth://totp/me?secret=JBS=WY3DP", "base32 padding in middle"),
    ("otpauth://totp/A:me?secret=JBSWY3DPEHPK3PXP&issuer=B", "issuer mismatch"),
    ("otpauth://totp/a:me?secret=JBSWY3DPEHPK3PXP&issuer=A", "issuer mismatch (case)"),
    ("otpauth://totp/me?secret=JBSWY3DPEHPK3PXP&algorithm=MD5", "algorithm"),
    ("otpauth://totp/me?secret=JBSWY3DPEHPK3PXP&algorithm=SHA-1", "algorithm"),
    ("otpauth://totp/me?secret=JBSWY3DPEHPK3PXP&algorithm=", "algorithm"),
    ("otpauth://totp/me?secret=JBSWY3DPEHPK3PXP&digits=10", "digits 10"),
    ("otpauth://totp/me?secret=JBSWY3DPEHPK3PXP&digits=5", "digits 5"),
    ("otpauth://totp/me?secret=JBSWY3DPEHPK3PXP&digits=9", "digits 9"),
    ("otpauth://totp/me?secret=JBSWY3DPEHPK3PXP&digits=-6", "digits sign"),
    ("otpauth://totp/me?secret=JBSWY3DPEHPK3PXP&digits=+6", "digits sign"),
    ("otpauth://totp/me?secret=JBSWY3DPEHPK3PXP&digits=six", "digits text"),
    ("otpauth://totp/me?secret=JBSWY3DPEHPK3PXP&digits=", "digits empty"),
    ("otpauth://totp/me?secret=JBSWY3DPEHPK3PXP&period=0", "period 0"),
    ("otpauth://totp/me?secret=JBSWY3DPEHPK3PXP&period=-30", "period negative"),
    ("otpauth://totp/me?secret=JBSWY3DPEHPK3PXP&period=14", "period low"),
    ("otpauth://totp/me?secret=JBSWY3DPEHPK3PXP&period=301", "period high"),
    ("otpauth://totp/me?secret=JBSWY3DPEHPK3PXP&period=30.5", "period float"),
    ("otpauth://totp/me?secret=JBSWY3DPEHPK3PXP&period=" + "9" * 25, "period huge"),
    ("otpauth://hotp/me?secret=JBSWY3DPEHPK3PXP", "counter missing"),
    ("otpauth://hotp/me?secret=JBSWY3DPEHPK3PXP&counter=", "counter empty"),
    ("otpauth://hotp/me?secret=JBSWY3DPEHPK3PXP&counter=-1", "counter negative"),
    ("otpauth://hotp/me?secret=JBSWY3DPEHPK3PXP&counter=18446744073709551616", "counter > 2^64-1"),
    ("otpauth://hotp/me?secret=JBSWY3DPEHPK3PXP&counter=0x10", "counter hex"),
    ("otpauth://totp/me?secret=JBSWY3DPEHPK3PXP&secret=JBSWY3DPEHPK3PXP", "duplicate secret"),
    ("otpauth://totp/me?secret=JBSWY3DPEHPK3PXP&SECRET=JBSWY3DPEHPK3PXP", "duplicate secret case"),
    ("otpauth://totp/me?secret=JBSWY3DPEHPK3PXP&issuer=A&issuer=A", "duplicate issuer"),
    ("otpauth://totp/me?secret=JBSWY3DPEHPK3PXP&digits=6&digits=8", "duplicate digits"),
    ("otpauth://totp/me?secret=JBSWY3DPEHPK3PXP&period=30&period=30", "duplicate period"),
    ("otpauth://hotp/me?secret=JBSWY3DPEHPK3PXP&counter=1&counter=2", "duplicate counter"),
    ("otpauth://totp/me?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&algorithm=SHA1", "duplicate alg"),
    ("otpauth://totp/me%2?secret=JBSWY3DPEHPK3PXP", "truncated escape"),
    ("otpauth://totp/me%?secret=JBSWY3DPEHPK3PXP", "truncated escape"),
    ("otpauth://totp/me%zz?secret=JBSWY3DPEHPK3PXP", "bad escape"),
    ("otpauth://totp/me?secret=JBSWY3DPEHPK3PXP&issuer=%G0", "bad escape"),
    ("otpauth://totp/me%FF?secret=JBSWY3DPEHPK3PXP", "invalid utf-8"),
    ("otpauth://totp/me%C3%28?secret=JBSWY3DPEHPK3PXP", "invalid utf-8"),
    ("otpauth://totp/me%C0%AF?secret=JBSWY3DPEHPK3PXP", "overlong utf-8"),
    ("otpauth://totp/me%ED%A0%80?secret=JBSWY3DPEHPK3PXP", "surrogate"),
    ("otpauth://totp/me%F4%90%80%80?secret=JBSWY3DPEHPK3PXP", "> U+10FFFF"),
    ("otpauth://totp/me%E2%82?secret=JBSWY3DPEHPK3PXP", "truncated utf-8"),
    ("otpauth://totp/me%00?secret=JBSWY3DPEHPK3PXP", "nul"),
    ("otpauth://totp/me%0A?secret=JBSWY3DPEHPK3PXP", "newline"),
    ("otpauth://totp/me%7F?secret=JBSWY3DPEHPK3PXP", "del"),
    ("otpauth://totp/me%C2%85?secret=JBSWY3DPEHPK3PXP", "C1 control"),
    ("otpauth://totp/Bank%E2%80%AE:me?secret=JBSWY3DPEHPK3PXP", "bidi override"),
    ("otpauth://totp/Ba%E2%80%8Bnk:me?secret=JBSWY3DPEHPK3PXP", "zero width space"),
    ("otpauth://totp/me?secret=JBSWY3DPEHPK3PXP&issuer=a%0Db", "control in issuer"),
    ("otpauth://totp/me\n?secret=JBSWY3DPEHPK3PXP", "raw newline"),
    ("otpauth://totp/me\t?secret=JBSWY3DPEHPK3PXP", "raw tab"),
    ("otpauth://totp/me?secret=JBSWY3DPEHPK3PXP#frag", "fragment"),
    ("otpauth://totp/A:b:c?secret=JBSWY3DPEHPK3PXP", "colon in account"),
    ("otpauth://totp/A:b%3Ac?secret=JBSWY3DPEHPK3PXP", "encoded colon in account"),
    ("otpauth://totp/me?secret=JBSWY3DPEHPK3PXP&issuer=A%3AB", "colon in issuer param"),
    ("otpauth://totp/" + "i" * 33 + ":me?secret=JBSWY3DPEHPK3PXP", "issuer too long"),
    ("otpauth://totp/me?secret=JBSWY3DPEHPK3PXP&issuer=" + "i" * 33, "issuer param too long"),
    ("otpauth://totp/" + "%C3%A9" * 17 + ":me?secret=JBSWY3DPEHPK3PXP", "issuer too long (bytes)"),
    ("otpauth://totp/" + "a" * 65 + "?secret=JBSWY3DPEHPK3PXP", "account too long"),
    ("otpauth://totp/me?secret=" + base32.encode(bytes(65), pad=False), "secret too long"),
    ("otpauth://totp/me?secret=JBSWY3DPEHPK3PXP&image=" + "x" * 500, "uri too long"),
]


@pytest.mark.parametrize(("text", "why"), INVALID, ids=[w for _, w in INVALID])
def test_invalid_uris(text, why):
    with pytest.raises(InvalidInput):
        uri.parse(text)
    with pytest.raises(InvalidInput):
        uri.parse(text.encode())


def test_raw_bytes_invalid_utf8_and_types():
    with pytest.raises(InvalidInput):
        uri.parse(b"otpauth://totp/m\xffe?secret=JBSWY3DPEHPK3PXP")
    with pytest.raises(InvalidInput):
        uri.parse(None)
    with pytest.raises(InvalidInput):
        uri.parse(12)
    # exactly 512 bytes is accepted, 513 refused
    base = f"otpauth://totp/me?secret={SECRET_B32}&image="
    ok = base + "x" * (512 - len(base))
    assert uri.parse(ok).secret == SECRET
    with pytest.raises(InvalidInput):
        uri.parse(ok + "x")
    with pytest.raises(InvalidInput):
        uri.parse("é" * 300)  # 300 chars but 600 bytes


# -- OtpParams validation ---------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"kind": "motp"},
        {"issuer": None},
        {"issuer": "a:b"},
        {"issuer": " lead"},
        {"issuer": "x" * 33},
        {"account": ""},
        {"account": "trail "},
        {"account": b"bytes"},
        {"account": "a" * 65},
        {"account": "a\x00b"},
        {"secret": b""},
        {"secret": "str"},
        {"secret": bytes(65)},
        {"algorithm": "sha1"},
        {"digits": 9},
        {"period": 10},
        {"kind": "hotp", "counter": None},
        {"kind": "hotp", "counter": -1},
        {"kind": "hotp", "counter": True},
        {"kind": "hotp", "counter": 2**64},
    ],
)
def test_params_validation(kwargs):
    args = {
        "kind": "totp",
        "issuer": "I",
        "account": "a",
        "secret": SECRET,
        "algorithm": "SHA1",
        "digits": 6,
        "period": None,
        "counter": None,
    }
    args.update(kwargs)
    with pytest.raises(InvalidInput):
        uri.OtpParams(**args)


# -- building ------------------------------------------------------------------


def test_build_canonical_forms():
    p = uri.OtpParams("totp", "ACME Co", "john.doe@email.com", SECRET)
    assert uri.build(p) == (
        "otpauth://totp/ACME%20Co:john.doe@email.com?secret=JBSWY3DPEHPK3PXP"
        "&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30"
    )
    p = uri.OtpParams("hotp", "", "bob", SECRET, "SHA512", 8, counter=7)
    assert uri.build(p) == ("otpauth://hotp/bob?secret=JBSWY3DPEHPK3PXP&algorithm=SHA512&digits=8&counter=7")
    p = uri.OtpParams("totp", "Société", "a+b c/d?e&f=g#h", SECRET, period=60)
    built = uri.build(p)
    assert "Soci%C3%A9t%C3%A9:a%2Bb%20c%2Fd%3Fe%26f%3Dg%23h?" in built
    assert uri.parse(built).account == "a+b c/d?e&f=g#h"


def test_build_drops_label_issuer_when_too_long():
    issuer = "é" * 16  # 32 bytes, 96 encoded chars
    account = "è" * 32  # 64 bytes
    p = uri.OtpParams("hotp", issuer, account, bytes(range(64)), "SHA512", 8, counter=2**64 - 1)
    built = uri.build(p)
    assert len(built) <= uri.MAX_URI_LEN
    assert built.startswith("otpauth://hotp/%C3%A8")
    q = uri.parse(built)
    assert (q.issuer, q.account, q.secret, q.counter) == (issuer, account, bytes(range(64)), 2**64 - 1)


def test_pct_encode():
    assert uri.pct_encode("aZ09-._~@") == "aZ09-._~@"
    assert uri.pct_encode(" :/?#[]!$&'()*+,;=%") == (
        "%20%3A%2F%3F%23%5B%5D%21%24%26%27%28%29%2A%2B%2C%3B%3D%25"
    )


# -- property tests ------------------------------------------------------------------

_text_char = st.characters(
    blacklist_categories=("Cs", "Cc", "Cf", "Zl", "Zp"),
    blacklist_characters=":\u061c\ufeff",
)


def _bounded(max_bytes, min_size):
    return (
        st.text(_text_char, min_size=min_size, max_size=max_bytes)
        .map(lambda s: s.strip(" "))
        .filter(lambda s: len(s.encode()) <= max_bytes and len(s) >= min_size)
    )


@given(
    st.sampled_from(["totp", "hotp"]),
    _bounded(32, 0),
    _bounded(64, 1),
    st.binary(min_size=1, max_size=64),
    st.sampled_from(["SHA1", "SHA256", "SHA512"]),
    st.sampled_from([6, 7, 8]),
    st.integers(min_value=15, max_value=300),
    st.integers(min_value=0, max_value=2**64 - 1),
)
def test_build_parse_roundtrip(kind, issuer, account, secret, alg, digits, period, counter):
    p = uri.OtpParams(kind, issuer, account, secret, alg, digits, period, counter)
    built = uri.build(p)
    assert len(built.encode()) <= uri.MAX_URI_LEN
    assert built.isascii()
    q = uri.parse(built)
    for attr in ("kind", "issuer", "account", "secret", "algorithm", "digits", "period", "counter"):
        assert getattr(q, attr) == getattr(p, attr)
    # standard library agrees on the decoding
    parsed = urllib.parse.urlsplit(built)
    assert parsed.scheme == "otpauth" and parsed.netloc == kind
    assert urllib.parse.parse_qs(parsed.query)["secret"] == [base32.encode(secret, pad=False)]


@given(st.text(max_size=600))
def test_parse_never_crashes_on_text(s):
    with contextlib.suppress(InvalidInput):
        uri.parse(s)


@given(st.binary(max_size=600))
def test_parse_never_crashes_on_bytes(b):
    with contextlib.suppress(InvalidInput):
        uri.parse(b"otpauth://totp/" + b)


@given(
    st.lists(
        st.sampled_from(
            [
                "secret=JBSWY3DPEHPK3PXP",
                "issuer=A",
                "digits=7",
                "period=60",
                "counter=3",
                "algorithm=SHA256",
                "x=%",
                "secret=%ZZ",
                "&",
                "=",
                "issuer=%E2%80%AE",
                "digits=99",
            ]
        ),
        max_size=8,
    ),
    st.sampled_from(["totp", "hotp"]),
)
def test_parse_param_soup(parts, kind):
    try:
        p = uri.parse(f"otpauth://{kind}/A:me?" + "&".join(parts))
    except InvalidInput:
        return
    assert p.secret == SECRET
    assert p.issuer == "A"
