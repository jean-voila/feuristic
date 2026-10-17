# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""``otpauth://`` URI codec (Google Authenticator "Key Uri Format").

Accepted subset (normative description: ``docs/protocols/otpauth.md``)::

    otpauth://TYPE/LABEL?PARAMETERS
    TYPE   = "totp" / "hotp"                      (case-insensitive)
    LABEL  = [issuer ":" *" "] account            (percent-encoded UTF-8;
                                                   the ":" may be "%3A")
    PARAMETERS: secret (required, base32), issuer, algorithm
                (SHA1/SHA256/SHA512, case-insensitive), digits (6/7/8),
                period (TOTP, 15..300, default 30),
                counter (HOTP, required, 0..2^64-1)

Validation rules (all violations raise :class:`InvalidInput`):

* the whole URI is at most :data:`MAX_URI_LEN` bytes, contains no control
  character, no fragment (``#``) and is valid UTF-8 (RFC 3629);
* percent-escapes (RFC 3986 §2.1) must be well formed; decoded text must be
  valid UTF-8 without control, bidirectional-override or zero-width
  characters (display spoofing);
* in query values ``+`` means a space (``application/x-www-form-urlencoded``,
  as produced by most web libraries); in the label ``+`` is literal;
* issuer ≤ 32 bytes, account 1..64 bytes (UTF-8, after trimming spaces),
  neither may contain ``:`` (Key Uri Format); decoded secret 1..64 bytes
  (docs/architecture.md §6.3);
* if both the label issuer and the ``issuer`` parameter are present they
  must be identical;
* a known parameter may appear only once; unknown parameters (``image``,
  ``color`` ...) are ignored; ``period`` is ignored for HOTP and ``counter``
  for TOTP.

Secrets shorter than :data:`WEAK_SECRET_LEN` bytes (80 bits) are accepted but
flagged (:attr:`OtpParams.weak_secret`) so that the UI can warn — RFC 4226
§4 R6 requires at least 128 bits and recommends 160.

:func:`build` produces the canonical export form used for QR display
(spec §8.1).
"""

from micropython import const

from ...core import base32
from ...core.errors import InvalidInput
from . import hotp as _hotp
from . import totp as _totp

TOTP = "totp"
HOTP = "hotp"
KINDS = (TOTP, HOTP)

MAX_URI_LEN = const(512)
MAX_ISSUER_LEN = const(32)
MAX_ACCOUNT_LEN = const(64)
MAX_SECRET_LEN = const(64)
WEAK_SECRET_LEN = const(10)  # < 80 bits: UI warning
_MAX_DECIMAL_DIGITS = const(20)

_PREFIX = b"otpauth://"
_UNRESERVED = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~@"
_HEX = "0123456789ABCDEF"
_KNOWN = ("secret", "issuer", "algorithm", "digits", "period", "counter")


# ---------------------------------------------------------------------------
# text validation helpers
# ---------------------------------------------------------------------------


def _forbidden_cp(cp: int) -> bool:
    """Code points refused in displayed text (controls, bidi/zero-width, BOM)."""
    return (
        cp < 0x20
        or 0x7F <= cp <= 0x9F
        or cp == 0x061C
        or 0x200B <= cp <= 0x200F
        or 0x2028 <= cp <= 0x202E
        or 0x2060 <= cp <= 0x206F
        or cp == 0xFEFF
    )


def _check_utf8(data: bytes, allow_controls: bool = False) -> None:
    """Strict UTF-8 validation (RFC 3629 §3/§4: no overlongs, surrogates, > U+10FFFF)."""
    i = 0
    n = len(data)
    while i < n:
        c = data[i]
        if c < 0x80:
            cp = c
            i += 1
        else:
            if 0xC2 <= c <= 0xDF:
                need, cp, lo = 1, c & 0x1F, 0x80
            elif 0xE0 <= c <= 0xEF:
                need, cp, lo = 2, c & 0x0F, 0x800
            elif 0xF0 <= c <= 0xF4:
                need, cp, lo = 3, c & 0x07, 0x10000
            else:
                raise InvalidInput("invalid UTF-8")
            if i + need >= n:
                raise InvalidInput("truncated UTF-8")
            for k in range(1, need + 1):
                cc = data[i + k]
                if cc & 0xC0 != 0x80:
                    raise InvalidInput("invalid UTF-8")
                cp = (cp << 6) | (cc & 0x3F)
            if cp < lo or cp > 0x10FFFF or 0xD800 <= cp <= 0xDFFF:
                raise InvalidInput("invalid UTF-8")
            i += need + 1
        if not allow_controls and _forbidden_cp(cp):
            raise InvalidInput("forbidden character")


def _hexval(c: int) -> int:
    if 0x30 <= c <= 0x39:
        return c - 0x30
    if 0x41 <= c <= 0x46:
        return c - 0x37
    if 0x61 <= c <= 0x66:
        return c - 0x57
    return -1


def _pct_decode(data: bytes, plus_is_space: bool) -> bytes:
    """RFC 3986 §2.1 percent-decoding (strict: malformed escapes are errors)."""
    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        c = data[i]
        if c == 0x25:  # '%'
            if i + 2 >= n:
                raise InvalidInput("truncated percent-escape")
            hi = _hexval(data[i + 1])
            lo = _hexval(data[i + 2])
            if hi < 0 or lo < 0:
                raise InvalidInput("invalid percent-escape")
            out.append((hi << 4) | lo)
            i += 3
        elif c == 0x2B and plus_is_space:  # '+'
            out.append(0x20)
            i += 1
        else:
            out.append(c)
            i += 1
    return bytes(out)


def _decode_text(data: bytes, plus_is_space: bool) -> str:
    raw = _pct_decode(data, plus_is_space)
    _check_utf8(raw)
    return raw.decode()


def _ascii_lower(data: bytes) -> bytes:
    return bytes(c + 32 if 0x41 <= c <= 0x5A else c for c in data)


def _parse_uint(data: bytes, field: str) -> int:
    if not 1 <= len(data) <= _MAX_DECIMAL_DIGITS:
        raise InvalidInput(field)
    v = 0
    for c in data:
        if not 0x30 <= c <= 0x39:
            raise InvalidInput(field)
        v = v * 10 + (c - 0x30)
    return v


def _trim_spaces(s: str) -> str:
    return s.strip(" ")


def check_issuer(issuer: str) -> str:
    """Validate an issuer (may be empty). Returns it unchanged."""
    if not isinstance(issuer, str):
        raise InvalidInput("issuer")
    raw = issuer.encode()
    if len(raw) > MAX_ISSUER_LEN:
        raise InvalidInput("issuer too long")
    _check_utf8(raw)
    if ":" in issuer:
        raise InvalidInput("issuer contains ':'")
    if issuer != _trim_spaces(issuer):
        raise InvalidInput("issuer has surrounding spaces")
    return issuer


def check_account(account: str) -> str:
    """Validate an account name (1..64 bytes). Returns it unchanged."""
    if not isinstance(account, str):
        raise InvalidInput("account")
    raw = account.encode()
    if not 1 <= len(raw) <= MAX_ACCOUNT_LEN:
        raise InvalidInput("account length")
    _check_utf8(raw)
    if ":" in account:
        raise InvalidInput("account contains ':'")
    if account != _trim_spaces(account):
        raise InvalidInput("account has surrounding spaces")
    return account


# ---------------------------------------------------------------------------
# parameters object
# ---------------------------------------------------------------------------


class OtpParams:
    """A validated OTP account description (from a URI, a backup or the UI).

    ``period`` is ``None`` for HOTP; ``counter`` is ``None`` for TOTP.
    The constructor validates every field and raises :class:`InvalidInput`.
    """

    def __init__(
        self,
        kind: str,
        issuer: str,
        account: str,
        secret,
        algorithm: str = _hotp.SHA1,
        digits: int = 6,
        period=None,
        counter=None,
    ) -> None:
        if kind not in KINDS:
            raise InvalidInput("kind")
        check_issuer(issuer)
        check_account(account)
        if not isinstance(secret, (bytes, bytearray)) or not 1 <= len(secret) <= MAX_SECRET_LEN:
            raise InvalidInput("secret length")
        _hotp.check_params(secret, digits, algorithm)
        if kind == TOTP:
            if period is None:
                period = _totp.DEFAULT_PERIOD
            _totp.check_period(period)
            counter = None
        else:
            if isinstance(counter, bool) or not isinstance(counter, int):
                raise InvalidInput("counter")
            if not 0 <= counter <= _hotp.MAX_COUNTER:
                raise InvalidInput("counter")
            period = None
        self.kind = kind
        self.issuer = issuer
        self.account = account
        self.secret = bytes(secret)
        self.algorithm = algorithm
        self.digits = digits
        self.period = period
        self.counter = counter

    @property
    def weak_secret(self) -> bool:
        """True if the secret is shorter than 80 bits (show a UI warning)."""
        return len(self.secret) < WEAK_SECRET_LEN

    def label(self) -> str:
        """Human-readable ``"Issuer: account"`` (or just the account)."""
        return label_of(self.issuer, self.account)

    def __repr__(self) -> str:  # never print the secret
        return f"OtpParams({self.kind!r}, {self.issuer!r}, {self.account!r})"


def label_of(issuer: str, account: str) -> str:
    if issuer:
        return issuer + ": " + account
    return account


# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------


def parse(uri) -> OtpParams:
    """Parse and validate an ``otpauth://`` URI (``str`` or bytes-like)."""
    if isinstance(uri, str):
        if len(uri) > MAX_URI_LEN:
            raise InvalidInput("URI too long")
        raw = uri.encode()
    elif isinstance(uri, (bytes, bytearray, memoryview)):
        if len(uri) > MAX_URI_LEN:
            raise InvalidInput("URI too long")
        raw = bytes(uri)
    else:
        raise InvalidInput("URI type")
    if len(raw) > MAX_URI_LEN:
        raise InvalidInput("URI too long")
    # raw text: valid UTF-8, no control characters (raw spaces are tolerated)
    _check_utf8(raw)
    if raw.find(b"#") >= 0:
        raise InvalidInput("URI fragment not supported")
    if _ascii_lower(raw[: len(_PREFIX)]) != _PREFIX:
        raise InvalidInput("not an otpauth URI")
    rest = raw[len(_PREFIX) :]

    slash = rest.find(b"/")
    if slash < 0:
        raise InvalidInput("missing label")
    kind_raw = _ascii_lower(rest[:slash])
    if kind_raw == b"totp":
        kind = TOTP
    elif kind_raw == b"hotp":
        kind = HOTP
    else:
        raise InvalidInput("unsupported OTP type")
    rest = rest[slash + 1 :]
    q = rest.find(b"?")
    if q < 0:
        raise InvalidInput("missing parameters")
    label_raw = rest[:q]
    query_raw = rest[q + 1 :]

    # -- label ---------------------------------------------------------------
    label = _decode_text(label_raw, False)
    colon = label.find(":")
    if colon >= 0:
        label_issuer = _trim_spaces(label[:colon])
        account = _trim_spaces(label[colon + 1 :])
    else:
        label_issuer = ""
        account = _trim_spaces(label)

    # -- parameters ----------------------------------------------------------
    values = {}
    for part in query_raw.split(b"&"):
        if not part:
            continue
        eq = part.find(b"=")
        name = _ascii_lower(part if eq < 0 else part[:eq])
        try:
            name_s = name.decode()
        except UnicodeError:  # pragma: no cover - raw already validated as UTF-8
            continue
        if name_s not in _KNOWN:
            continue  # unknown parameters are ignored (image=, color=, ...)
        if eq < 0:
            raise InvalidInput("parameter without value")
        if name_s in values:
            raise InvalidInput("duplicate parameter")
        values[name_s] = part[eq + 1 :]

    if "secret" not in values:
        raise InvalidInput("missing secret")
    secret_text = _pct_decode(values["secret"], True)
    secret = base32.decode(secret_text, MAX_SECRET_LEN, strict=False, max_input=MAX_URI_LEN)

    issuer = label_issuer
    if "issuer" in values:
        param_issuer = _trim_spaces(_decode_text(values["issuer"], True))
        if param_issuer:
            if label_issuer and param_issuer != label_issuer:
                raise InvalidInput("issuer mismatch")
            issuer = param_issuer

    algorithm = _hotp.SHA1
    if "algorithm" in values:
        alg = _ascii_lower(_pct_decode(values["algorithm"], True))
        if alg == b"sha1":
            algorithm = _hotp.SHA1
        elif alg == b"sha256":
            algorithm = _hotp.SHA256
        elif alg == b"sha512":
            algorithm = _hotp.SHA512
        else:
            raise InvalidInput("unsupported algorithm")

    digits = 6
    if "digits" in values:
        digits = _parse_uint(values["digits"], "digits")

    period = None
    counter = None
    if kind == TOTP:
        if "period" in values:
            period = _parse_uint(values["period"], "period")
    else:
        if "counter" not in values:
            raise InvalidInput("missing counter")
        counter = _parse_uint(values["counter"], "counter")

    return OtpParams(kind, issuer, account, secret, algorithm, digits, period, counter)


# ---------------------------------------------------------------------------
# building
# ---------------------------------------------------------------------------


def pct_encode(text: str) -> str:
    """Percent-encode UTF-8 ``text``; keeps RFC 3986 unreserved characters and ``@``."""
    out = []
    for c in text.encode():
        if _UNRESERVED.find(bytes((c,))) >= 0:
            out.append(chr(c))
        else:
            out.append("%" + _HEX[c >> 4] + _HEX[c & 0x0F])
    return "".join(out)


def build(params: OtpParams) -> str:
    """Canonical ``otpauth://`` URI for ``params`` (spec §8.1 QR export).

    Form: ``otpauth://TYPE/[ISSUER:]ACCOUNT?secret=B32&[issuer=ISSUER&]
    algorithm=ALG&digits=D&(period=P|counter=C)`` with the secret in
    unpadded upper-case base32 and every other character than RFC 3986
    unreserved ones and ``@`` percent-encoded (``%XX``, upper-case hex).
    If the result would exceed :data:`MAX_URI_LEN` (only possible with
    very long non-ASCII names) the issuer prefix of the label is omitted —
    the ``issuer`` parameter, which takes precedence in every reader, is kept.
    """
    issuer_enc = pct_encode(params.issuer) if params.issuer else ""
    account_enc = pct_encode(params.account)
    query = "secret=" + base32.encode(params.secret, pad=False)
    if issuer_enc:
        query += "&issuer=" + issuer_enc
    query += "&algorithm=" + params.algorithm + "&digits=" + str(params.digits)
    if params.kind == TOTP:
        query += "&period=" + str(params.period)
    else:
        query += "&counter=" + str(params.counter)
    head = "otpauth://" + params.kind + "/"
    uri = head + (issuer_enc + ":" if issuer_enc else "") + account_enc + "?" + query
    if len(uri) > MAX_URI_LEN:
        uri = head + account_enc + "?" + query
        if len(uri) > MAX_URI_LEN:  # pragma: no cover - impossible with the field caps
            raise InvalidInput("URI too long")
    return uri
