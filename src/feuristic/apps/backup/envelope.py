# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Encrypted backup envelope, format v1 (spec §8.2, §8.3; normative
description in ``docs/protocols/backup-format-v1.md`` §3–§4, rationale in
``docs/adr/0004-backup-envelope.md``).

Binary layout (integers big-endian)::

    offset  size  field
    0       4     magic  "FEBK" (46 45 42 4B)
    4       1     version = 0x01
    5       2     H = length of the header map
    7       H     header: canonical CBOR map {1: kind, 2: backup id,
                  3: kdf, 4: iterations, 5: salt, 6: aead, 7: nonce}
    7+H     n     ciphertext (AES-256-GCM of the canonical CBOR plaintext)
    7+H+n   16    GCM tag (128 bit)

* KDF: ``key = PBKDF2-HMAC-SHA256(passphrase, salt, 600 000, 32)``.
* AEAD: AES-256-GCM, 96-bit random nonce, 128-bit tag,
  ``AAD = envelope[0 : 7+H]`` — magic, version, length and *every* header
  field are authenticated.
* The format is independent of the device and of the hardware revision
  (spec §8.3): only the passphrase and the public header are needed.

Authentication before parsing: the header is the only part interpreted
before the tag is verified; it is bounded (≤ 96 bytes), decoded with the
canonical, depth-limited CBOR decoder and checked against a fixed schema.
The plaintext is decoded (``canonical=True``) and validated **only after**
the tag verified.
"""

from micropython import const

from ...core import cbor
from ...core.errors import InvalidInput
from ...core.secure import wipe
from ...platform import crypto
from . import provider as _provider
from .errors import (
    AuthenticationFailed,
    BackupFormatError,
    PlaintextError,
    UnsupportedParameters,
    UnsupportedVersion,
    WeakPassphrase,
)

MAGIC = b"FEBK"
VERSION = const(1)
PREFIX_LEN = const(7)  # magic(4) | version(1) | header length(2)

KDF_PBKDF2_HMAC_SHA256 = const(1)
AEAD_AES_256_GCM = const(1)

#: PBKDF2 iteration count mandated by spec §8.2. Read at call time so host
#: tests may monkeypatch a lower value for speed; format v1 accepts exactly
#: this value when opening an envelope.
ITERATIONS = 600_000
#: iterations per incremental KDF step (progress / UI / USB keep-alive)
KDF_CHUNK = 4096

SALT_LEN = const(16)
NONCE_LEN = const(12)
TAG_LEN = const(16)
KEY_LEN = const(32)
BACKUP_ID_LEN = const(8)

KIND_IDENTITY = const(1)
KIND_FULL = const(2)
_KIND_NAMES = {KIND_IDENTITY: "identity", KIND_FULL: "full"}

# header map keys
H_KIND = const(1)
H_BACKUP_ID = const(2)
H_KDF = const(3)
H_ITERATIONS = const(4)
H_SALT = const(5)
H_AEAD = const(6)
H_NONCE = const(7)
_HEADER_KEYS = (H_KIND, H_BACKUP_ID, H_KDF, H_ITERATIONS, H_SALT, H_AEAD, H_NONCE)

MAX_HEADER_LEN = const(96)
MAX_ENVELOPE_LEN = const(65536)
#: items per envelope accepted by decoders (the v1 exporter writes exactly 1)
MAX_ITEMS = const(16)
#: identities in one "full" export set
MAX_SET_COUNT = const(1024)
#: CBOR data items allowed in one exported item
MAX_ITEM_CBOR_ITEMS = const(1024)
_MAX_PLAINTEXT_CBOR_ITEMS = const(MAX_ITEM_CBOR_ITEMS * MAX_ITEMS + 32)
_PLAINTEXT_MAX_DEPTH = const(8)
#: largest unix time accepted in "created" (year 2106)
MAX_CREATED = 0xFFFFFFFF

PASSPHRASE_MIN_LEN = const(12)
PASSPHRASE_MAX_LEN = const(128)

#: smallest possible envelope: prefix + minimal header + 1 byte + tag
_MIN_ENVELOPE_LEN = const(PREFIX_LEN + 1 + 1 + TAG_LEN)


# ---------------------------------------------------------------------------
# passphrase policy
# ---------------------------------------------------------------------------


def check_passphrase(passphrase) -> None:
    """Enforce the passphrase policy (spec §8.2; format doc §3.1).

    12..128 bytes, each in ``0x20..0x7E`` (printable ASCII, space allowed):
    the on-device two-button keyboard only offers ASCII, and restricting the
    alphabet guarantees that the same passphrase typed on either hardware
    revision yields the same bytes (no Unicode normalisation issue).
    Must be ``bytes``/``bytearray``. Raises :class:`WeakPassphrase`.
    """
    if not isinstance(passphrase, (bytes, bytearray)):
        raise WeakPassphrase("passphrase must be bytes")
    n = len(passphrase)
    if n < PASSPHRASE_MIN_LEN:
        raise WeakPassphrase("passphrase too short")
    if n > PASSPHRASE_MAX_LEN:
        raise WeakPassphrase("passphrase too long")
    for b in passphrase:
        if b < 0x20 or b > 0x7E:
            raise WeakPassphrase("passphrase must be printable ASCII")


def passphrases_match(a, b) -> bool:
    """Constant-time comparison for the double-entry check of the UI glue."""
    return crypto.ct_equal(bytes(a), bytes(b))


# ---------------------------------------------------------------------------
# key derivation
# ---------------------------------------------------------------------------


async def derive_key(passphrase, salt, progress=None, yield_fn=None, iterations=None) -> bytearray:
    """PBKDF2-HMAC-SHA256(passphrase, salt, ITERATIONS) → 32-byte ``bytearray``.

    Runs incrementally in steps of :data:`KDF_CHUNK` iterations; after each
    step ``progress(done, total)`` is called (sync) and ``await yield_fn()``
    is awaited (both optional) so the firmware can refresh a progress bar
    and service USB. The caller owns the returned buffer and must
    :func:`feuristic.core.secure.wipe` it.
    """
    check_passphrase(passphrase)
    if not isinstance(salt, (bytes, bytearray)) or len(salt) != SALT_LEN:
        raise InvalidInput("salt length")
    total = ITERATIONS if iterations is None else iterations
    if not isinstance(total, int) or total < 1:
        raise InvalidInput("iterations")
    chunk = KDF_CHUNK if KDF_CHUNK > 0 else total
    ctx = crypto.Pbkdf2Sha256(bytes(passphrase), bytes(salt))
    done = 0
    if progress is not None:
        progress(0, total)
    while done < total:
        step = total - done
        step = min(step, chunk)
        # trezor-crypto semantics: the iteration counts of successive
        # update() calls add up to the total (U1 is computed at init)
        ctx.update(step)
        done += step
        if progress is not None:
            progress(done, total)
        if yield_fn is not None and done < total:
            await yield_fn()
    return bytearray(ctx.key())


class KeyCache:
    """Derived keys indexed by salt, for one export or restore session.

    A full export uses one salt for all its envelopes, so a full restore
    runs the 600 000 iterations once. :meth:`wipe` must be called when the
    session ends (keys are kept in ``bytearray`` buffers).
    """

    def __init__(self) -> None:
        self._entries = []  # [(salt bytes, key bytearray)]

    def get(self, salt):
        for s, k in self._entries:
            if crypto.ct_equal(s, bytes(salt)):
                return k
        return None

    def put(self, salt, key) -> None:
        if self.get(salt) is None:
            self._entries.append((bytes(salt), key))

    def __len__(self) -> int:
        return len(self._entries)

    def wipe(self) -> None:
        for _, k in self._entries:
            wipe(k)
        self._entries = []


# ---------------------------------------------------------------------------
# header
# ---------------------------------------------------------------------------


class Header:
    """Parsed (not yet authenticated) envelope header."""

    def __init__(self, kind, backup_id, iterations, salt, nonce, aad) -> None:
        self.kind = kind
        self.backup_id = backup_id
        self.kdf = KDF_PBKDF2_HMAC_SHA256
        self.iterations = iterations
        self.salt = salt
        self.aead = AEAD_AES_256_GCM
        self.nonce = nonce
        #: bytes authenticated as AAD (= prefix + header map)
        self.aad = aad

    @property
    def body_offset(self) -> int:
        return len(self.aad)


def encode_header(kind: int, backup_id: bytes, salt: bytes, nonce: bytes, iterations=None) -> bytes:
    """Return ``magic | version | H | header`` (the AAD of the envelope)."""
    if kind not in _KIND_NAMES:
        raise InvalidInput("kind")
    if len(backup_id) != BACKUP_ID_LEN or len(salt) != SALT_LEN or len(nonce) != NONCE_LEN:
        raise InvalidInput("header field length")
    it = ITERATIONS if iterations is None else iterations
    hdr = cbor.encode(
        {
            H_KIND: kind,
            H_BACKUP_ID: bytes(backup_id),
            H_KDF: KDF_PBKDF2_HMAC_SHA256,
            H_ITERATIONS: it,
            H_SALT: bytes(salt),
            H_AEAD: AEAD_AES_256_GCM,
            H_NONCE: bytes(nonce),
        }
    )
    if len(hdr) > MAX_HEADER_LEN:
        raise InvalidInput("header too long")
    return MAGIC + bytes((VERSION,)) + len(hdr).to_bytes(2, "big") + hdr


def _uint(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def parse_header(envelope) -> Header:
    """Parse and strictly validate the public header (before authentication)."""
    if not isinstance(envelope, (bytes, bytearray, memoryview)):
        raise BackupFormatError("envelope must be bytes")
    n = len(envelope)
    if n > MAX_ENVELOPE_LEN:
        raise BackupFormatError("envelope too long")
    if n < PREFIX_LEN or bytes(envelope[0:4]) != MAGIC:
        raise BackupFormatError("not a feuristic backup")
    if envelope[4] != VERSION:
        raise UnsupportedVersion("unsupported backup version")
    hlen = int.from_bytes(bytes(envelope[5:7]), "big")
    if hlen < 1 or hlen > MAX_HEADER_LEN:
        raise BackupFormatError("header length")
    if n < PREFIX_LEN + hlen + 1 + TAG_LEN:
        raise BackupFormatError("envelope truncated")
    raw = bytes(envelope[PREFIX_LEN : PREFIX_LEN + hlen])
    try:
        h = cbor.decode(raw, canonical=True, max_depth=1, max_items=1 + 2 * len(_HEADER_KEYS))
    except cbor.CborError:
        raise BackupFormatError("header is not canonical CBOR")
    if not isinstance(h, dict) or len(h) != len(_HEADER_KEYS):
        raise BackupFormatError("header fields")
    for k in _HEADER_KEYS:
        if k not in h:
            raise BackupFormatError("header fields")
    kind = h[H_KIND]
    if not _uint(kind) or kind not in _KIND_NAMES:
        raise BackupFormatError("header kind")
    bid = h[H_BACKUP_ID]
    if not isinstance(bid, bytes) or len(bid) != BACKUP_ID_LEN:
        raise BackupFormatError("header backup id")
    if not _uint(h[H_KDF]) or h[H_KDF] != KDF_PBKDF2_HMAC_SHA256:
        raise UnsupportedParameters("kdf")
    it = h[H_ITERATIONS]
    if not _uint(it) or it != ITERATIONS:
        raise UnsupportedParameters("iterations")
    salt = h[H_SALT]
    if not isinstance(salt, bytes) or len(salt) != SALT_LEN:
        raise BackupFormatError("header salt")
    if not _uint(h[H_AEAD]) or h[H_AEAD] != AEAD_AES_256_GCM:
        raise UnsupportedParameters("aead")
    nonce = h[H_NONCE]
    if not isinstance(nonce, bytes) or len(nonce) != NONCE_LEN:
        raise BackupFormatError("header nonce")
    return Header(kind, bid, it, salt, nonce, bytes(envelope[0 : PREFIX_LEN + hlen]))


# ---------------------------------------------------------------------------
# plaintext
# ---------------------------------------------------------------------------


class Contents:
    """Authenticated, schema-validated plaintext of one envelope."""

    def __init__(self, header, kind, items, seq=None, count=None, created=None) -> None:
        self.header = header
        self.kind = kind  # KIND_IDENTITY / KIND_FULL
        self.items = items  # list of item dicts (provider-specific fields)
        self.seq = seq  # 1-based position in a full export set (KIND_FULL)
        self.count = count  # size of the full export set (KIND_FULL)
        self.created = created  # optional unix time (informational only)

    @property
    def backup_id(self) -> bytes:
        return self.header.backup_id


def build_plaintext(kind: int, items, seq=None, count=None, created=None) -> dict:
    """Return the plaintext map (validated with the same rules as on open)."""
    if kind not in _KIND_NAMES:
        raise InvalidInput("kind")
    pt = {"v": 1, "kind": _KIND_NAMES[kind], "items": list(items)}
    if kind == KIND_FULL:
        pt["seq"] = seq
        pt["count"] = count
    elif seq is not None or count is not None:
        raise InvalidInput("seq/count only for full exports")
    if created is not None:
        pt["created"] = created
    try:
        _validate_plaintext(pt, kind)
    except PlaintextError as e:
        raise InvalidInput(str(e))
    return pt


def _validate_plaintext(pt, header_kind: int) -> tuple:
    """Strict v1 schema (format doc §4.2 CDDL). Returns (items, seq, count, created)."""
    if not isinstance(pt, dict):
        raise PlaintextError("plaintext must be a map")
    allowed = ("v", "kind", "items", "seq", "count", "created")
    for k in pt:
        if k not in allowed:
            raise PlaintextError("unknown plaintext field")
    v = pt.get("v")
    if not _uint(v) or v != 1:
        raise PlaintextError("plaintext version")
    kind_name = pt.get("kind")
    if kind_name != _KIND_NAMES.get(header_kind):
        raise PlaintextError("plaintext kind does not match header")
    items = pt.get("items")
    if not isinstance(items, list) or not 1 <= len(items) <= MAX_ITEMS:
        raise PlaintextError("items")
    if header_kind == KIND_IDENTITY and len(items) != 1:
        raise PlaintextError("identity backup must hold one item")
    for it in items:
        try:
            _provider.check_item_common(it)
        except InvalidInput:
            raise PlaintextError("item")
    seq = pt.get("seq")
    count = pt.get("count")
    if header_kind == KIND_FULL:
        if not _uint(count) or not 1 <= count <= MAX_SET_COUNT:
            raise PlaintextError("count")
        if not _uint(seq) or not 1 <= seq <= count:
            raise PlaintextError("seq")
    elif "seq" in pt or "count" in pt:
        raise PlaintextError("seq/count only allowed in full exports")
    created = pt.get("created")
    if "created" in pt and (not _uint(created) or created > MAX_CREATED):
        raise PlaintextError("created")
    return items, seq, count, created


# ---------------------------------------------------------------------------
# seal / open
# ---------------------------------------------------------------------------


def seal(key, salt, kind: int, items, backup_id=None, seq=None, count=None, created=None) -> bytes:
    """Encrypt ``items`` into a complete envelope.

    ``key`` is the 32-byte output of :func:`derive_key` for ``salt``. A fresh
    96-bit nonce is drawn for every call (random draw order: backup id if
    not given, then nonce). Returns the envelope bytes.
    """
    if len(key) != KEY_LEN:
        raise InvalidInput("key length")
    pt = cbor.encode(build_plaintext(kind, items, seq, count, created))
    if backup_id is None:
        backup_id = crypto.random_bytes(BACKUP_ID_LEN)
    nonce = crypto.random_bytes(NONCE_LEN)
    aad = encode_header(kind, backup_id, salt, nonce)
    if len(aad) + len(pt) + TAG_LEN > MAX_ENVELOPE_LEN:
        raise InvalidInput("backup too large")
    ct, tag = crypto.aes256_gcm_encrypt(bytes(key), nonce, pt, aad)
    return aad + ct + tag


def open_with_key(envelope, key, header=None) -> Contents:
    """Authenticate, decrypt and validate ``envelope`` with a derived key.

    Raises :class:`AuthenticationFailed` (wrong passphrase / altered data),
    :class:`BackupFormatError` (bad header) or :class:`PlaintextError`.
    """
    h = parse_header(envelope) if header is None else header
    off = h.body_offset
    ct = bytes(envelope[off : len(envelope) - TAG_LEN])
    tag = bytes(envelope[len(envelope) - TAG_LEN :])
    try:
        pt = crypto.aes256_gcm_decrypt(bytes(key), h.nonce, ct, tag, h.aad)
    except crypto.AuthenticationError:
        raise AuthenticationFailed("authentication failed")
    # --- authenticated from here on ---
    try:
        obj = cbor.decode(
            pt,
            canonical=True,
            max_depth=_PLAINTEXT_MAX_DEPTH,
            max_items=_MAX_PLAINTEXT_CBOR_ITEMS,
        )
    except cbor.CborError:
        raise PlaintextError("plaintext is not canonical CBOR")
    items, seq, count, created = _validate_plaintext(obj, h.kind)
    return Contents(h, h.kind, items, seq, count, created)


async def open_envelope(envelope, passphrase, progress=None, yield_fn=None, cache=None) -> Contents:
    """Parse the header, derive the key (or reuse it from ``cache``) and
    :func:`open_with_key`.

    A newly derived key is stored in ``cache`` only after it authenticated
    the envelope, so a wrong passphrase never poisons the cache; otherwise
    it is wiped."""
    h = parse_header(envelope)
    check_passphrase(passphrase)
    cached = cache.get(h.salt) if cache is not None else None
    if cached is not None:
        return open_with_key(envelope, cached, h)
    key = await derive_key(passphrase, h.salt, progress, yield_fn)
    keep = False
    try:
        contents = open_with_key(envelope, key, h)
        if cache is not None:
            cache.put(h.salt, key)
            keep = True
        return contents
    finally:
        if not keep:
            wipe(key)


def kind_name(kind: int) -> str:
    return _KIND_NAMES.get(kind, "?")
