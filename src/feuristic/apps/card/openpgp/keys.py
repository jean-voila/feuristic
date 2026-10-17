# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""OpenPGP card key algorithms: attributes, generation, public key DOs,
private operations and OpenPGP v4 fingerprints.

Supported algorithm attributes (OpenPGP Card 3.4 §4.4.3.9):

* ``16 2B 06 01 04 01 DA 47 0F 01`` — EdDSA Ed25519 (signature, authentication)
* ``12 2B 06 01 04 01 97 55 01 05 01`` — ECDH Curve25519 (decryption)
* ``01 08 00 00 xx 00`` — RSA-2048, e = 65537 (any role; only when
  :mod:`feuristic.core.rsa` is available)

Public key encodings in DO ``7F49`` follow what GnuPG's scdaemon expects
from OpenPGP 3.x cards (``app-openpgp.c: ecc_read_pubkey``): tag ``86``
carries the **raw 32-byte** public key (Ed25519 point; X25519 u-coordinate
in native little-endian order) *without* the ``0x40`` prefix — GnuPG adds
the prefix itself for curves flagged with the DJB tweak. RSA uses ``81``
(modulus) and ``82`` (exponent).
"""

from micropython import const

from ....core import tlv
from ....core.errors import InvalidInput
from ....platform import crypto
from . import const as pgp

KIND_NONE = None


def rsa_module():
    """Return :mod:`feuristic.core.rsa` if available (else ``None``)."""
    try:
        from ....core import rsa as _rsa
    except ImportError:
        return None
    if not hasattr(_rsa, "generate"):
        return None
    return _rsa


def rsa_available() -> bool:
    return rsa_module() is not None


def parse_attr(role: int, attr) -> str:
    """Return the canonical key kind for ``attr`` in ``role`` or raise.

    Raises :class:`InvalidInput` for unsupported attributes.
    """
    attr = bytes(attr)
    if role in (pgp.SIG, pgp.AUT):
        if attr in (pgp.ATTR_ED25519, pgp.ATTR_ED25519 + b"\xff"):
            return pgp.KIND_ED25519
    elif role == pgp.DEC and attr in (pgp.ATTR_X25519, pgp.ATTR_X25519 + b"\xff"):
        return pgp.KIND_X25519
    if len(attr) in (5, 6) and attr[0] == pgp.ALGO_RSA:
        nbits = (attr[1] << 8) | attr[2]
        ebits = (attr[3] << 8) | attr[4]
        fmt = attr[5] if len(attr) == 6 else 0
        if nbits == pgp.RSA_BITS and 17 <= ebits <= 32 and fmt <= 3 and rsa_available():
            return pgp.KIND_RSA2048
    raise InvalidInput("unsupported algorithm attributes")


def canonical_attr(kind: str) -> bytes:
    if kind == pgp.KIND_ED25519:
        return pgp.ATTR_ED25519
    if kind == pgp.KIND_X25519:
        return pgp.ATTR_X25519
    if kind == pgp.KIND_RSA2048:
        return pgp.ATTR_RSA2048
    raise InvalidInput("kind")


def kind_of(attr) -> str:
    """Key kind of stored (canonical) attributes."""
    attr = bytes(attr)
    if attr == pgp.ATTR_ED25519:
        return pgp.KIND_ED25519
    if attr == pgp.ATTR_X25519:
        return pgp.KIND_X25519
    if attr == pgp.ATTR_RSA2048:
        return pgp.KIND_RSA2048
    raise InvalidInput("stored attributes")


def display_name(kind: str) -> str:
    if kind == pgp.KIND_ED25519:
        return "Ed25519"
    if kind == pgp.KIND_X25519:
        return "Curve25519"
    if kind == pgp.KIND_RSA2048:
        return "RSA-2048"
    return "?"


def secret_len(kind: str) -> int:
    if kind == pgp.KIND_RSA2048:
        return 2 * (pgp.RSA_BYTES // 2)
    return 32


def check_secret(kind: str, secret) -> None:
    """Validate the stored secret encoding of a key (lengths, RSA modulus)."""
    if not isinstance(secret, (bytes, bytearray)) or len(secret) != secret_len(kind):
        raise InvalidInput("key secret length")
    if kind == pgp.KIND_RSA2048:
        key = rsa_key(secret)
        n = key.n
        if len(n) != pgp.RSA_BYTES or not n[0] & 0x80:
            raise InvalidInput("RSA modulus size")


def rsa_key(secret):
    """``p || q`` (128 + 128 bytes) → completed :class:`RsaKey`."""
    half = len(secret) // 2
    key = crypto.RsaKey(bytes(secret[:half]), bytes(secret[half:]), pgp.RSA_E)
    p = int.from_bytes(key.p, "big")
    q = int.from_bytes(key.q, "big")
    if p < 3 or q < 3 or p == q or not p & 1 or not q & 1:
        raise InvalidInput("RSA primes")
    crypto.rsa_complete(key)
    return key


async def generate(kind: str, yield_fn=None, progress=None) -> bytes:
    """Generate a fresh secret for ``kind`` (strong RNG)."""
    if kind in (pgp.KIND_ED25519, pgp.KIND_X25519):
        return crypto.random_bytes(32)
    if kind == pgp.KIND_RSA2048:
        mod = rsa_module()
        if mod is None:
            raise InvalidInput("RSA not available")
        key = await mod.generate(bits=pgp.RSA_BITS, e=pgp.RSA_E, progress=progress, yield_fn=yield_fn)
        p = bytes(key.p)
        q = bytes(key.q)
        half = pgp.RSA_BYTES // 2
        if len(p) > half or len(q) > half:
            raise InvalidInput("RSA prime size")
        return bytes(half - len(p)) + p + bytes(half - len(q)) + q
    raise InvalidInput("kind")


def public_key(kind: str, secret) -> bytes:
    """Ed25519/X25519: 32-byte public key; RSA: modulus ``n`` (256 bytes)."""
    if kind == pgp.KIND_ED25519:
        return crypto.ed25519_public(bytes(secret))
    if kind == pgp.KIND_X25519:
        return crypto.x25519_public(bytes(secret))
    if kind == pgp.KIND_RSA2048:
        return rsa_key(secret).n
    raise InvalidInput("kind")


def public_key_do(kind: str, pub: bytes) -> bytes:
    """DO ``7F49`` (public key template, §7.2.14)."""
    if kind == pgp.KIND_RSA2048:
        body = tlv.build(0x81, pub) + tlv.build(0x82, pgp.RSA_E.to_bytes(3, "big"))
    else:
        body = tlv.build(0x86, pub)
    return tlv.build(0x7F49, body)


def ed25519_sign(secret, data) -> bytes:
    return crypto.ed25519_sign(bytes(secret), bytes(data))


def x25519_shared(secret, peer) -> bytes:
    return crypto.x25519(bytes(secret), bytes(peer))


# --- PKCS#1 v1.5 (RFC 8017 §8.2, §7.2) ---------------------------------------------

_PKCS1_MIN_PAD = const(8)


def pkcs1v15_sign_pad(digest_info, k: int) -> bytes:
    mod = rsa_module()
    if mod is not None and hasattr(mod, "pkcs1v15_sign_pad"):
        return bytes(mod.pkcs1v15_sign_pad(digest_info, k))
    digest_info = bytes(digest_info)
    ps = k - 3 - len(digest_info)
    if ps < _PKCS1_MIN_PAD:
        raise InvalidInput("DigestInfo too long")
    return b"\x00\x01" + b"\xff" * ps + b"\x00" + digest_info


def pkcs1v15_decrypt_unpad(em) -> bytes:
    """Decode EME-PKCS1-v1_5; raise InvalidInput (single error) on failure."""
    mod = rsa_module()
    if mod is not None and hasattr(mod, "pkcs1v15_decrypt_unpad"):
        out = mod.pkcs1v15_decrypt_unpad(em)
        if out is None:
            raise InvalidInput("decryption error")
        return bytes(out)
    em = bytes(em)
    # branch-light scan: always walk the whole block
    bad = em[0] | (em[1] ^ 0x02)
    sep = 0
    for i in range(2, len(em)):
        is_zero = 1 if em[i] == 0 else 0
        first = is_zero & (1 if sep == 0 else 0)
        sep = sep | (i * first)
    if bad or sep == 0 or sep < 2 + _PKCS1_MIN_PAD:
        raise InvalidInput("decryption error")
    return em[sep + 1 :]


def rsa_sign(secret, digest_info) -> bytes:
    key = rsa_key(secret)
    em = pkcs1v15_sign_pad(digest_info, len(key.n))
    return crypto.rsa_private(key, em)


def rsa_decrypt(secret, cryptogram) -> bytes:
    key = rsa_key(secret)
    if len(cryptogram) != len(key.n):
        raise InvalidInput("cryptogram length")
    em = crypto.rsa_private(key, bytes(cryptogram))
    return pkcs1v15_decrypt_unpad(em)


# --- OpenPGP v4 fingerprints (RFC 4880 §12.2, RFC 6637, draft-ietf-openpgp-crypto-refresh)


def _mpi(value: bytes) -> bytes:
    value = bytes(value)
    i = 0
    while i < len(value) and value[i] == 0:
        i += 1
    value = value[i:]
    if not value:
        return b"\x00\x00"
    top = value[0]
    nbits = 8 * (len(value) - 1)
    while top:
        nbits += 1
        top >>= 1
    return nbits.to_bytes(2, "big") + value


#: KDF parameters GnuPG uses for Curve25519 ECDH keys: SHA-256, AES-128
CV25519_KDF_PARAMS = b"\x03\x01\x08\x07"


def v4_public_body(kind: str, pub: bytes, created: int) -> bytes:
    """Body of a version 4 public-key packet as GnuPG builds it for card keys."""
    head = b"\x04" + (created & 0xFFFFFFFF).to_bytes(4, "big")
    if kind == pgp.KIND_ED25519:
        return (
            head
            + bytes((pgp.ALGO_EDDSA, len(pgp.OID_ED25519)))
            + pgp.OID_ED25519
            + _mpi(b"\x40" + bytes(pub))
        )
    if kind == pgp.KIND_X25519:
        return (
            head
            + bytes((pgp.ALGO_ECDH, len(pgp.OID_CV25519)))
            + pgp.OID_CV25519
            + _mpi(b"\x40" + bytes(pub))
            + CV25519_KDF_PARAMS
        )
    if kind == pgp.KIND_RSA2048:
        return head + bytes((pgp.ALGO_RSA,)) + _mpi(pub) + _mpi(pgp.RSA_E.to_bytes(3, "big"))
    raise InvalidInput("kind")


def v4_fingerprint(kind: str, pub: bytes, created: int) -> bytes:
    """20-byte OpenPGP v4 fingerprint: SHA-1(0x99 || len16 || body)."""
    body = v4_public_body(kind, pub, created)
    return crypto.sha1(b"\x99" + len(body).to_bytes(2, "big") + body)


def format_fingerprint(fpr: bytes) -> str:
    """``"ABCD 1234 ..."`` (10 groups of 4 upper-case hex digits)."""
    h = bytes(fpr).hex().upper()
    return " ".join(h[i : i + 4] for i in range(0, len(h), 4))
