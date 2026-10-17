# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Cryptographic primitives facade.

This is the *only* module through which shared feuristic code performs
cryptography. Two backends exist:

* firmware: ``trezor.crypto`` (trezor-crypto) + ``feuristic_native`` (RSA);
* host:     the ``cryptography`` package (used by the CPython test-suite).

All functions take and return ``bytes`` (or ``bytearray``) unless noted.
Elliptic-curve conventions:

* P-256 secret keys are 32-byte big-endian scalars in ``[1, n-1]``; public
  keys are 65-byte uncompressed SEC1 points (``04 || X || Y``).
* Ed25519 secret keys are 32-byte seeds; signatures are 64 bytes.
* X25519 keys are 32-byte little-endian strings as in RFC 7748.
* RSA keys are handled through :class:`RsaKey`.
"""

from micropython import const

from . import _backend

if _backend.FIRMWARE:
    from trezor.crypto import aes as _aes
    from trezor.crypto import hmac as _hmac
    from trezor.crypto import pbkdf2 as _pbkdf2
    from trezor.crypto import random as _random
    from trezor.crypto.curve import curve25519 as _x25519
    from trezor.crypto.curve import ed25519 as _ed25519
    from trezor.crypto.curve import nist256p1 as _p256
    from trezor.crypto.hashlib import sha256 as _sha256
    from trezor.crypto.hashlib import sha512 as _sha512
else:  # pragma: no cover - import side of the host backend
    from . import _host_crypto as _h

P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

SHA1_SIZE = const(20)
SHA256_SIZE = const(32)
SHA512_SIZE = const(64)
GCM_TAG_SIZE = const(16)
GCM_NONCE_SIZE = const(12)


class CryptoError(Exception):
    """Raised on invalid keys, bad parameters or failed authentication."""


class AuthenticationError(CryptoError):
    """AEAD tag (or MAC) verification failed. No plaintext is released."""


# ---------------------------------------------------------------------------
# Randomness
# ---------------------------------------------------------------------------

_test_rng = None  # host-only deterministic override, see platform.testing


def random_bytes(n: int, strong: bool = True) -> bytes:
    """Return ``n`` random bytes.

    ``strong=True`` (default) mixes the MCU TRNG with the secure element RNG
    on the device. Use ``strong=False`` only for non-secret material
    (e.g. per-item IVs), never for keys.
    """
    if n < 0 or n > 1024:
        raise ValueError("random_bytes: 0..1024")
    if _test_rng is not None:
        return _test_rng(n)
    if _backend.FIRMWARE:
        return _random.bytes(n, strong)
    return _h.random_bytes(n)


# ---------------------------------------------------------------------------
# Hashes and MACs
# ---------------------------------------------------------------------------


def sha256(data: bytes = b"") -> bytes:
    if _backend.FIRMWARE:
        return _sha256(data).digest()
    return _h.sha256(data)


def sha512(data: bytes = b"") -> bytes:
    if _backend.FIRMWARE:
        return _sha512(data).digest()
    return _h.sha512(data)


def sha1(data: bytes = b"") -> bytes:
    """SHA-1. Only for HOTP/TOTP (RFC 4226/6238) and OpenPGP v4 fingerprints."""
    from ._sha1 import sha1 as _pysha1

    return _pysha1(data)


class Sha256:
    """Incremental SHA-256."""

    def __init__(self, data: bytes = b"") -> None:
        if _backend.FIRMWARE:
            self._h = _sha256(data)
        else:
            self._h = _h.Sha256(data)

    def update(self, data: bytes) -> None:
        self._h.update(data)

    def digest(self) -> bytes:
        return self._h.digest()


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    if _backend.FIRMWARE:
        return _hmac(_hmac.SHA256, key, msg).digest()
    return _h.hmac("sha256", key, msg)


def hmac_sha512(key: bytes, msg: bytes) -> bytes:
    if _backend.FIRMWARE:
        return _hmac(_hmac.SHA512, key, msg).digest()
    return _h.hmac("sha512", key, msg)


def hmac_sha1(key: bytes, msg: bytes) -> bytes:
    return _generic_hmac(sha1, 64, key, msg)


def hmac(alg: str, key: bytes, msg: bytes) -> bytes:
    """HMAC with ``alg`` in ``("sha1", "sha256", "sha512")``."""
    if alg == "sha1":
        return hmac_sha1(key, msg)
    if alg == "sha256":
        return hmac_sha256(key, msg)
    if alg == "sha512":
        return hmac_sha512(key, msg)
    raise ValueError("unsupported HMAC algorithm")


def _generic_hmac(hash_fn, block_size: int, key: bytes, msg: bytes) -> bytes:
    if len(key) > block_size:
        key = hash_fn(key)
    key = bytes(key) + bytes(block_size - len(key))
    ipad = bytes(b ^ 0x36 for b in key)
    opad = bytes(b ^ 0x5C for b in key)
    return hash_fn(opad + hash_fn(ipad + bytes(msg)))


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF with SHA-256."""
    if length <= 0 or length > 255 * SHA256_SIZE:
        raise ValueError("hkdf length")
    if not salt:
        salt = bytes(SHA256_SIZE)
    prk = hmac_sha256(salt, ikm)
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac_sha256(prk, block + info + bytes((counter,)))
        okm += block
        counter += 1
    return okm[:length]


class Pbkdf2Sha256:
    """Incremental PBKDF2-HMAC-SHA256 producing one 32-byte block.

    ``update(n)`` runs ``n`` more iterations so long derivations (600 000
    iterations for backups) can report progress and keep USB alive.
    """

    def __init__(self, password: bytes, salt: bytes) -> None:
        if _backend.FIRMWARE:
            self._ctx = _pbkdf2(_pbkdf2.HMAC_SHA256, password, salt)
        else:
            self._ctx = _h.Pbkdf2Sha256(password, salt)

    def update(self, iterations: int) -> None:
        self._ctx.update(iterations)

    def key(self) -> bytes:
        return self._ctx.key()[:SHA256_SIZE]


def pbkdf2_hmac_sha256(password: bytes, salt: bytes, iterations: int) -> bytes:
    if iterations < 1:
        raise ValueError("iterations")
    ctx = Pbkdf2Sha256(password, salt)
    ctx.update(iterations)
    return ctx.key()


# ---------------------------------------------------------------------------
# Symmetric ciphers
# ---------------------------------------------------------------------------


def aes256_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> tuple:
    """Return ``(ciphertext, tag)``. ``nonce`` must be 12 bytes and unique per key."""
    _check_gcm(key, nonce)
    if _backend.FIRMWARE:
        from trezor.crypto import aesgcm_encrypt

        ctx = aesgcm_encrypt(key, nonce)
        if aad:
            ctx.auth(aad)
        ct = ctx.encrypt(plaintext)
        return ct, ctx.finish()
    return _h.gcm_encrypt(key, nonce, plaintext, aad)


def aes256_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    """Return the plaintext only if the tag verifies, else raise AuthenticationError."""
    _check_gcm(key, nonce)
    if len(tag) != GCM_TAG_SIZE:
        raise AuthenticationError
    if _backend.FIRMWARE:
        from trezor.crypto import aesgcm_decrypt

        ctx = aesgcm_decrypt(key, nonce)
        if aad:
            ctx.auth(aad)
        pt = bytearray(ciphertext)
        ctx.decrypt_in_place(pt)
        try:
            ctx.finish(tag)  # raises AuthenticationError on mismatch
        except Exception:
            # wipe the speculative plaintext before reporting the failure
            _wipe(pt)
            raise AuthenticationError
        return bytes(pt)
    return _h.gcm_decrypt(key, nonce, ciphertext, tag, aad)


def _check_gcm(key: bytes, nonce: bytes) -> None:
    if len(key) != 32:
        raise CryptoError("AES-256 key must be 32 bytes")
    if len(nonce) != GCM_NONCE_SIZE:
        raise CryptoError("GCM nonce must be 12 bytes")


def aes256_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-256-CBC without padding (``len(data) % 16 == 0``). CTAP PIN protocols."""
    _check_cbc(key, iv, data)
    if _backend.FIRMWARE:
        return _aes(_aes.CBC, key, iv).encrypt(data)
    return _h.cbc(key, iv, data, True)


def aes256_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    _check_cbc(key, iv, data)
    if _backend.FIRMWARE:
        return _aes(_aes.CBC, key, iv).decrypt(data)
    return _h.cbc(key, iv, data, False)


def aes_ecb_encrypt_block(key: bytes, block: bytes) -> bytes:
    """Single-block AES encryption (any AES key size). Used by PIV mgmt-key auth."""
    if len(block) != 16 or len(key) not in (16, 24, 32):
        raise CryptoError("AES block/key size")
    if _backend.FIRMWARE:
        return _aes(_aes.ECB, key).encrypt(block)
    return _h.ecb(key, block, True)


def aes_ecb_decrypt_block(key: bytes, block: bytes) -> bytes:
    if len(block) != 16 or len(key) not in (16, 24, 32):
        raise CryptoError("AES block/key size")
    if _backend.FIRMWARE:
        return _aes(_aes.ECB, key).decrypt(block)
    return _h.ecb(key, block, False)


def _check_cbc(key: bytes, iv: bytes, data: bytes) -> None:
    if len(key) != 32 or len(iv) != 16 or len(data) % 16:
        raise CryptoError("AES-CBC parameters")


# ---------------------------------------------------------------------------
# P-256 (secp256r1)
# ---------------------------------------------------------------------------


def p256_generate() -> bytes:
    """Fresh random secret scalar (32 bytes, strong RNG, rejection sampled)."""
    while True:
        sk = random_bytes(32)
        k = int.from_bytes(sk, "big")
        if 0 < k < P256_ORDER:
            return sk


def p256_public(sk: bytes) -> bytes:
    _check_p256_sk(sk)
    if _backend.FIRMWARE:
        return _p256.publickey(sk, False)
    return _h.p256_public(sk)


def p256_sign_digest(sk: bytes, digest: bytes) -> bytes:
    """ECDSA over a pre-computed digest. Returns raw ``r || s`` (64 bytes)."""
    _check_p256_sk(sk)
    if len(digest) != 32:
        raise CryptoError("P-256 digest must be 32 bytes")
    if _backend.FIRMWARE:
        return _p256.sign(sk, digest, False)[1:]
    return _h.p256_sign_digest(sk, digest)


def p256_verify_digest(pk: bytes, sig_rs: bytes, digest: bytes) -> bool:
    if len(sig_rs) != 64 or len(digest) != 32:
        return False
    if _backend.FIRMWARE:
        try:
            return _p256.verify(pk, b"\x00" + bytes(sig_rs), digest)
        except Exception:
            return False
    return _h.p256_verify_digest(pk, sig_rs, digest)


def p256_ecdh(sk: bytes, peer_pk: bytes) -> bytes:
    """Return the 32-byte X coordinate of ``sk * peer_pk``.

    Raises :class:`CryptoError` if ``peer_pk`` is not a valid uncompressed
    point on the curve.
    """
    _check_p256_sk(sk)
    if len(peer_pk) != 65 or peer_pk[0] != 0x04:
        raise CryptoError("P-256 point encoding")
    if _backend.FIRMWARE:
        try:
            return _p256.multiply(sk, peer_pk)[1:33]
        except Exception:
            raise CryptoError("P-256 invalid point")
    return _h.p256_ecdh(sk, peer_pk)


def _check_p256_sk(sk: bytes) -> None:
    if len(sk) != 32:
        raise CryptoError("P-256 secret size")
    k = int.from_bytes(sk, "big")
    if not 0 < k < P256_ORDER:
        raise CryptoError("P-256 secret range")


def ecdsa_sig_to_der(sig_rs: bytes) -> bytes:
    """Encode a raw 64-byte ``r || s`` signature as an ASN.1 DER SEQUENCE."""

    def _int(v: bytes) -> bytes:
        v = bytes(v).lstrip(b"\x00") or b"\x00"
        if v[0] & 0x80:
            v = b"\x00" + v
        return b"\x02" + bytes((len(v),)) + v

    body = _int(sig_rs[:32]) + _int(sig_rs[32:])
    return b"\x30" + bytes((len(body),)) + body


# ---------------------------------------------------------------------------
# Curve25519
# ---------------------------------------------------------------------------


def ed25519_public(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise CryptoError("Ed25519 seed size")
    if _backend.FIRMWARE:
        return _ed25519.publickey(seed)
    return _h.ed25519_public(seed)


def ed25519_sign(seed: bytes, msg: bytes) -> bytes:
    if len(seed) != 32:
        raise CryptoError("Ed25519 seed size")
    if _backend.FIRMWARE:
        return _ed25519.sign(seed, msg)
    return _h.ed25519_sign(seed, msg)


def ed25519_verify(pk: bytes, sig: bytes, msg: bytes) -> bool:
    if len(pk) != 32 or len(sig) != 64:
        return False
    if _backend.FIRMWARE:
        try:
            return _ed25519.verify(pk, sig, msg)
        except Exception:
            return False
    return _h.ed25519_verify(pk, sig, msg)


def x25519_public(sk: bytes) -> bytes:
    if len(sk) != 32:
        raise CryptoError("X25519 key size")
    if _backend.FIRMWARE:
        return _x25519.publickey(sk)
    return _h.x25519_public(sk)


def x25519(sk: bytes, peer_pk: bytes) -> bytes:
    """RFC 7748 X25519. Rejects the all-zero shared secret (small-order input)."""
    if len(sk) != 32 or len(peer_pk) != 32:
        raise CryptoError("X25519 key size")
    if _backend.FIRMWARE:
        shared = _x25519.multiply(sk, peer_pk)
    else:
        shared = _h.x25519(sk, peer_pk)
    if not any(shared):
        raise CryptoError("X25519 small-order point")
    return shared


# ---------------------------------------------------------------------------
# RSA (keys generated and used on-device; see feuristic.core.rsa)
# ---------------------------------------------------------------------------


class RsaKey:
    """RSA private key held as CRT components (big-endian byte strings).

    Only ``p``, ``q`` and ``e`` are persisted; the other components are
    recomputed with :func:`rsa_complete`.
    """

    def __init__(self, p: bytes, q: bytes, e: int = 65537) -> None:
        self.p = p
        self.q = q
        self.e = e
        self.n = b""
        self.dp = b""
        self.dq = b""
        self.qinv = b""


def rsa_complete(key: RsaKey) -> RsaKey:
    """Fill ``n``, ``dp``, ``dq`` and ``qinv`` from ``p``, ``q`` and ``e``."""
    if _backend.FIRMWARE:
        import feuristic_native

        n, dp, dq, qinv = feuristic_native.rsa_complete(key.p, key.q, key.e)
    else:
        n, dp, dq, qinv = _h.rsa_complete(key.p, key.q, key.e)
    key.n, key.dp, key.dq, key.qinv = n, dp, dq, qinv
    return key


def rsa_private(key: RsaKey, block: bytes) -> bytes:
    """Raw RSA private operation ``block^d mod n`` (CRT, constant time on device).

    ``block`` must be exactly ``len(n)`` bytes and numerically ``< n``.
    Padding (PKCS#1 v1.5 / PSS / OAEP decoding) is the caller's job.
    """
    if not key.n:
        rsa_complete(key)
    if len(block) != len(key.n) or int.from_bytes(block, "big") >= int.from_bytes(key.n, "big"):
        raise CryptoError("RSA input out of range")
    if _backend.FIRMWARE:
        import feuristic_native

        out = feuristic_native.rsa_private(key.p, key.q, key.dp, key.dq, key.qinv, block)
        if out is None:
            raise CryptoError("RSA private operation failed")
        return out
    return _h.rsa_private(key, block)


def rsa_public(n: bytes, e: int, block: bytes) -> bytes:
    """Raw RSA public operation (used for self-tests / verification)."""
    if _backend.FIRMWARE:
        import feuristic_native

        return feuristic_native.rsa_public(n, e, block)
    return _h.rsa_public(n, e, block)


def rsa_modpow(base: bytes, exp: bytes, mod: bytes) -> bytes:
    """``base^exp mod mod`` for odd ``mod`` (used by the incremental key
    generator; each call is bounded to ~150 ms on a Cortex-M4)."""
    if _backend.FIRMWARE:
        import feuristic_native

        return feuristic_native.modpow(base, exp, mod)
    return _h.modpow(base, exp, mod)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _wipe(buf) -> None:
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0


def ct_equal(a: bytes, b: bytes) -> bool:
    """Constant-time comparison of two byte strings."""
    if len(a) != len(b):
        return False
    acc = 0
    for x, y in zip(a, b):
        acc |= x ^ y
    return acc == 0
