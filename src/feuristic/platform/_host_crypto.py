# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Host (CPython) crypto backend built on the ``cryptography`` package.

Never imported on the device. Mirrors the semantics of the firmware backend
exactly, including error behaviour, so the test-suite exercises the same
contracts the firmware relies on.
"""

import hashlib
import hmac as _hmac
import os

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric import x25519 as _cx25519
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def random_bytes(n):
    return os.urandom(n)


def sha256(data):
    return hashlib.sha256(bytes(data)).digest()


def sha512(data):
    return hashlib.sha512(bytes(data)).digest()


class Sha256:
    def __init__(self, data=b""):
        self._h = hashlib.sha256(bytes(data))

    def update(self, data):
        self._h.update(bytes(data))

    def digest(self):
        return self._h.digest()


def hmac(alg, key, msg):
    return _hmac.new(bytes(key), bytes(msg), alg).digest()


class Pbkdf2Sha256:
    """Incremental PBKDF2 (single 32-byte block), mirrors trezor.crypto.pbkdf2."""

    def __init__(self, password, salt):
        self._prf = _hmac.new(bytes(password), digestmod="sha256")
        # trezor-crypto computes U1 in Init and marks it as "first"
        self._u = self._mac(bytes(salt) + b"\x00\x00\x00\x01")
        self._t = int.from_bytes(self._u, "big")
        self._first = 1

    def _mac(self, data):
        h = self._prf.copy()
        h.update(data)
        return h.digest()

    def update(self, iterations):
        # Mirrors pbkdf2_hmac_sha256_Update: the first call performs
        # iterations-1 rounds (U1 was computed in Init), later calls perform
        # exactly `iterations` rounds.
        for _ in range(self._first, iterations):
            self._u = self._mac(self._u)
            self._t ^= int.from_bytes(self._u, "big")
        self._first = 0

    def key(self):
        return self._t.to_bytes(32, "big")


def gcm_encrypt(key, nonce, plaintext, aad):
    out = AESGCM(bytes(key)).encrypt(bytes(nonce), bytes(plaintext), bytes(aad) or None)
    return out[:-16], out[-16:]


def gcm_decrypt(key, nonce, ciphertext, tag, aad):
    from .crypto import AuthenticationError

    try:
        return AESGCM(bytes(key)).decrypt(bytes(nonce), bytes(ciphertext) + bytes(tag), bytes(aad) or None)
    except InvalidTag:
        raise AuthenticationError from None


def cbc(key, iv, data, encrypt):
    c = Cipher(algorithms.AES(bytes(key)), modes.CBC(bytes(iv)))
    ctx = c.encryptor() if encrypt else c.decryptor()
    return ctx.update(bytes(data)) + ctx.finalize()


def ecb(key, block, encrypt):
    c = Cipher(algorithms.AES(bytes(key)), modes.ECB())  # noqa: S305 - single-block primitive
    ctx = c.encryptor() if encrypt else c.decryptor()
    return ctx.update(bytes(block)) + ctx.finalize()


def _p256_priv(sk):
    return ec.derive_private_key(int.from_bytes(sk, "big"), ec.SECP256R1())


def p256_public(sk):
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return _p256_priv(sk).public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def p256_sign_digest(sk, digest):
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

    der = _p256_priv(sk).sign(bytes(digest), ec.ECDSA(Prehashed(hashes.SHA256())))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def p256_verify_digest(pk, sig_rs, digest):
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

    try:
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes(pk))
        der = encode_dss_signature(int.from_bytes(sig_rs[:32], "big"), int.from_bytes(sig_rs[32:], "big"))
        pub.verify(der, bytes(digest), ec.ECDSA(Prehashed(hashes.SHA256())))
        return True
    except (InvalidSignature, ValueError):
        return False


def p256_ecdh(sk, peer_pk):
    from .crypto import CryptoError

    try:
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes(peer_pk))
    except ValueError:
        raise CryptoError("P-256 invalid point") from None
    return _p256_priv(sk).exchange(ec.ECDH(), pub)


def ed25519_public(seed):
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return (
        ed25519.Ed25519PrivateKey.from_private_bytes(bytes(seed))
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )


def ed25519_sign(seed, msg):
    return ed25519.Ed25519PrivateKey.from_private_bytes(bytes(seed)).sign(bytes(msg))


def ed25519_verify(pk, sig, msg):
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(bytes(pk)).verify(bytes(sig), bytes(msg))
        return True
    except (InvalidSignature, ValueError):
        return False


def x25519_public(sk):
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return (
        _cx25519.X25519PrivateKey.from_private_bytes(bytes(sk))
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )


def x25519(sk, peer_pk):
    priv = _cx25519.X25519PrivateKey.from_private_bytes(bytes(sk))
    try:
        return priv.exchange(_cx25519.X25519PublicKey.from_public_bytes(bytes(peer_pk)))
    except ValueError:
        # cryptography rejects all-zero results; mirror device behaviour (zeros)
        return bytes(32)


def _i(b):
    return int.from_bytes(b, "big")


def rsa_complete(p, q, e):
    p_i, q_i = _i(p), _i(q)
    n = p_i * q_i
    phi = (p_i - 1) * (q_i - 1)
    d = pow(e, -1, phi)
    size = (n.bit_length() + 7) // 8
    half = (size + 1) // 2
    return (
        n.to_bytes(size, "big"),
        (d % (p_i - 1)).to_bytes(half, "big"),
        (d % (q_i - 1)).to_bytes(half, "big"),
        pow(q_i, -1, p_i).to_bytes(half, "big"),
    )


def rsa_private(key, block):
    p, q = _i(key.p), _i(key.q)
    priv = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=pow(key.e, -1, (p - 1) * (q - 1)),
        dmp1=_i(key.dp),
        dmq1=_i(key.dq),
        iqmp=_i(key.qinv),
        public_numbers=rsa.RSAPublicNumbers(key.e, p * q),
    )
    d = priv.d
    n = p * q
    return pow(_i(block), d, n).to_bytes(len(key.n), "big")


def rsa_public(n, e, block):
    return pow(_i(block), e, _i(n)).to_bytes(len(n), "big")


def modpow(base, exp, mod):
    return pow(_i(base), _i(exp), _i(mod)).to_bytes(len(mod), "big")
