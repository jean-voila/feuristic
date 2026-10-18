# SPDX-License-Identifier: GPL-3.0-only
"""Known-answer and contract tests for feuristic.platform.crypto (host backend).

The firmware backend is exercised by the MicroPython tests in tests/upy with
the same vectors, so both backends are held to identical contracts.
"""

import hashlib
import hmac

import pytest
from hypothesis import given
from hypothesis import strategies as st

from feuristic.platform import crypto

# --- SHA-1 (pure Python implementation shared by both backends) -------------


@pytest.mark.parametrize(
    "msg,digest",
    [
        (b"", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        (b"abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
        ),
        (b"a" * 1000, hashlib.sha1(b"a" * 1000).hexdigest()),
    ],
)
def test_sha1_vectors(msg, digest):
    assert crypto.sha1(msg).hex() == digest


@given(st.binary(max_size=300))
def test_sha1_matches_hashlib(data):
    assert crypto.sha1(data) == hashlib.sha1(data).digest()


@given(st.binary(max_size=100), st.binary(max_size=200))
def test_hmac_sha1_matches_stdlib(key, msg):
    assert crypto.hmac_sha1(key, msg) == hmac.new(key, msg, "sha1").digest()


def test_hmac_dispatch_and_rfc2202():
    # RFC 2202 test case 2
    assert crypto.hmac("sha1", b"Jefe", b"what do ya want for nothing?").hex() == (
        "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
    )
    # RFC 4231 test case 2
    assert crypto.hmac("sha256", b"Jefe", b"what do ya want for nothing?").hex() == (
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    )
    assert crypto.hmac("sha512", b"Jefe", b"what do ya want for nothing?")[:8].hex() == "164b7a7bfcf819e2"
    with pytest.raises(ValueError):
        crypto.hmac("md5", b"k", b"m")


# --- HKDF / PBKDF2 -----------------------------------------------------------


def test_hkdf_rfc5869_case1():
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    okm = crypto.hkdf_sha256(ikm, salt, info, 42)
    assert okm.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    )


def test_hkdf_rejects_bad_length():
    with pytest.raises(ValueError):
        crypto.hkdf_sha256(b"k", b"s", b"i", 0)


@pytest.mark.parametrize("iterations", [1, 2, 4096])
def test_pbkdf2_matches_hashlib(iterations):
    expected = hashlib.pbkdf2_hmac("sha256", b"password", b"salt", iterations, 32)
    assert crypto.pbkdf2_hmac_sha256(b"password", b"salt", iterations) == expected


def test_pbkdf2_incremental_equals_oneshot():
    ctx = crypto.Pbkdf2Sha256(b"passphrase", b"0123456789abcdef")
    for _ in range(10):
        ctx.update(100)
    assert ctx.key() == hashlib.pbkdf2_hmac("sha256", b"passphrase", b"0123456789abcdef", 1000, 32)


# --- AES-GCM -----------------------------------------------------------------


def test_gcm_roundtrip_and_tamper():
    key = bytes(range(32))
    nonce = bytes(12)
    ct, tag = crypto.aes256_gcm_encrypt(key, nonce, b"hello world", b"aad")
    assert crypto.aes256_gcm_decrypt(key, nonce, ct, tag, b"aad") == b"hello world"
    bad = bytes([tag[0] ^ 1]) + tag[1:]
    with pytest.raises(crypto.AuthenticationError):
        crypto.aes256_gcm_decrypt(key, nonce, ct, bad, b"aad")
    with pytest.raises(crypto.AuthenticationError):
        crypto.aes256_gcm_decrypt(key, nonce, ct, tag, b"other aad")
    with pytest.raises(crypto.AuthenticationError):
        crypto.aes256_gcm_decrypt(key, nonce, ct, tag[:15], b"aad")


def test_gcm_nist_vector():
    # NIST GCM test vector (AES-256, 96-bit IV, empty plaintext)
    key = bytes(32)
    nonce = bytes(12)
    ct, tag = crypto.aes256_gcm_encrypt(key, nonce, b"")
    assert ct == b""
    assert tag.hex() == "530f8afbc74536b9a963b4f1c4cb738b"


def test_gcm_parameter_checks():
    with pytest.raises(crypto.CryptoError):
        crypto.aes256_gcm_encrypt(bytes(16), bytes(12), b"x")
    with pytest.raises(crypto.CryptoError):
        crypto.aes256_gcm_encrypt(bytes(32), bytes(16), b"x")


def test_cbc_and_ecb():
    key = bytes(range(32))
    iv = bytes(16)
    data = bytes(range(32))
    ct = crypto.aes256_cbc_encrypt(key, iv, data)
    assert crypto.aes256_cbc_decrypt(key, iv, ct) == data
    with pytest.raises(crypto.CryptoError):
        crypto.aes256_cbc_encrypt(key, iv, b"short")
    blk = crypto.aes_ecb_encrypt_block(bytes(24), bytes(16))
    assert crypto.aes_ecb_decrypt_block(bytes(24), blk) == bytes(16)
    # FIPS-197 C.3 (AES-256)
    k = bytes(range(32))
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert crypto.aes_ecb_encrypt_block(k, pt).hex() == "8ea2b7ca516745bfeafc49904b496089"


# --- P-256 -------------------------------------------------------------------


def test_p256_sign_verify_ecdh():
    sk = crypto.p256_generate()
    pk = crypto.p256_public(sk)
    assert len(pk) == 65 and pk[0] == 4
    digest = crypto.sha256(b"message")
    sig = crypto.p256_sign_digest(sk, digest)
    assert len(sig) == 64
    assert crypto.p256_verify_digest(pk, sig, digest)
    assert not crypto.p256_verify_digest(pk, sig, crypto.sha256(b"other"))
    sk2 = crypto.p256_generate()
    pk2 = crypto.p256_public(sk2)
    assert crypto.p256_ecdh(sk, pk2) == crypto.p256_ecdh(sk2, pk)


def test_p256_rejects_invalid():
    with pytest.raises(crypto.CryptoError):
        crypto.p256_public(bytes(32))
    with pytest.raises(crypto.CryptoError):
        crypto.p256_public((crypto.P256_ORDER).to_bytes(32, "big"))
    sk = crypto.p256_generate()
    with pytest.raises(crypto.CryptoError):
        crypto.p256_ecdh(sk, b"\x04" + bytes(64))  # not on curve
    with pytest.raises(crypto.CryptoError):
        crypto.p256_ecdh(sk, b"\x02" + bytes(32))
    with pytest.raises(crypto.CryptoError):
        crypto.p256_sign_digest(sk, b"short")


def test_ecdsa_der_encoding():
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    sig = bytes([0x80] + [1] * 31) + bytes([0] * 31 + [5])
    der = crypto.ecdsa_sig_to_der(sig)
    r, s = decode_dss_signature(der)
    assert r == int.from_bytes(sig[:32], "big")
    assert s == 5


# --- Curve25519 --------------------------------------------------------------


def test_ed25519_rfc8032_test2():
    seed = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
    pk = crypto.ed25519_public(seed)
    assert pk.hex() == "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
    sig = crypto.ed25519_sign(seed, b"\x72")
    assert sig.hex() == (
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    )
    assert crypto.ed25519_verify(pk, sig, b"\x72")
    assert not crypto.ed25519_verify(pk, sig, b"x")
    with pytest.raises(crypto.CryptoError):
        crypto.ed25519_sign(seed, b"")


def test_x25519_rfc7748():
    a = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    b_pub = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    assert crypto.x25519_public(a).hex() == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    assert crypto.x25519(a, b_pub).hex() == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"


def test_x25519_rejects_small_order():
    with pytest.raises(crypto.CryptoError):
        crypto.x25519(bytes(range(32)), bytes(32))


# --- RSA ---------------------------------------------------------------------


def test_rsa_private_public_roundtrip():
    from cryptography.hazmat.primitives.asymmetric import rsa

    priv = rsa.generate_private_key(65537, 2048)
    nums = priv.private_numbers()
    key = crypto.RsaKey(nums.p.to_bytes(128, "big"), nums.q.to_bytes(128, "big"))
    crypto.rsa_complete(key)
    assert int.from_bytes(key.n, "big") == nums.public_numbers.n
    block = (12345678901234567890).to_bytes(256, "big")
    sig = crypto.rsa_private(key, block)
    assert crypto.rsa_public(key.n, 65537, sig) == block
    with pytest.raises(crypto.CryptoError):
        crypto.rsa_private(key, b"\xff" * 256)


# --- misc --------------------------------------------------------------------


def test_ct_equal():
    assert crypto.ct_equal(b"abc", b"abc")
    assert not crypto.ct_equal(b"abc", b"abd")
    assert not crypto.ct_equal(b"abc", b"ab")


def test_random_bytes_bounds_and_override(det_rng):
    a = crypto.random_bytes(16)
    assert len(a) == 16
    with pytest.raises(ValueError):
        crypto.random_bytes(2000)
