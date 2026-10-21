# SPDX-License-Identifier: GPL-3.0-only
"""feuristic.platform.crypto on the firmware backend (trezor-crypto, feuristic_native).

Mirrors tests/host/test_platform/test_crypto.py known-answer vectors.
"""

from upytest import raises, run, test

from feuristic.platform import _backend, crypto

H = bytes.fromhex


@test
def backend_is_firmware():
    assert _backend.FIRMWARE


@test
def authenticate_large_blobs_in_bounded_chunks():
    key, nonce, aad = b"k" * 32, b"n" * 12, b"blob ownership"
    for size in (0, 1, 15, 16, 17, 255, 256, 257, 4070):
        ciphertext, tag = crypto.aes256_gcm_encrypt(key, nonce, b"p" * size, aad)
        view = memoryview(ciphertext)
        assert crypto.aes256_gcm_verify(key, nonce, view, tag, aad) is None
        raises(crypto.AuthenticationError, crypto.aes256_gcm_verify, key, nonce, view, tag, b"wrong")
        changed = bytes((tag[0] ^ 1,)) + tag[1:]
        raises(crypto.AuthenticationError, crypto.aes256_gcm_verify, key, nonce, view, changed, aad)
        arena = bytearray(size + 8)
        arena[size:] = b"TAILTAIL"
        plaintext = crypto.aes256_gcm_decrypt_into(key, nonce, view, tag, arena, aad)
        assert bytes(plaintext) == b"p" * size and arena[size:] == b"TAILTAIL"
        raises(
            crypto.AuthenticationError, crypto.aes256_gcm_decrypt_into, key, nonce, view, changed, arena, aad
        )
        assert not any(arena[:size]) and arena[size:] == b"TAILTAIL"


@test
def sha1_sha256_hmac():
    assert crypto.sha1(b"abc").hex() == "a9993e364706816aba3e25717850c26c9cd0d89d"
    assert crypto.sha256(b"abc").hex() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert crypto.hmac("sha1", b"Jefe", b"what do ya want for nothing?").hex() == (
        "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
    )
    assert crypto.hmac("sha256", b"Jefe", b"what do ya want for nothing?").hex() == (
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    )


@test
def hkdf_and_pbkdf2():
    okm = crypto.hkdf_sha256(H("0b" * 22), H("000102030405060708090a0b0c"), H("f0f1f2f3f4f5f6f7f8f9"), 42)
    assert okm.hex() == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    # RFC 7914 §11 PBKDF2-HMAC-SHA256 vector (1 iteration, 32 bytes)
    k = crypto.pbkdf2_hmac_sha256(b"passwd", b"salt", 1)
    assert k.hex() == "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
    ctx = crypto.Pbkdf2Sha256(b"password", b"salt")
    ctx.update(2048)
    ctx.update(2048)
    assert ctx.key() == crypto.pbkdf2_hmac_sha256(b"password", b"salt", 4096)


@test
def aes_gcm():
    ct, tag = crypto.aes256_gcm_encrypt(bytes(32), bytes(12), b"")
    assert ct == b"" and tag.hex() == "530f8afbc74536b9a963b4f1c4cb738b"
    key = bytes(range(32))
    ct, tag = crypto.aes256_gcm_encrypt(key, bytes(12), b"hello world", b"aad")
    assert crypto.aes256_gcm_decrypt(key, bytes(12), ct, tag, b"aad") == b"hello world"
    bad = bytes([tag[0] ^ 1]) + tag[1:]
    raises(crypto.AuthenticationError, crypto.aes256_gcm_decrypt, key, bytes(12), ct, bad, b"aad")


@test
def aes_ecb_cbc():
    k = bytes(range(32))
    assert crypto.aes_ecb_encrypt_block(k, H("00112233445566778899aabbccddeeff")).hex() == (
        "8ea2b7ca516745bfeafc49904b496089"
    )
    data = bytes(range(32))
    assert crypto.aes256_cbc_decrypt(k, bytes(16), crypto.aes256_cbc_encrypt(k, bytes(16), data)) == data


@test
def p256():
    sk = crypto.p256_generate()
    pk = crypto.p256_public(sk)
    assert len(pk) == 65 and pk[0] == 4
    d = crypto.sha256(b"m")
    sig = crypto.p256_sign_digest(sk, d)
    assert crypto.p256_verify_digest(pk, sig, d)
    assert not crypto.p256_verify_digest(pk, sig, crypto.sha256(b"x"))
    sk2 = crypto.p256_generate()
    assert crypto.p256_ecdh(sk, crypto.p256_public(sk2)) == crypto.p256_ecdh(sk2, pk)
    raises(crypto.CryptoError, crypto.p256_ecdh, sk, b"\x04" + bytes(64))


@test
def curve25519():
    seed = H("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
    pk = crypto.ed25519_public(seed)
    assert pk.hex() == "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
    sig = crypto.ed25519_sign(seed, b"\x72")
    assert sig.hex() == (
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    )
    assert crypto.ed25519_verify(pk, sig, b"\x72")
    assert not crypto.ed25519_verify(pk, sig, b"x")
    raises(crypto.CryptoError, crypto.ed25519_sign, seed, b"")


@test
def rsa_small_keygen_and_ops():
    from feuristic.core import rsa

    def drive(coro):
        try:
            while True:
                coro.send(None)
        except StopIteration as e:
            return e.value

    key = drive(rsa.generate(1024))
    crypto.rsa_complete(key)
    block = bytes(1) + bytes(range(1, 128))
    sig = crypto.rsa_private(key, block)
    assert crypto.rsa_public(key.n, key.e, sig) == block


run()
