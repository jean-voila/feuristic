# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""PKCS#1 v1.5 helpers of feuristic.core.rsa (RFC 8017), incl. Wycheproof."""

import hashlib
import json
import os

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from feuristic.core import rsa as frsa
from feuristic.core.errors import InvalidInput
from feuristic.platform import crypto

VECTORS = os.path.join(os.path.dirname(__file__), "..", "..", "vectors", "rsa", "wycheproof_rsa.json")
HASHES = {"sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}
HASHLIB = {
    "SHA-256": ("sha256", hashlib.sha256),
    "SHA-384": ("sha384", hashlib.sha384),
    "SHA-512": ("sha512", hashlib.sha512),
}


def _load():
    with open(VECTORS) as f:
        return json.load(f)


def _key(k):
    key = crypto.RsaKey(bytes.fromhex(k["p"]), bytes.fromhex(k["q"]), k["e"])
    crypto.rsa_complete(key)
    assert key.n == bytes.fromhex(k["n"])
    assert key.dp == bytes.fromhex(k["dp"])
    assert key.dq == bytes.fromhex(k["dq"])
    assert key.qinv == bytes.fromhex(k["qinv"])
    return key


@pytest.fixture(scope="module")
def pyca_key():
    return rsa.generate_private_key(65537, 2048)


def _from_pyca(priv):
    nums = priv.private_numbers()
    key = crypto.RsaKey(nums.p.to_bytes(128, "big"), nums.q.to_bytes(128, "big"), 65537)
    crypto.rsa_complete(key)
    return key


# --- DigestInfo / EMSA-PKCS1-v1_5 ------------------------------------------


@pytest.mark.parametrize("name", ["sha256", "sha384", "sha512"])
def test_sign_pad_verifies_with_cryptography(pyca_key, name):
    key = _from_pyca(pyca_key)
    msg = b"feuristic PIV signature"
    digest = hashlib.new(name, msg).digest()
    em = frsa.pkcs1v15_sign_pad(frsa.digest_info(name, digest), len(key.n))
    assert len(em) == 256 and em[:2] == b"\x00\x01"
    sig = crypto.rsa_private(key, em)
    pyca_key.public_key().verify(sig, msg, padding.PKCS1v15(), HASHES[name]())


def test_wycheproof_signature_generation():
    data = _load()
    assert data["sign"], "vectors missing"
    count = 0
    for group in data["sign"]:
        key = _key(group["key"])
        name, fn = HASHLIB[group["sha"]]
        for t in group["tests"]:
            digest = fn(bytes.fromhex(t["msg"])).digest()
            em = frsa.pkcs1v15_sign_pad(frsa.digest_info(name, digest), len(key.n))
            assert crypto.rsa_private(key, em).hex() == t["sig"], t["tcId"]
            count += 1
    assert count >= 30


def test_digest_info_layout():
    di = frsa.digest_info("sha256", bytes(32))
    assert di.hex().startswith("3031300d060960864801650304020105000420")
    assert len(frsa.digest_info("sha384", bytes(48))) == 19 + 48
    assert len(frsa.digest_info("sha512", bytes(64))) == 19 + 64


@pytest.mark.parametrize(
    ("name", "size"),
    [("sha256", 31), ("sha256", 33), ("sha384", 32), ("sha512", 48), ("sha1", 20), ("md5", 16)],
)
def test_digest_info_rejects(name, size):
    with pytest.raises(InvalidInput):
        frsa.digest_info(name, bytes(size))


def test_sign_pad_lengths():
    t = frsa.digest_info("sha512", bytes(64))  # 83 bytes
    em = frsa.pkcs1v15_sign_pad(t, 83 + 11)
    assert em == b"\x00\x01" + b"\xff" * 8 + b"\x00" + t
    with pytest.raises(InvalidInput):
        frsa.pkcs1v15_sign_pad(t, 83 + 10)


# --- RSAES-PKCS1-v1_5 decoding -----------------------------------------------


def test_decrypt_roundtrip_with_cryptography(pyca_key):
    key = _from_pyca(pyca_key)
    for msg in (b"", b"x", b"secret session key 0123456789abcdef", bytes(245)):
        ct = pyca_key.public_key().encrypt(msg, padding.PKCS1v15())
        em = crypto.rsa_private(key, ct)
        assert frsa.pkcs1v15_decrypt_unpad(em, 256) == msg


def test_wycheproof_decryption():
    data = _load()
    seen_valid = seen_invalid = 0
    for group in data["decrypt"]:
        key = _key(group["key"])
        k = len(key.n)
        for t in group["tests"]:
            ct = bytes.fromhex(t["ct"])
            try:
                em = crypto.rsa_private(key, ct)
            except crypto.CryptoError:
                # ciphertext length != k or c >= n: rejected before decoding
                assert t["result"] == "invalid", t["tcId"]
                assert "InvalidCiphertextFormat" in t["flags"] or len(ct) != k, t["tcId"]
                seen_invalid += 1
                continue
            out = frsa.pkcs1v15_decrypt_unpad(em, k)
            if t["result"] == "valid":
                assert out == bytes.fromhex(t["msg"]), t["tcId"]
                seen_valid += 1
            else:
                assert out is None, t["tcId"]
                seen_invalid += 1
    assert seen_valid >= 40 and seen_invalid >= 20


def _em(ps: bytes, msg: bytes, head: bytes = b"\x00\x02") -> bytes:
    return head + ps + b"\x00" + msg


@pytest.mark.parametrize("k", [11, 12, 64, 128, 256])
def test_unpad_boundaries(k):
    # PS of exactly 8 bytes, separator at index 10: valid
    msg = bytes(range(1, k - 10))
    em = _em(b"\x01" * 8, msg)
    assert len(em) == k
    assert frsa.pkcs1v15_decrypt_unpad(em, k) == msg
    # empty message: separator is the last byte
    em = _em(b"\x07" * (k - 3), b"")
    assert frsa.pkcs1v15_decrypt_unpad(em, k) == b""


def test_unpad_rejects_malformed():
    k = 64
    good = _em(b"\xaa" * 20, b"m" * (k - 23))
    assert frsa.pkcs1v15_decrypt_unpad(good, k) == b"m" * (k - 23)
    bad = [
        b"\x01" + good[1:],  # first byte
        b"\x00\x01" + good[2:],  # block type 1
        b"\x00\x00" + good[2:],  # block type 0
        b"\x00\xff" + good[2:],
        _em(b"\xaa" * 7, b"m" * (k - 10)),  # PS too short (7)
        _em(b"", b"m" * (k - 3)),  # no PS
        b"\x00\x02" + b"\xaa" * (k - 2),  # no separator
        b"\x00\x02" + b"\x00" + b"\xaa" * (k - 3),  # separator at index 2
        b"\x00\x02" + b"\xaa" * 5 + b"\x00" + b"\xaa" * (k - 8),  # zero inside PS (idx 7)
        bytes(k),
    ]
    for em in bad:
        assert len(em) == k
        assert frsa.pkcs1v15_decrypt_unpad(em, k) is None, em.hex()
    # length mismatches / too-small moduli
    assert frsa.pkcs1v15_decrypt_unpad(good[:-1], k) is None
    assert frsa.pkcs1v15_decrypt_unpad(good + b"\x00", k) is None
    assert frsa.pkcs1v15_decrypt_unpad(_em(b"\x01" * 7, b""), 10) is None
    assert frsa.pkcs1v15_decrypt_unpad(b"", 0) is None


def test_unpad_accepts_bytearray_and_memoryview():
    em = _em(b"\x05" * 9, b"hello")
    assert frsa.pkcs1v15_decrypt_unpad(bytearray(em), len(em)) == b"hello"
    assert frsa.pkcs1v15_decrypt_unpad(memoryview(em), len(em)) == b"hello"


def test_unpad_second_zero_is_part_of_message():
    em = _em(b"\x09" * 8, b"\x00\x00abc")
    assert frsa.pkcs1v15_decrypt_unpad(em, len(em)) == b"\x00\x00abc"


def test_public_numbers(det_rng):
    data = _load()
    k = data["sign"][0]["key"]
    key = crypto.RsaKey(bytes.fromhex(k["p"]), bytes.fromhex(k["q"]), k["e"])
    n, e = frsa.public_numbers(key)  # completes the key on demand
    assert n == bytes.fromhex(k["n"]) and e == k["e"]
    assert frsa.public_numbers(key) == (n, e)


def test_unpad_default_length():
    """``k`` defaults to len(em) (used by the OpenPGP applet)."""
    em = _em(b"\x11" * 8, b"msg")
    assert frsa.pkcs1v15_decrypt_unpad(em) == b"msg"
    assert frsa.pkcs1v15_decrypt_unpad(_em(b"\x11" * 7, b"msg")) is None
    assert frsa.pkcs1v15_decrypt_unpad(b"\x00\x02" + b"\x11" * 12) is None
    assert frsa.pkcs1v15_decrypt_unpad(b"\x00\x02\x01") is None  # shorter than 11
