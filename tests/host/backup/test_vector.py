# SPDX-License-Identifier: GPL-3.0-only
"""Normative test vector of docs/protocols/backup-format-v1.md §10.

Generated with ``feuristic.platform.testing.deterministic_rng()`` (the
``det_rng`` fixture) and the real 600 000 PBKDF2 iterations. If this test
changes, the document must change with it (and vice versa).
"""

import hashlib

import cbor2
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from feuristic.apps.backup import envelope, frames
from feuristic.core import base45
from feuristic.platform import crypto

from ..aio import run

PASSPHRASE = b"correct horse battery staple"
ITEM = {"type": "example", "v": 1, "label": "Example identity", "secret": bytes(range(32))}
CREATED = 1_800_000_000

SALT = "778f41b9e5a960dacd70a61bbec357cd"
KEY = "147a98dfa786ba474adcba47ff2102b9dc3d15c819dbccee35995bf0098bdc8a"
BACKUP_ID = "ac25714e21b1883d"
NONCE = "015808a7e62817a47192c63c"
AAD = (
    "4645424b010037a701010248ac25714e21b1883d0301041a000927c00550778f41b9e5a960dacd70a61bbec357cd"
    "0601074c015808a7e62817a47192c63c"
)
PLAINTEXT = (
    "a4617601646b696e64686964656e74697479656974656d7381a46176016474797065676578616d706c65656c6162"
    "656c704578616d706c65206964656e74697479667365637265745820000102030405060708090a0b0c0d0e0f1011"
    "12131415161718191a1b1c1d1e1f67637265617465641a6b49d200"
)
CIPHERTEXT = (
    "cdd51a18a6b3aa566c3164c387a68f146aeb03d33c59e3b6c409161690152a662c717bf449dc82ef56f59d7e6389"
    "452b0a1620e6de2744c6452f160b92bd3dcf857af29209cc8e7dbf36f02db9ade254132790ce54c434a196d537f4"
    "17dc24bc604b23779ce8870b91d0a181516a992cd305a8919f6ac2"
)
TAG = "46127862388a5421a52aefc416b3b630"
FRAMES_DENSE = [
    "FB1:EYLQEEUB42AH100200Y*86H8V50R17W50:C0EYLQEEUB42AH4H0FN0900615AU075F+D8N1T:ACW/P/:KA5OM4B7Y0N-0T70A41"
    "F4TM:24GEX2P/0QKD3F3L1OLMUDAXCV6H/3IBNDYL0ES7JZSAZOTZ2U9I9G5$R57UF+D9ZJ0:0",
    "FB1:EYLQEEUB42AH200200K*RPBUC2V0:F-FH%J5*Z2H8TH/4.2P*.5$K1P-NPAQJOFZKIV%PG+FO.65Z59:LDSA305Z3Q8 OBJK/.QR"
    "%UG$RT NKM9K5F$HT K1*GQUFGJLD0U58W0JIIFMDS%8%9FT67RSAR*K0EU6*2K1NUBDM8U",
]
FRAMES_LARGE = [
    "FB1:EYLQEEUB42AH100900Y*86H8V50R17W50:C0EYLQEEUB42AH4H0V$7V0E",
    "FB1:EYLQEEUB42AH200900FN0900615AU075F+D8N1T:ACW/P/:KA5O1K5BE1",
    "FB1:EYLQEEUB42AH300900M4B7Y0N-0T70A41F4TM:24GEX2P/0QKD3O%TYDK",
    "FB1:EYLQEEUB42AH400900F3L1OLMUDAXCV6H/3IBNDYL0ES7JZSAZONP53H9",
    "FB1:EYLQEEUB42AH500900TZ2U9I9G5$R57UF8F9*OGV:A/+JBQCMX8VAV80B",
    "FB1:EYLQEEUB42AH600900HC1774 3SBV8QX8IZ2ZOIS 7F*G/TUXA1IMD5*L",
    "FB1:EYLQEEUB42AH700900R0IZ7OFGUDLNPRS/I2ZDIAWAIT633JE3771B4HI",
    "FB1:EYLQEEUB42AH800900X03:S4 7CYL4S$JB3HNJIZIK7DAHGJLUQ%Y4202",
    "FB1:EYLQEEUB42AH900900/DL+6K9PO3F2YIC.LHIB4BJ5NZOGWMQ768Z683",
]
ENVELOPE = AAD + CIPHERTEXT + TAG


def test_vector_generation(det_rng):
    # random draw order: salt (16), backup id (8), nonce (12)
    salt = crypto.random_bytes(16)
    assert salt.hex() == SALT
    key = run(envelope.derive_key(PASSPHRASE, salt))
    assert bytes(key).hex() == KEY
    bid = crypto.random_bytes(8)
    assert bid.hex() == BACKUP_ID
    env = envelope.seal(key, salt, envelope.KIND_IDENTITY, [ITEM], bid, created=CREATED)
    assert env.hex() == ENVELOPE
    assert len(env) == 197
    assert frames.split(env, bid, "dense") == FRAMES_DENSE
    assert frames.split(env, bid, "large") == FRAMES_LARGE


def test_vector_decrypts_with_feuristic():
    env = bytes.fromhex(ENVELOPE)
    c = run(envelope.open_envelope(env, PASSPHRASE))
    assert c.items == [ITEM] and c.created == CREATED and c.kind == envelope.KIND_IDENTITY
    assert c.backup_id.hex() == BACKUP_ID
    for profile_frames in (FRAMES_DENSE, FRAMES_LARGE):
        r = frames.Reassembler()
        for t in reversed(profile_frames):
            r.add(t)
        assert r.assemble() == env


def test_vector_independent_implementation():
    """Decode the vector with hashlib + cryptography + cbor2 only, following
    the document (no feuristic code), to prove the format is implementable."""
    binary_frames = [base45.decode(t[4:]) for t in FRAMES_DENSE]
    env = b"".join(b[12:-4] for b in sorted(binary_frames, key=lambda b: b[8:10]))
    assert env.hex() == ENVELOPE
    assert env[:5] == b"FEBK\x01"
    hlen = int.from_bytes(env[5:7], "big")
    header = cbor2.loads(env[7 : 7 + hlen])
    assert header == {
        1: 1,
        2: bytes.fromhex(BACKUP_ID),
        3: 1,
        4: 600_000,
        5: bytes.fromhex(SALT),
        6: 1,
        7: bytes.fromhex(NONCE),
    }
    key = hashlib.pbkdf2_hmac("sha256", PASSPHRASE, header[5], header[4], 32)
    assert key.hex() == KEY
    pt = AESGCM(key).decrypt(header[7], env[7 + hlen :], env[: 7 + hlen])
    assert pt.hex() == PLAINTEXT
    assert cbor2.loads(pt) == {"v": 1, "kind": "identity", "items": [ITEM], "created": CREATED}
    assert cbor2.dumps(cbor2.loads(pt), canonical=True) == pt
