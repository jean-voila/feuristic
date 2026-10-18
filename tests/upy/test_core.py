# SPDX-License-Identifier: GPL-3.0-only
"""Core modules on the device MicroPython (real norcow storage of the emulator)."""

from upytest import raises, run, storage_setup, test

from feuristic.core import base32, base45, cbor, counters, store, tlv
from feuristic.core.errors import InvalidInput

H = bytes.fromhex


def drive(coro):
    try:
        while True:
            coro.send(None)
    except StopIteration as e:
        return e.value


@test
def cbor_vectors_and_canonical():
    assert cbor.encode({"a": 1, "b": [2, 3]}).hex() == "a26161016162820203"
    assert cbor.encode(18446744073709551615).hex() == "1bffffffffffffffff"
    assert cbor.decode(H("a201020304")) == {1: 2, 3: 4}
    try:
        cbor.decode(H("1817"), canonical=True)
        raise AssertionError("non-canonical accepted")
    except cbor.CborError:
        pass
    raises(cbor.CborError, cbor.decode, H("9f01ff"))


@test
def tlv_roundtrip():
    data = tlv.build(0x5FC102, b"abc") + tlv.build(0x53, bytes(300))
    assert tlv.parse(data) == [(0x5FC102, b"abc"), (0x53, bytes(300))]
    raises(tlv.TlvError, tlv.parse, H("5383"))


@test
def base32_base45():
    assert base32.decode("MZXW6YTBOI======") == b"foobar"
    assert base32.encode(b"foobar") == "MZXW6YTBOI======"
    assert base45.encode(b"AB") == "BB8"
    assert base45.decode("%69 VD92EX0") == b"Hello!!"
    raises(InvalidInput, base45.decode, "GGW")


@test
def record_store_on_norcow():
    from feuristic.platform import kv

    s = store.RecordStore(0x30, 4, 64, rtype=9)
    s.wipe()
    s.load()
    uid = b"\x01" * 8
    s.put(uid, b"one")
    s.put(uid, b"two")
    s2 = store.RecordStore(0x30, 4, 64, rtype=9)
    s2.load()
    assert s2.get(uid) == b"two"
    assert len(s2) == 1
    s2.wipe()
    assert kv.get(0x30, 0) is None


@test
def redundant_counter_on_norcow():
    c = counters.RedundantCounter(0x30, 0x40, 0x41)
    c.reset()
    assert c.get() == 0
    assert c.increment() == 1
    alloc = counters.NonceAllocator(c, block=4)
    vals = [alloc.allocate() for _ in range(6)]
    assert vals == [1, 2, 3, 4, 5, 6]
    c.reset()


@test
def hotp_totp_vectors():
    from feuristic.apps.otp import hotp, totp

    secret = b"12345678901234567890"
    expected = ["755224", "287082", "359152", "969429", "338314"]
    for i, code in enumerate(expected):
        assert hotp.hotp(secret, i) == code
    assert totp.totp_at(secret, 59, 30, 8)[0] == "94287082"
    s256 = b"12345678901234567890123456789012"
    assert totp.totp_at(s256, 1111111109, 30, 8, "SHA256")[0] == "68084774"


@test
def otpauth_uri():
    from feuristic.apps.otp import uri

    p = uri.parse("otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example")
    assert p.issuer == "Example" and p.account == "alice@google.com"
    assert uri.parse(uri.build(p)).secret == p.secret
    raises(InvalidInput, uri.parse, "otpauth://totp/x?secret=!!!")


@test
def backup_envelope_roundtrip():
    from feuristic.apps.backup import envelope

    salt = bytes(16)
    key = drive(envelope.derive_key(b"correct horse battery", salt, iterations=10))
    env = envelope.seal(key, salt, 1, [{"v": 1, "type": "otp", "x": b"\x00"}], backup_id=bytes(8))
    out = envelope.open_with_key(env, key)
    assert out.items[0]["type"] == "otp"


@test
def apdu_codec():
    from feuristic.apps.card import apdu

    c = apdu.parse(apdu.build(0x00, 0xA4, 0x04, 0x00, H("d27600012401"), 256))
    assert c.ins == 0xA4 and c.data == H("d27600012401") and c.ne == 256
    big = apdu.parse(apdu.build(0x00, 0xDB, 0x3F, 0xFF, bytes(1000)))
    assert big.extended and len(big.data) == 1000


storage_setup()
run()
