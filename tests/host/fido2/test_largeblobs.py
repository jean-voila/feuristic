# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""authenticatorLargeBlobs (CTAP 2.1 §6.10)."""

import hashlib

import pytest
from ctap_harness import CDH, make, open_hid
from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.blob import LargeBlobs
from fido2.ctap2.pin import ClientPin, PinProtocolV1, PinProtocolV2

from feuristic.apps.fido2 import largeblobs as lb

ERR = CtapError.ERR
PERM = ClientPin.PERMISSION


def serialize(items) -> bytes:
    data = cbor.encode(items)
    return data + hashlib.sha256(data).digest()[:16]


def expect(code, fn, *a, **kw):
    with pytest.raises(CtapError) as e:
        fn(*a, **kw)
    assert e.value.code == code


def test_empty_array_constant():
    assert serialize([]) == lb.EMPTY_ARRAY
    assert lb.check_integrity(lb.EMPTY_ARRAY)
    assert not lb.check_integrity(b"\x80" + bytes(16))
    assert not lb.check_integrity(b"\x80")


def test_initial_read(ctap2):
    assert LargeBlobs(ctap2).read_blob_array() == []
    assert ctap2.large_blobs(0, get=100) == {1: lb.EMPTY_ARRAY}
    assert ctap2.large_blobs(17, get=100) == {1: b""}
    expect(ERR.INVALID_PARAMETER, ctap2.large_blobs, 18, get=1)


def test_put_get_blob_with_large_blob_key(ctap2):
    att = make(ctap2, rk=True, extensions={"largeBlobKey": True})
    blobs = LargeBlobs(ctap2)
    blobs.put_blob(att.large_blob_key, b"hello world" * 50)
    assert blobs.get_blob(att.large_blob_key) == b"hello world" * 50
    a = ctap2.get_assertion("example.com", CDH, extensions={"largeBlobKey": True})
    assert blobs.get_blob(a.large_blob_key) == b"hello world" * 50
    blobs.delete_blob(att.large_blob_key)
    assert blobs.read_blob_array() == []


@pytest.mark.parametrize("proto_cls", [PinProtocolV1, PinProtocolV2])
def test_write_requires_lbw_token_when_pin_set(ctap2, proto_cls):
    proto = proto_cls()
    c = ClientPin(ctap2, proto)
    c.set_pin("1234")
    with pytest.raises(CtapError) as e:
        LargeBlobs(ctap2).write_blob_array([{1: b"x", 2: b"y" * 12, 3: 1}])
    assert e.value.code == ERR.PUAT_REQUIRED
    tok = c.get_pin_token("1234", PERM.GET_ASSERTION, "example.com")
    with pytest.raises(CtapError) as e:
        LargeBlobs(ctap2, proto, tok).write_blob_array([])
    assert e.value.code == ERR.PIN_AUTH_INVALID
    tok = c.get_pin_token("1234", PERM.LARGE_BLOB_WRITE)
    w = LargeBlobs(ctap2, proto, tok)
    w.write_blob_array([{1: b"a"}])
    w.write_blob_array([{1: b"b"}])  # lbw survives use
    assert LargeBlobs(ctap2).read_blob_array() == [{1: b"b"}]
    # lbw is kept by clearPinUvAuthTokenPermissionsExceptLbw
    tok = c.get_pin_token("1234", PERM.LARGE_BLOB_WRITE | PERM.MAKE_CREDENTIAL, "example.com")
    make(ctap2, rk=True, pin_uv_param=proto.authenticate(tok, CDH), pin_uv_protocol=proto.VERSION)
    LargeBlobs(ctap2, proto, tok).write_blob_array([{1: b"c"}])
    # missing protocol / bad protocol
    data = serialize([])
    expect(ERR.MISSING_PARAMETER, ctap2.large_blobs, 0, set=data, length=len(data), pin_uv_param=b"x" * 16)
    expect(
        ERR.INVALID_PARAMETER,
        ctap2.large_blobs,
        0,
        set=data,
        length=len(data),
        pin_uv_param=b"x" * 16,
        pin_uv_protocol=5,
    )


def test_fragmented_write(ctap2, device):
    items = [{1: bytes([i]) * 300, 2: b"n" * 12, 3: 300} for i in range(10)]
    data = serialize(items)
    assert 3000 < len(data) <= 4096
    off = 0
    while off < len(data):
        chunk = data[off : off + 1000]
        r = ctap2.large_blobs(off, set=chunk, length=len(data) if off == 0 else None)
        assert r == {}
        if off + len(chunk) < len(data):
            # not committed yet
            assert ctap2.large_blobs(0, get=17)[1] == lb.EMPTY_ARRAY
        off += len(chunk)
    assert LargeBlobs(ctap2).read_blob_array() == items
    # reading with offsets
    got = b""
    while True:
        frag = ctap2.large_blobs(len(got), get=700)[1]
        got += frag
        if len(frag) < 700:
            break
    assert got == data
    device.power_cycle()
    assert LargeBlobs(Ctap2(open_hid(device))).read_blob_array() == items


def test_write_errors(ctap2):
    data = serialize([{1: b"x"}])
    expect(ERR.MISSING_PARAMETER, ctap2.send_cbor, 0x0C, {1: 10})
    expect(ERR.INVALID_PARAMETER, ctap2.send_cbor, 0x0C, {3: 0})
    expect(ERR.INVALID_PARAMETER, ctap2.send_cbor, 0x0C, {1: 10, 2: data, 3: 0})
    expect(ERR.INVALID_PARAMETER, ctap2.send_cbor, 0x0C, {1: 10, 3: 0, 4: 5})
    expect(ERR.INVALID_LENGTH, ctap2.large_blobs, 0, get=7546)
    expect(ERR.INVALID_PARAMETER, ctap2.large_blobs, 0, set=data)  # length missing
    expect(ERR.LARGE_BLOB_STORAGE_FULL, ctap2.large_blobs, 0, set=data, length=4097)
    expect(ERR.INVALID_PARAMETER, ctap2.large_blobs, 0, set=data[:10], length=16)
    expect(ERR.INVALID_SEQ, ctap2.large_blobs, 5, set=data)  # no write in progress
    ctap2.large_blobs(0, set=data[:5], length=len(data))
    expect(ERR.INVALID_PARAMETER, ctap2.large_blobs, 5, set=data[5:], length=len(data))
    expect(ERR.INVALID_SEQ, ctap2.large_blobs, 6, set=data[6:])
    expect(ERR.INVALID_PARAMETER, ctap2.large_blobs, 5, set=data[5:] + b"extra")
    ctap2.large_blobs(5, set=data[5:])
    assert LargeBlobs(ctap2).read_blob_array() == [{1: b"x"}]
    expect(ERR.INVALID_LENGTH, ctap2.large_blobs, 0, set=b"\0" * 7546, length=4096)
    expect(ERR.CBOR_UNEXPECTED_TYPE, ctap2.send_cbor, 0x0C, {1: "x", 3: 0})


def test_integrity_failure_keeps_previous_array(ctap2):
    LargeBlobs(ctap2).write_blob_array([{1: b"keep"}])
    bad = cbor.encode([{1: b"new"}]) + b"\0" * 16
    expect(ERR.INTEGRITY_FAILURE, ctap2.large_blobs, 0, set=bad, length=len(bad))
    assert LargeBlobs(ctap2).read_blob_array() == [{1: b"keep"}]


def test_max_size_array(ctap2):
    data = serialize([{1: b"z" * 4074}])
    assert len(data) == 4096
    ctap2.large_blobs(0, set=data, length=len(data))
    assert ctap2.large_blobs(0, get=7000)[1] == data
    data = serialize([{1: b"z" * 4075}])
    expect(ERR.LARGE_BLOB_STORAGE_FULL, ctap2.large_blobs, 0, set=data, length=len(data))


def test_atomic_commit_power_loss(ctap2, device, kv):
    from feuristic.platform.testing import PowerLoss

    LargeBlobs(ctap2).write_blob_array([{1: b"old"}])
    data = serialize([{1: b"new"}])
    kv.crash_after_ops = kv.ops  # the very next storage operation fails
    with pytest.raises(PowerLoss):
        device.auth.large_blobs.handle({2: data, 3: 0, 4: len(data)})
    device.power_cycle()
    assert LargeBlobs(Ctap2(open_hid(device))).read_blob_array() == [{1: b"old"}]


def test_local_entries_api(device):
    lbs = device.auth.large_blobs
    assert lbs.entries() == []
    lbs.write_entries([{1: b"a"}])
    assert lbs.entries() == [{1: b"a"}]
    from feuristic.core.errors import StorageFull

    with pytest.raises(StorageFull):
        lbs.write_entries([{1: b"x" * 5000}])
