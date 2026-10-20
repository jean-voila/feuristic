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


def test_integrity_and_local_write_avoid_full_size_temporaries(device, monkeypatch):
    items = [{1: b"x" * 4074}]
    serialized = serialize(items)
    original_hash = lb.crypto.sha256
    original_encode = lb.cbor.encode

    def hash_view(data):
        assert isinstance(data, memoryview)
        return original_hash(data)

    def no_joined_body(obj):
        if isinstance(obj, list):
            raise AssertionError("encoded an unnecessary full CBOR body")
        return original_encode(obj)

    monkeypatch.setattr(lb.crypto, "sha256", hash_view)
    monkeypatch.setattr(lb.cbor, "encode", no_joined_body)
    assert lb.serialize(items) == serialized
    assert lb.check_integrity(serialized)
    device.auth.large_blobs.write_entries(items)
    assert device.auth.large_blobs.entries() == items


def test_fragment_commit_reuses_reserved_pending_buffer(device, monkeypatch):
    blobs = device.auth.large_blobs
    data = serialize([{1: b"x" * 4074}])
    blobs.handle({2: data[:100], 3: 0, 4: 4096})
    pending = blobs._pending
    assert len(pending) == 4100
    original_commit = blobs.blob._commit
    original_head = blobs.blob._head
    committed = []

    def commit_same(buffer, generation, key):
        assert buffer is pending
        committed.append(True)
        original_commit(buffer, generation, key)

    def no_second_payload_read():
        raise MemoryError("no room beside the pending array")

    monkeypatch.setattr(blobs.blob, "_commit", commit_same)
    monkeypatch.setattr(blobs.blob, "_head", no_second_payload_read)
    blobs.handle({2: data[100:], 3: 100})
    assert blobs._pending is None
    assert committed == [True]
    monkeypatch.setattr(blobs.blob, "_head", original_head)
    assert blobs.read() == data


def test_normal_memory_probe_client_uses_real_pin_token_and_ctap_fragments(device, monkeypatch):
    import ast
    import runpy
    from pathlib import Path

    from feuristic.apps.fido2.context import NULL_CHANNEL
    from feuristic.core import cbor as codec

    path = Path(__file__).resolve().parents[3] / "tools" / "probe_normal_memory32.py"
    monkeypatch.syspath_prepend(str(path.parent))
    script = ast.parse(runpy.run_path(str(path))["SCRIPT"])
    functions = [
        node
        for node in ast.walk(script)
        if isinstance(node, ast.FunctionDef)
        and node.name in ("run", "ctap", "lbw_token", "trailer", "blob_fragment")
    ]
    scope = {"auth": device.auth, "crypto": lb.crypto, "cbor": codec, "NULL_CHANNEL": NULL_CHANNEL}
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(path), "exec"), scope)
    device.auth.pin.local_set_pin("123456")
    token = scope["lbw_token"]()
    assert token == device.auth.pin._token
    for value in (b"x", b"y", b"z"):
        tag = scope["trailer"](value)
        full = serialize([{1: value * 4074}])
        for offset in range(0, 4096, 256):
            fragment = scope["blob_fragment"](value, tag, offset)
            assert fragment == full[offset : offset + 256]
            message = (
                b"\xff" * 32 + b"\x0c\x00" + offset.to_bytes(4, "little") + hashlib.sha256(fragment).digest()
            )
            request = {2: fragment, 3: offset, 5: lb.crypto.hmac_sha256(token, message)[:16], 6: 1}
            if offset == 0:
                request[4] = 4096
            assert scope["ctap"](12, request) == {}
        for offset in range(0, 4096, 256):
            assert scope["ctap"](12, {1: 256, 3: offset})[1] == full[offset : offset + 256]


@pytest.mark.parametrize("proto_cls", [PinProtocolV1, PinProtocolV2])
def test_authenticated_4k_fragments_at_100_passkeys_and_32_otp(ctap2, device, proto_cls):
    from feuristic.apps.fido2 import credentials as cr
    from feuristic.apps.otp.accounts import OtpAccounts
    from feuristic.apps.otp.uri import OtpParams

    for index in range(100):
        device.auth.store.create_resident(
            "a" * 63 + "." + "b" * 56 + ".example",
            index.to_bytes(64, "big"),
            "n" * 64,
            "d" * 64,
            cr.ALG_ES256,
            (index + 1).to_bytes(32, "big"),
            1,
            True,
            True,
        )
    otp = OtpAccounts()
    for index in range(32):
        name = str(index).ljust(64, "x")
        otp.add(OtpParams("hotp", "i" * 32, name, b"s" * 64, "SHA512", 8, counter=1001))
    proto = proto_cls()
    client = ClientPin(ctap2, proto)
    client.set_pin("123456")
    token = client.get_pin_token("123456", PERM.LARGE_BLOB_WRITE)
    for byte in (b"x", b"y", b"z"):
        data = serialize([{1: byte * 4074}])
        for offset in range(0, 4096, 256):
            fragment = data[offset : offset + 256]
            message = (
                b"\xff" * 32 + b"\x0c\x00" + offset.to_bytes(4, "little") + hashlib.sha256(fragment).digest()
            )
            assert (
                ctap2.large_blobs(
                    offset,
                    set=fragment,
                    length=4096 if offset == 0 else None,
                    pin_uv_param=proto.authenticate(token, message),
                    pin_uv_protocol=proto.VERSION,
                )
                == {}
            )
        assert b"".join(ctap2.large_blobs(offset, get=256)[1] for offset in range(0, 4096, 256)) == data
    device.power_cycle()
    assert device.auth.store.count() == 100
    assert len(OtpAccounts()) == 32
    assert device.auth.large_blobs.entries() == [{1: b"z" * 4074}]


def test_local_array_replacement_invalidates_fragment_generation(device):
    blobs = device.auth.large_blobs
    data = serialize([{1: b"pending"}])
    blobs.handle({2: data[:5], 3: 0, 4: len(data)})
    blobs.write_entries([{1: b"local replacement"}])
    with pytest.raises(lb.CtapError) as caught:
        blobs.handle({2: data[5:], 3: 5})
    assert caught.value.code == ERR.INVALID_SEQ
    assert blobs.entries() == [{1: b"local replacement"}]
