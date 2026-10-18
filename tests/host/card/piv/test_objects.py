# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""PUT DATA / GET DATA of certificates and data objects, size limits, storage."""

import contextlib
import os

import pytest

from feuristic.apps.card.piv import consts, storage
from feuristic.core import cbor, namespaces, tlv
from feuristic.core.errors import StorageCorrupted, StorageFull
from feuristic.platform import testing

from .pivutil import cert_object, get_data, mgmt_auth, put_data, tx, verify


@pytest.fixture
def admin(piv):
    mgmt_auth(piv)
    return piv


@pytest.mark.parametrize(("tag", "slot"), sorted(consts.CERT_OBJECTS.items()))
def test_certificate_roundtrip(admin, store, tag, slot):
    der = os.urandom(700)
    assert put_data(admin, tag, cert_object(der)).sw == 0x9000
    r = get_data(admin, tag)
    assert r.sw == 0x9000
    assert r.data == tlv.build(0x53, cert_object(der))
    assert store.get_slot(slot).cert == der


def test_certificate_without_key_and_key_kept(admin, store):
    from .pivutil import generate

    generate(admin, 0x9A)
    pub = store.get_slot(0x9A).pub
    put_data(admin, consts.OBJ_CERT_9A, cert_object(b"\x30\x00"))
    assert store.get_slot(0x9A).pub == pub
    put_data(admin, consts.OBJ_CERT_9C, cert_object(b"\x30\x00"))
    assert not store.get_slot(0x9C).has_key


def test_certificate_compressed_flag_and_minimal_forms(admin):
    assert put_data(admin, consts.OBJ_CERT_9A, cert_object(b"\x1f\x8b\x08", 1)).sw == 0x9000
    assert tlv.find(tlv.find(get_data(admin, consts.OBJ_CERT_9A).data, 0x53), 0x71) == b"\x01"
    # 71 and FE are optional on input
    assert put_data(admin, consts.OBJ_CERT_9A, tlv.build(0x70, b"\x30\x00")).sw == 0x9000
    body = tlv.find(get_data(admin, consts.OBJ_CERT_9A).data, 0x53)
    assert body == cert_object(b"\x30\x00")


def test_certificate_size_limit(admin):
    assert put_data(admin, consts.OBJ_CERT_9A, cert_object(os.urandom(2048))).sw == 0x9000
    assert put_data(admin, consts.OBJ_CERT_9C, cert_object(os.urandom(2049))).sw == 0x6A84
    assert get_data(admin, consts.OBJ_CERT_9C).sw == 0x6A82


def test_delete_certificate(admin, store):
    put_data(admin, consts.OBJ_CERT_9A, cert_object(b"\x30\x00"))
    assert put_data(admin, consts.OBJ_CERT_9A, b"").sw == 0x9000
    assert get_data(admin, consts.OBJ_CERT_9A).sw == 0x6A82
    assert store.get_slot(0x9A) is None  # no key, no cert: record removed


@pytest.mark.parametrize(
    "value",
    [
        tlv.build(0x70, b""),
        tlv.build(0x71, b"\x00"),
        cert_object(b"\x30\x00", 2),
        tlv.build(0x70, b"\x30\x00") + tlv.build(0x71, b"\x00\x00"),
        tlv.build(0x70, b"\x30\x00") + tlv.build(0x70, b"\x30\x00"),
        tlv.build(0x70, b"\x30\x00") + tlv.build(0xFE, b"\x01"),
        tlv.build(0x70, b"\x30\x00") + tlv.build(0x72, b""),
        b"\x70\x05\x30",
    ],
)
def test_malformed_certificate_object(admin, value):
    assert put_data(admin, consts.OBJ_CERT_9A, value).sw == 0x6A80


def test_put_data_requires_management_key(piv):
    assert put_data(piv, consts.OBJ_CERT_9A, cert_object(b"\x30\x00")).sw == 0x6982
    verify(piv)  # the PIN is not enough
    assert put_data(piv, consts.OBJ_CHUID, tlv.build(0x34, bytes(16))).sw == 0x6982


@pytest.mark.parametrize(
    "data",
    [
        tlv.build(0x5C, bytes.fromhex("5FC105")),
        tlv.build(0x53, b"") + tlv.build(0x5C, bytes.fromhex("5FC105")),
        tlv.build(0x5C, bytes.fromhex("5FC105")) + tlv.build(0x54, b""),
        tlv.build(0x5C, b"") + tlv.build(0x53, b""),
    ],
)
def test_put_data_malformed(admin, data):
    assert tx(admin, 0xDB, 0x3F, 0xFF, data).sw == 0x6A80


def test_put_data_wrong_p1p2(admin):
    assert tx(admin, 0xDB, 0x3F, 0x00, tlv.build(0x5C, b"\x7e") + tlv.build(0x53, b"")).sw == 0x6A86


@pytest.mark.parametrize("tag", [consts.OBJ_DISCOVERY, 0x5FC103, 0x5FFF00, 0x5FC10D])
def test_put_unknown_or_read_only_object(admin, tag):
    assert put_data(admin, tag, tlv.build(0x01, b"\x00")).sw == 0x6A80


def test_chuid_override_and_reset(admin):
    custom = tlv.build(0x30, bytes(25)) + tlv.build(0x34, b"G" * 16) + tlv.build(0x35, b"20991231")
    assert put_data(admin, consts.OBJ_CHUID, custom).sw == 0x9000
    assert get_data(admin, consts.OBJ_CHUID).data == tlv.build(0x53, custom)
    assert put_data(admin, consts.OBJ_CHUID, b"").sw == 0x9000
    assert tlv.find(tlv.find(get_data(admin, consts.OBJ_CHUID).data, 0x53), 0x30) != bytes(25)


def test_printed_and_security_objects(admin):
    printed = tlv.build(0x01, b"ALICE") + tlv.build(0xFE, b"")
    assert put_data(admin, consts.OBJ_PRINTED, printed).sw == 0x9000
    assert get_data(admin, consts.OBJ_PRINTED).sw == 0x6982
    verify(admin)
    assert get_data(admin, consts.OBJ_PRINTED).data == tlv.build(0x53, printed)
    so = tlv.build(0xBA, b"\x00" * 10) + tlv.build(0xBB, b"\x01" * 100)
    assert put_data(admin, consts.OBJ_SECURITY, so).sw == 0x9000
    assert get_data(admin, consts.OBJ_SECURITY).data == tlv.build(0x53, so)


@pytest.mark.parametrize(("tag", "cap"), sorted(consts.DATA_OBJECT_CAPS.items()))
def test_data_object_caps(admin, tag, cap):
    def obj(n):  # a single TLV of total length n
        hdr = 4 if n - 4 > 0xFF else 3 if n - 3 >= 0x80 else 2
        return tlv.build(0x01, bytes(n - hdr))

    assert put_data(admin, tag, obj(cap)).sw == 0x9000
    assert put_data(admin, tag, obj(cap + 1)).sw == 0x6A84


def test_data_object_must_be_tlv(admin):
    assert put_data(admin, consts.OBJ_CCC, b"\xf0\x05\x00").sw == 0x6A80


def test_total_budget(admin, store):
    for tag in consts.CERT_OBJECTS:
        assert put_data(admin, tag, cert_object(os.urandom(2048))).sw == 0x9000
    for tag, cap in consts.DATA_OBJECT_CAPS.items():
        r = put_data(admin, tag, tlv.build(0x01, bytes(cap - 4)))
        if r.sw != 0x9000:
            assert r.sw == 0x6A84
    assert store.used_bytes() <= storage.TOTAL_MAX


def test_storage_keys_in_piv_range(admin, store):
    from .pivutil import generate

    generate(admin, 0x9A)
    put_data(admin, consts.OBJ_CHUID, tlv.build(0x34, bytes(16)))
    keys = [k for (app, k) in testing.KV.data if app == namespaces.CARD]
    assert keys and all(0x10 <= k <= 0x16 for k in keys)
    assert store.store.key_range() == (0x10, 0x16)


def test_put_power_loss_is_atomic(admin, store):
    put_data(admin, consts.OBJ_CERT_9A, cert_object(b"A" * 100))
    for crash_at in range(4):
        testing.KV.crash_after_ops = testing.KV.ops + crash_at
        with contextlib.suppress(testing.PowerLoss):
            put_data(admin, consts.OBJ_CERT_9A, cert_object(b"B" * 100))
        testing.KV.crash_after_ops = None
        fresh = storage.PivStore()
        fresh.load()
        assert fresh.get_slot(0x9A).cert in (b"A" * 100, b"B" * 100)
        admin._store = fresh
        put_data(admin, consts.OBJ_CERT_9A, cert_object(b"A" * 100))


def test_store_full_maps_to_6a84(admin, monkeypatch, store):
    def boom(*_a, **_k):
        raise StorageFull("x")

    monkeypatch.setattr(store.store, "put", boom)
    assert put_data(admin, consts.OBJ_CERT_9A, cert_object(b"\x30\x00")).sw == 0x6A84


def test_corrupt_records_map_to_6581(piv, store):
    store.store.put(storage.slot_uid(0x9A), b"\xa1\x00\x02")  # schema 2
    assert get_data(piv, consts.OBJ_CERT_9A).sw == 0x6581
    store.store.put(storage.UID_CREDS, b"\xff")
    store._creds = None
    assert tx(piv, 0x20, 0, 0x80).sw == 0x6581


def test_slot_record_codec_rejects_garbage():
    for payload in [
        b"",
        cbor.encode([1]),
        cbor.encode({0: 1, 1: 0x9B, 8: 2, 9: 1}),
        cbor.encode({0: 1, 1: 0x9A, 2: 0x11, 3: bytes(31), 4: bytes(65), 8: 2, 9: 1}),
        cbor.encode({0: 1, 1: 0x9A, 2: 0x99, 8: 2, 9: 1}),
        cbor.encode({0: 1, 1: 0x9A, 2: 0x07, 5: bytes(100), 6: bytes(128), 7: 65537, 8: 2, 9: 1}),
        cbor.encode({0: 1, 1: 0x9A, 8: True, 9: 1}),
    ]:
        with pytest.raises(StorageCorrupted):
            storage.SlotData.decode(payload)


def test_credentials_codec_rejects_garbage():
    good = storage.Credentials.defaults().encode()
    assert storage.Credentials.decode(good).mgmt_alg == consts.ALG_AES192
    m = cbor.decode(good)
    m[6] = bytes(16)  # AES-192 key of the wrong size
    with pytest.raises(StorageCorrupted):
        storage.Credentials.decode(cbor.encode(m))
    m = cbor.decode(good)
    m[8] = 0
    with pytest.raises(StorageCorrupted):
        storage.Credentials.decode(cbor.encode(m))


def test_pin_hash_is_salted(store):
    a = storage.Credentials.defaults()
    b = storage.Credentials.defaults()
    assert a.pin_hash != b.pin_hash
    assert a.matches(consts.REF_PIN, storage.pad_pin(b"123456"))
    assert b"123456" not in a.encode()


def test_pin_format_helper():
    assert storage.pin_format_ok(b"123456\xff\xff")
    assert storage.pin_format_ok(b"12345678")
    assert not storage.pin_format_ok(b"\xff" * 8)
    assert not storage.pin_format_ok(b"1234567")
    with pytest.raises(Exception):  # noqa: B017
        storage.pad_pin(b"12345")
