# SPDX-License-Identifier: GPL-3.0-only
import contextlib

import cbor2
import pytest
from hypothesis import given
from hypothesis import strategies as st

from feuristic.core import cbor


def test_array_items_borrow_payloads_and_enforce_complete_bounded_input():
    source = bytearray(cbor.encode([{1: b"x" * 300}, {2: b"last"}]))
    items = list(cbor.array_items(source, max_depth=2, max_items=7))
    assert [bytes(raw) for _, raw in items] == [cbor.encode({1: b"x" * 300}), cbor.encode({2: b"last"})]
    assert items[0][0][1].obj is source
    for data, limits in (
        (source + b"\x00", {}),
        (source, {"max_items": 6}),
        (source, {"max_depth": 1}),
        (b"\x80", {"max_items": 0}),
        (b"\x80", {"max_depth": -1}),
        (b"\xa0", {}),
    ):
        with pytest.raises(cbor.CborError):
            list(cbor.array_items(data, **limits))


# RFC 8949 Appendix A examples (subset supported by feuristic)
VECTORS = [
    (0, "00"),
    (1, "01"),
    (10, "0a"),
    (23, "17"),
    (24, "1818"),
    (25, "1819"),
    (100, "1864"),
    (1000, "1903e8"),
    (1000000, "1a000f4240"),
    (1000000000000, "1b000000e8d4a51000"),
    (18446744073709551615, "1bffffffffffffffff"),
    (-1, "20"),
    (-10, "29"),
    (-100, "3863"),
    (-1000, "3903e7"),
    (False, "f4"),
    (True, "f5"),
    (None, "f6"),
    (b"", "40"),
    (b"\x01\x02\x03\x04", "4401020304"),
    ("", "60"),
    ("a", "6161"),
    ("IETF", "6449455446"),
    ("ü", "62c3bc"),
    ([], "80"),
    ([1, 2, 3], "83010203"),
    ([1, [2, 3], [4, 5]], "8301820203820405"),
    ({}, "a0"),
    ({1: 2, 3: 4}, "a201020304"),
    ({"a": 1, "b": [2, 3]}, "a26161016162820203"),
]


@pytest.mark.parametrize("obj,hexenc", VECTORS)
def test_rfc8949_vectors(obj, hexenc):
    assert cbor.encode(obj).hex() == hexenc
    assert cbor.decode(bytes.fromhex(hexenc)) == obj
    assert cbor.decode(bytes.fromhex(hexenc), canonical=True) == obj


def test_map_key_ordering_is_bytewise():
    # CTAP2 canonical: ints before text, shorter before longer
    obj = {"bb": 1, "a": 2, 10: 3, -1: 4, 1: 5}
    enc = cbor.encode(obj)
    assert enc.hex() == "a5" + "0105" + "0a03" + "2004" + "616102" + "62626201"


@pytest.mark.parametrize("buffer", [bytes, bytearray, memoryview])
def test_encode_parts_matches_canonical_nested_encoding(buffer):
    obj = {"long": [buffer(b"x" * 4096), {24: False, 1: None}], 2: "text", b"a": -7}
    parts = cbor.encode_parts(obj)
    encoded = b"".join(parts)
    normalized = {"long": [b"x" * 4096, {24: False, 1: None}], 2: "text", b"a": -7}
    assert encoded == cbor.encode(obj) == cbor2.dumps(normalized, canonical=True)
    assert cbor.decode(memoryview(encoded), canonical=True) == cbor.decode(encoded)


def test_encode_parts_snapshots_mutable_bytes():
    source = bytearray(b"first")
    parts = cbor.encode_parts([memoryview(source)])
    source[:] = b"later"
    assert b"".join(parts) == cbor.encode([b"first"])


@pytest.mark.parametrize(
    "hexenc",
    [
        "1817",  # non-shortest uint
        "190017",  # non-shortest uint (2 bytes)
        "5801aa",  # non-shortest length
        "a2616201616101",  # keys out of order
    ],
)
def test_canonical_rejects_non_deterministic(hexenc):
    data = bytes.fromhex(hexenc)
    cbor.decode(data)  # lenient decoding accepts it
    with pytest.raises(cbor.CborError):
        cbor.decode(data, canonical=True)


@pytest.mark.parametrize(
    "hexenc,reason",
    [
        ("", "empty"),
        ("18", "truncated head"),
        ("44010203", "truncated bytes"),
        ("5f", "indefinite bytes"),
        ("9f01ff", "indefinite array"),
        ("c11a514b67b0", "tag"),
        ("f97c00", "float16"),
        ("fb3ff199999999999a", "float64"),
        ("62c328", "invalid utf-8"),
        ("a201020103", "duplicate key"),
        ("0001", "trailing"),
        ("a1800102", "array as key"),
        ("1c", "reserved info"),
        ("f0", "unassigned simple"),
    ],
)
def test_rejects_malformed(hexenc, reason):
    with pytest.raises(cbor.CborError):
        cbor.decode(bytes.fromhex(hexenc))


def test_depth_and_item_limits():
    deep = bytes.fromhex("81" * 9 + "00")
    with pytest.raises(cbor.CborError):
        cbor.decode(deep)
    assert cbor.decode(bytes.fromhex("81" * 8 + "00"), max_depth=8) is not None
    huge_array = bytes.fromhex("9a7fffffff")  # claims 2^31 items
    with pytest.raises(cbor.CborError):
        cbor.decode(huge_array)
    many = cbor.encode(list(range(3000)))
    with pytest.raises(cbor.CborError):
        cbor.decode(many)
    assert len(cbor.decode(many, max_items=4000)) == 3000


def test_allow_trailing():
    obj, n = cbor.decode(bytes.fromhex("0102"), allow_trailing=True)
    assert obj == 1 and n == 1


def test_encode_rejects_unsupported():
    with pytest.raises(cbor.CborError):
        cbor.encode(1.5)
    with pytest.raises(cbor.CborError):
        cbor.encode(2**64)
    with pytest.raises(cbor.CborError):
        cbor.encode(-(2**64) - 1)
    with pytest.raises(cbor.CborError):
        cbor.encode({(1,): 3})
    with pytest.raises(cbor.CborError):
        cbor.encode({None: 3})
    with pytest.raises(cbor.CborError):
        cbor.encode(object())


_scalars = st.one_of(
    st.integers(min_value=-(2**64), max_value=2**64 - 1),
    st.binary(max_size=40),
    st.text(max_size=20),
    st.booleans(),
    st.none(),
)
_values = st.recursive(
    _scalars,
    lambda children: st.one_of(
        st.lists(children, max_size=5),
        st.dictionaries(st.one_of(st.integers(-1000, 1000), st.text(max_size=8)), children, max_size=5),
    ),
    max_leaves=25,
)


def _reference_encode(obj):
    """Independent oracle: cbor2 for scalars, CTAP2/RFC 8949 bytewise key order for maps.

    (cbor2's ``canonical=True`` implements RFC 7049 length-first ordering,
    which differs from CTAP2's major-type-first ordering, so maps are
    re-encoded here.)"""
    if isinstance(obj, dict):
        items = sorted((cbor2.dumps(k), _reference_encode(v)) for k, v in obj.items())
        head = cbor2.dumps({})[:0]
        n = len(items)
        head = bytes([0xA0 | n]) if n < 24 else bytes([0xB8, n])
        return head + b"".join(k + v for k, v in items)
    if isinstance(obj, list):
        n = len(obj)
        head = bytes([0x80 | n]) if n < 24 else bytes([0x98, n])
        return head + b"".join(_reference_encode(x) for x in obj)
    return cbor2.dumps(obj)


@given(_values)
def test_roundtrip_and_cross_check_with_reference(obj):
    enc = cbor.encode(obj)
    assert b"".join(cbor.iter_encode(obj)) == enc
    assert cbor.decode(enc, canonical=True) == obj
    assert cbor2.loads(enc) == obj
    assert _reference_encode(obj) == enc


@given(st.binary(max_size=200))
def test_decoder_never_crashes(data):
    with contextlib.suppress(cbor.CborError):
        cbor.decode(data)


def test_byte_views_are_opt_in_and_map_keys_remain_hashable():
    raw = bytearray(cbor.encode({b"key": b"value"}))
    copied = cbor.decode(raw)
    viewed = cbor.decode(raw, bytes_view=True, canonical=True)
    assert isinstance(copied[b"key"], bytes)
    assert isinstance(viewed[b"key"], memoryview)
    raw[-1] = ord("X")
    assert copied[b"key"] == b"value" and viewed[b"key"] == b"valuX"
    assert cbor.encode(viewed) == bytes(raw)


def test_encode_into_checks_capacity_before_modifying_buffer():
    obj = {1: b"data", 2: [1, 2, 3]}
    encoded = cbor.encode(obj)
    buffer = bytearray(b"x" * (16 + len(encoded)))
    result = cbor.encode_into(obj, buffer, 16)
    assert result == encoded and buffer[:16] == b"x" * 16
    before = bytes(buffer)
    with pytest.raises(cbor.CborError):
        cbor.encode_into(obj, buffer, 17)
    assert buffer == before


def test_borrowed_cbor_parts_preserve_bytes_without_a_second_large_copy():
    data = bytearray(b"a" * 4096)
    copied = cbor.encode_parts({1: data})
    borrowed = cbor.encode_parts({1: memoryview(data)}, borrow_bytes=True)
    assert b"".join(copied) == b"".join(borrowed)
    data[-1] = ord("b")
    assert b"".join(copied)[-1:] == b"a"
    assert b"".join(borrowed)[-1:] == b"b"
