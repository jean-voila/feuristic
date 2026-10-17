# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Unit tests of helpers + hypothesis fuzzing of the CTAP2 parser and CTAPHID."""

import pytest
from ctap_harness import MS, Device, SimUI, aio_run, allocate_channel
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from feuristic.apps.fido2 import credentials as cr
from feuristic.apps.fido2 import ctaphid as hidmod
from feuristic.apps.fido2 import params as prm
from feuristic.apps.fido2.context import NULL_CHANNEL, Context
from feuristic.apps.fido2.ctap2 import Authenticator
from feuristic.apps.fido2.state import FidoState
from feuristic.apps.fido2.status import CtapError
from feuristic.core import cbor, namespaces
from feuristic.core.errors import InvalidInput
from feuristic.core.interaction import ScriptedInteraction
from feuristic.core.store import pack
from feuristic.platform import crypto, kv, testing

# ---------------------------------------------------------------------------
# params
# ---------------------------------------------------------------------------


@given(st.text(max_size=80))
def test_utf8_helpers_match_python(text):
    raw = text.encode("utf-8", "surrogatepass")
    try:
        text.encode()
        valid = True
    except UnicodeEncodeError:
        valid = False
    assert prm.utf8_valid(raw) == valid
    if valid:
        assert prm.utf8_code_points(raw) == len(text)
        t = prm.truncate_utf8(text, 64)
        assert len(t.encode()) <= 64 and text.startswith(t)


@given(st.binary(max_size=40))
def test_utf8_valid_on_random_bytes(raw):
    try:
        raw.decode("utf-8")
        ok = True
    except UnicodeDecodeError:
        ok = False
    assert prm.utf8_valid(raw) == ok


def test_raw_map_values():
    data = cbor.encode({1: 5, 2: {1: b"x"}, "s": 1})
    vals = prm.raw_map_values(data)
    assert vals[2] == cbor.encode({1: b"x"}) and vals[1] == b"\x05" and "s" not in vals
    big = cbor.encode({i: i for i in range(30)})
    assert prm.raw_map_values(big)[29] == b"\x18\x1d"
    for bad, code in [(b"", 0x11), (b"\x80", 0x11), (b"\xbf", 0x12), (b"\xa1\x01", 0x12), (b"\xb8", 0x12)]:
        with pytest.raises(CtapError) as e:
            prm.raw_map_values(bad)
        assert e.value.code == code
    with pytest.raises(CtapError):
        prm.raw_map_values(b"\xb9\xff\xff")


def test_decode_request():
    assert prm.decode_request(b"") == {}
    with pytest.raises(CtapError) as e:
        prm.decode_request(b"\x01")
    assert e.value.code == 0x11
    with pytest.raises(CtapError) as e:
        prm.decode_request(b"\xa1\x01\xfa\x00\x00\x00\x00")  # float
    assert e.value.code == 0x12


# ---------------------------------------------------------------------------
# credentials / state
# ---------------------------------------------------------------------------


def test_info_byte_roundtrip():
    for alg in cr.SUPPORTED_ALGS:
        for prot in (1, 2, 3):
            for h in (False, True):
                for lb in (False, True):
                    assert cr.decode_info(cr.encode_info(alg, prot, h, lb)) == (alg, prot, h, lb)
    for bad in (0, 0x20, -1, True, "x"):
        with pytest.raises(InvalidInput):
            cr.decode_info(bad)
    with pytest.raises(InvalidInput):
        cr.generate_key(-257)


def test_record_payload_size_cap():
    cred = cr.Credential(
        cr.KIND_RESIDENT,
        b"\x01" + bytes(12),
        bytes(32),
        b"\x11" * 32,
        rp_id="r" * 128,
        user_id=b"u" * 64,
        user_name="n" * 64,
        display_name="d" * 64,
        seq=0xFFFFFFFF,
        uid=bytes(8),
    )
    assert len(cr.encode_record(cred)) <= cr.MAX_PAYLOAD


def test_corrupt_records_are_skipped(device):
    store = device.auth.store
    store.create_resident("a.com", b"u", "n", None, -7, crypto.p256_generate(), 1, False, False)
    store.create_resident("b.com", b"v", None, None, -8, crypto.random_bytes(32), 3, True, False)
    # garbage record in a free slot, and a valid header with a bad payload
    kv.set(namespaces.FIDO_CREDS, 50, b"garbage")
    kv.set(namespaces.FIDO_CREDS, 51, pack(cr.RECORD_TYPE, 0, 99, b"\x07" * 8, b"\xa1\x01\x01"))
    kv.set(namespaces.FIDO_CREDS, 52, pack(cr.RECORD_TYPE, 0, 98, b"\x08" * 8, cbor.encode({1: 1, 9: 1})))
    device.power_cycle()
    assert device.auth.store.count() == 2
    assert {c[0] for c in device.auth.store.rps()} == {"a.com", "b.com"}


@pytest.mark.parametrize(
    "payload",
    [
        {1: -1, 2: "a", 3: b"", 6: 1, 7: bytes(32)},
        {1: 1, 2: "", 3: b"", 6: 1, 7: bytes(32)},
        {1: 1, 2: "a", 3: "x", 6: 1, 7: bytes(32)},
        {1: 1, 2: "a", 3: b"", 6: 1, 7: bytes(31)},
        {1: 1, 2: "a", 3: b"", 6: 0, 7: bytes(32)},
        {1: 1, 2: "a", 3: b"", 4: 5, 6: 1, 7: bytes(32)},
        {1: 1, 2: "a", 3: b"", 6: 1, 7: bytes(32), "x": 1},
    ],
)
def test_decode_record_strict(payload):
    with pytest.raises((InvalidInput, cbor.CborError)):
        cr.decode_record(bytes(8), cbor.encode(payload), 0)
    with pytest.raises(cbor.CborError):
        cr.decode_record(bytes(8), b"\xa2\x02\x61a\x01\x01", 0)  # non-canonical order


def test_duplicate_owner_resolved_at_load(device):
    """A power cut during an overwriting restore leaves two records for the
    same (rpId, user.id): the newest generation wins at the next load."""
    store = device.auth.store
    c1 = store.create_resident("a.com", b"u", "old", None, -7, crypto.p256_generate(), 1, False, False)
    c2 = cr.Credential(
        cr.KIND_RESIDENT,
        b"\x01" + b"\x09" * 8 + b"\x00\x00\x00\x07",
        c1.rp_id_hash,
        crypto.p256_generate(),
        rp_id="a.com",
        user_id=b"u",
        user_name="new",
        seq=7,
        uid=b"\x09" * 8,
    )
    store.records.put(c2.uid, cr.encode_record(c2), 0)  # bypasses the dedupe
    device.power_cycle()
    creds = device.auth.store.for_rp(c1.rp_id_hash)
    assert [c.user_name for c in creds] == ["new"]
    assert len(device.auth.store.records) == 1
    # and the other way round (older generation found second)
    c3 = cr.Credential(
        cr.KIND_RESIDENT,
        b"\x01" + b"\x00" * 8 + b"\x00\x00\x00\x08",
        c1.rp_id_hash,
        crypto.p256_generate(),
        rp_id="a.com",
        user_id=b"u",
        user_name="older",
        seq=8,
        uid=b"\x00" * 8,
    )
    raw = pack(cr.RECORD_TYPE, 0, 1, c3.uid, cr.encode_record(c3))
    kv.set(namespaces.FIDO_CREDS, 90, raw)
    device.power_cycle()
    assert [c.user_name for c in device.auth.store.for_rp(c1.rp_id_hash)] == ["new"]


def test_state_corruption_regenerates_seed(device):
    seed = device.auth.state.seed
    kv.set(namespaces.FIDO_STATE, 0, b"\x00\x00\x00\x09bogus")
    kv.set(namespaces.FIDO_STATE, 1, b"\x00\x00\x00\x08bogus")
    fresh = FidoState()
    assert fresh.seed != seed and fresh.pin_retries == 8 and not fresh.pin_is_set()
    with pytest.raises(ValueError):
        fresh.set_pin_hash(b"short")
    fresh.set_pin_retries(20)
    assert fresh.pin_retries == 8
    fresh.raise_signature_counter(1000)
    assert fresh.next_signature_counter() > 1000
    fresh.raise_signature_counter(5)  # never lowers
    assert fresh.next_signature_counter() > 1000


def test_u2f_unwrap_rejects_bad_scalar(device):
    store = device.auth.store
    kh = store.u2f_wrap(bytes(32), b"\xff" * 32)  # not a valid P-256 scalar
    assert store.u2f_unwrap(kh, bytes(32)) is None
    assert store.u2f_unwrap(kh[:-1], bytes(32)) is None
    assert store.lookup(b"", bytes(32)) is None
    assert store.lookup(b"\x01" * 65, bytes(32)) is None
    assert store.lookup_resident(b"\x02" * 13) is None
    assert store.lookup_resident(b"\x01" + bytes(12)) is None


def test_context_validation():
    with pytest.raises(ValueError):
        Context(b"short", None)
    ctx = Context(MS, None, power_up_ms=0)
    assert ctx.ms_since_power_up() == testing.CLOCK.now_ms()
    assert Context.now() == testing.CLOCK.now_ms()
    NULL_CHANNEL.set_status(2)
    assert NULL_CHANNEL.cancelled is False


def test_dispatch_with_core_scripted_interaction():
    ctx = Context(MS, ScriptedInteraction([True]))
    auth = Authenticator(ctx)
    assert aio_run(auth.dispatch(b"")) == b"\x03"
    assert aio_run(auth.dispatch(b"\x0b")) == b"\x00"
    assert aio_run(auth.dispatch(bytearray(b"\x04")))[0] == 0


def test_dispatch_internal_error_maps_to_other(device, monkeypatch):
    def boom(*_a):
        raise RuntimeError("x")

    monkeypatch.setattr(device.auth, "get_info", boom)
    assert aio_run(device.auth.dispatch(b"\x04")) == b"\x7f"
    from feuristic.core.errors import StorageFull

    def full(*_a):
        raise StorageFull

    monkeypatch.setattr(device.auth, "get_info", full)
    assert aio_run(device.auth.dispatch(b"\x04")) == b"\x28"


# ---------------------------------------------------------------------------
# fuzzing
# ---------------------------------------------------------------------------

cbor_leaf = st.one_of(
    st.integers(min_value=-(2**63), max_value=2**63),
    st.binary(max_size=80),
    st.text(max_size=30),
    st.booleans(),
    st.none(),
)
cbor_value = st.recursive(
    cbor_leaf,
    lambda children: st.one_of(
        st.lists(children, max_size=5),
        st.dictionaries(st.one_of(st.integers(-5, 12), st.text(max_size=12)), children, max_size=6),
    ),
    max_leaves=25,
)
requests = st.dictionaries(st.integers(min_value=-2, max_value=12), cbor_value, max_size=10)


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(cmd=st.sampled_from([0x01, 0x02, 0x04, 0x06, 0x07, 0x08, 0x0A, 0x0B, 0x0C, 0x41, 0x0D]), req=requests)
def test_fuzz_ctap2_structured(cmd, req):
    testing.reset_all()
    dev = Device(SimUI(default=True))
    resp = aio_run(dev.auth.dispatch(bytes((cmd,)) + cbor.encode(req)))
    assert isinstance(resp, bytes) and len(resp) >= 1
    if resp[0] == 0 and len(resp) > 1:
        assert isinstance(cbor.decode(resp[1:]), dict)
    else:
        assert len(resp) == 1 and resp[0] != 0x7F


@settings(max_examples=300, deadline=None)
@given(data=st.binary(max_size=300))
def test_fuzz_ctap2_raw_bytes(data):
    testing.reset_all()
    dev = Device(SimUI(default=False))
    resp = aio_run(dev.auth.dispatch(data))
    assert isinstance(resp, bytes) and len(resp) >= 1
    assert resp[0] != 0x7F


@settings(max_examples=200, deadline=None)
@given(packets=st.lists(st.binary(min_size=0, max_size=64), max_size=30))
def test_fuzz_ctaphid_packets(packets):
    testing.reset_all()
    dev = Device(SimUI(default=False))
    cid = allocate_channel(dev)
    for raw in packets:
        p = cid.to_bytes(4, "big") + raw[4:] if len(raw) >= 4 and raw[0] & 1 else raw
        dev.write(p)
        dev.advance(50)
    out = dev.read_all()
    assert all(len(p) == 64 for p in out)
    # the transport still works afterwards
    dev.advance(1000)
    dev.read_all()
    assert not dev.hid.busy()


@settings(max_examples=100, deadline=None)
@given(apdu=st.binary(max_size=200))
def test_fuzz_u2f_apdus(apdu):
    testing.reset_all()
    dev = Device(SimUI(default=True))
    cmd, payload = dev.app.u2f.handle(apdu)
    assert cmd in (0x03, 0x3F) and len(payload) >= 1
    job = dev.app.u2f.dialog_job()
    if job is not None:
        aio_run(job)


def test_ctaphid_constants():
    assert hidmod.MAX_MESSAGE == 57 + 128 * 59
