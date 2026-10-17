# SPDX-License-Identifier: GPL-3.0-only
"""OpenPGP identity record encoding and corruption handling."""

import pytest

from feuristic.apps.card.openpgp import const as pgp
from feuristic.apps.card.openpgp.storage import Identity, IdentityStore, KeySlot, PinRef
from feuristic.core import cbor
from feuristic.core.errors import InvalidInput, StorageCorrupted


def main_obj():
    ident = Identity.fresh()
    ident.keys[0].set_secret(bytes(32), pgp.ORIGIN_GENERATED)
    return cbor.decode(ident.encode_main(None))


def test_roundtrip():
    ident = Identity.fresh()
    ident.name = b"Doe<<J"
    ident.keys[1].set_secret(b"\x05" * 32, pgp.ORIGIN_IMPORTED)
    ident.keys[1].date = 77
    ident.pins[pgp.RC] = PinRef.create(b"resetting")
    raw = ident.encode_main(1)
    again, ref = Identity.decode_main(raw)
    assert ref == 1 and again.name == b"Doe<<J"
    assert again.keys[1].secret == b"\x05" * 32 and again.keys[1].date == 77
    assert again.pins[pgp.RC].matches(b"resetting")
    assert not again.pins[pgp.RC].matches(b"resettinG")


MUTATIONS = [
    lambda o: o.update({0: 2}),
    lambda o: o.pop(9),
    lambda o: o.update({1: 1}),
    lambda o: o.update({2: o[2][:2]}),
    lambda o: o[2][0].update({0: b"\x99"}),
    lambda o: o[2][1].update({0: pgp.ATTR_ED25519}),
    lambda o: o[2][0].update({0: pgp.ATTR_X25519}),
    lambda o: o[2][0].update({1: bytes(31)}),
    lambda o: o[2][0].update({2: bytes(19)}),
    lambda o: o[2][0].update({4: -1}),
    lambda o: o[2][0].update({5: 0}),
    lambda o: o[2][1].update({5: 1}),
    lambda o: o[2][0].pop(5),
    lambda o: o.update({3: b"x" * 40}),
    lambda o: o.update({6: [None, None, None]}),
    lambda o: o.update({6: [[1000, bytes(16), bytes(32), 0], None, None]}),
    lambda o: o.update({6: o[6][:2]}),
    lambda o: o.update({7: 3}),
    lambda o: o.update({8: True}),
    lambda o: o.update({9: 2}),
]


@pytest.mark.parametrize("mutate", MUTATIONS)
def test_decode_rejects(mutate):
    o = main_obj()
    mutate(o)
    with pytest.raises(InvalidInput):
        Identity.decode_main(cbor.encode(o))


@pytest.mark.parametrize(
    "aux",
    [
        {0: b"", 1: b"", 2: [b""] * 4},
        {0: b"u" * 255, 1: b"", 2: [b""] * 4, 3: b""},
        {0: b"", 1: b"", 2: [b""] * 3, 3: b""},
        {0: b"", 1: b"", 2: [b"", b"", b"", 5], 3: b""},
        {0: b"", 1: b"", 2: [b""] * 4, 3: bytes(2049)},
    ],
)
def test_decode_aux_rejects(aux):
    with pytest.raises(InvalidInput):
        Identity().decode_aux(cbor.encode(aux))


def test_corrupted_identity_record_is_reported():
    s = IdentityStore()
    s.records.load()
    s.records.put(pgp.UID_IDENTITY, b"\xa0")
    with pytest.raises(StorageCorrupted):
        IdentityStore().load()


def test_missing_aux_record_is_reported():
    s = IdentityStore()
    s.ident.url = b"https://x"
    s.save(aux_changed=True)
    ref = s._aux_ref
    s.records.delete(pgp.UID_AUX[ref])
    with pytest.raises(StorageCorrupted):
        IdentityStore().load()


def test_corrupted_aux_record_is_reported():
    s = IdentityStore()
    s.ident.url = b"https://x"
    s.save(aux_changed=True)
    s.records.put(pgp.UID_AUX[s._aux_ref], b"\x01")
    with pytest.raises(StorageCorrupted):
        IdentityStore().load()


def test_aux_removed_when_emptied():
    s = IdentityStore()
    s.ident.login = b"jdoe"
    s.save(aux_changed=True)
    assert s._aux_ref is not None
    s.ident.login = b""
    s.save(aux_changed=True)
    assert s._aux_ref is None
    assert not any(u in s.records for u in pgp.UID_AUX)


def test_keyslot_public_without_key():
    with pytest.raises(InvalidInput):
        KeySlot(pgp.ATTR_ED25519).public()


def test_signature_count_bounds():
    s = IdentityStore()
    s.ident.dsc_base = 5
    assert s.signature_count() == 0
    s.ident.dsc_base = -(1 << 30)
    assert s.signature_count() == 0xFFFFFF
    s.set_signature_count(7)
    assert s.signature_count() == 7
