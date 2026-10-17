# SPDX-License-Identifier: GPL-3.0-only
"""OpenPGP device-menu functions and v4 fingerprints."""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from feuristic.apps.card.openpgp import const as pgp
from feuristic.apps.card.openpgp import keys as alg
from feuristic.apps.card.openpgp import localmgmt
from feuristic.core import i18n
from feuristic.core.errors import InvalidInput, PolicyDenied

from ...aio import run
from .conftest import Env, public_from_7f49

T = 1_800_000_000


def test_v4_fingerprint_rfc9580_ed25519_legacy_vector():
    """RFC 9580 Appendix A.3 sample v4 Ed25519Legacy key."""
    secret = bytes.fromhex("1a8b1ff05ded48e18bf50166c664ab023ea70003d78d9e41f5758a91d850f8d2")
    pub = alg.public_key(pgp.KIND_ED25519, secret)
    assert pub.hex() == "3f098994bdd916ed4053197934e4a87c80733a1280d62f8010992e43ee3b2406"
    fpr = alg.v4_fingerprint(pgp.KIND_ED25519, pub, 0x53F35F0B)
    assert fpr.hex().upper() == "C959BDBAFA32A2F89A153B678CFDE12197965A9A"
    assert alg.format_fingerprint(fpr) == "C959 BDBA FA32 A2F8 9A15 3B67 8CFD E121 9796 5A9A"


def test_v4_body_cv25519_layout():
    body = alg.v4_public_body(pgp.KIND_X25519, bytes(range(32)), T)
    assert body[0] == 4 and int.from_bytes(body[1:5], "big") == T
    assert body[5] == 0x12 and body[6] == 10 and body[7:17] == pgp.OID_CV25519
    assert body[17:19] == (263).to_bytes(2, "big") and body[19] == 0x40
    assert body[20:52] == bytes(range(32))
    assert body[52:] == b"\x03\x01\x08\x07"


def test_mpi_encoding():
    assert alg._mpi(b"\x00\x01") == b"\x00\x01\x01"
    assert alg._mpi(b"\x80") == b"\x00\x08\x80"
    assert alg._mpi(b"") == b"\x00\x00"


def test_generate_locally_and_use_from_host():
    e = Env()
    fprs = run(localmgmt.generate_keys(e.store, localmgmt.PROFILE_25519, T))
    assert len(fprs) == 3 and len(set(fprs)) == 3
    st = localmgmt.status(e.store)
    assert [k["present"] for k in st["keys"]] == [True, True, True]
    assert st["keys"][0]["algorithm"] == "Ed25519" and st["keys"][1]["algorithm"] == "Curve25519"
    assert st["keys"][0]["created"] == T
    assert st["keys"][0]["fingerprint"] == alg.format_fingerprint(fprs[0])
    e.select()
    assert e.get(0xC5)[0] == b"".join(fprs)
    assert e.get(0xCD)[0] == T.to_bytes(4, "big") * 3
    assert e.get(0xDE)[0] == bytes.fromhex("010102010301")
    pub = public_from_7f49(e.read_public(0xB6)[0])[0x86]
    assert alg.v4_fingerprint(pgp.KIND_ED25519, pub, T) == fprs[0]
    assert localmgmt.public_key(e.store, pgp.SIG) == pub
    e.verify(0x81, b"123456")
    sig, sw = e.tx(0x2A, 0x9E, 0x9A, b"\x42" * 32, ne=256)
    assert sw == 0x9000
    Ed25519PublicKey.from_public_bytes(pub).verify(sig, b"\x42" * 32)
    assert e.ui.prompts[-1].fingerprint == fprs[0].hex().upper()


def test_local_generation_drops_host_verification():
    e = Env()
    e.select()
    e.verify(0x81, b"123456")
    run(localmgmt.generate_keys(e.store, localmgmt.PROFILE_25519, T))
    assert e.tx(0x20, 0, 0x81)[1] == 0x63C3


def test_generate_validation():
    e = Env()
    with pytest.raises(InvalidInput):
        run(localmgmt.generate_keys(e.store, localmgmt.PROFILE_25519, 5))
    with pytest.raises(InvalidInput):
        run(localmgmt.generate_keys(e.store, "p521", T))
    with pytest.raises(InvalidInput):
        run(localmgmt.generate_keys(e.store, localmgmt.PROFILE_25519, None))
    e.store.terminate()
    with pytest.raises(PolicyDenied):
        run(localmgmt.generate_keys(e.store, localmgmt.PROFILE_25519, T))


def test_profiles():
    ids = [p for p, _ in localmgmt.profiles()]
    assert ids[0] == localmgmt.PROFILE_25519
    assert (localmgmt.PROFILE_RSA2048 in ids) == alg.rsa_available()
    for _, key in localmgmt.profiles():
        assert i18n.t(key) != key


def test_set_pins_locally():
    e = Env()
    localmgmt.set_pin(e.store, pgp.PW1, b"246810")
    localmgmt.set_pin(e.store, pgp.PW3, b"13579135")
    localmgmt.set_pin(e.store, pgp.RC, b"87654321")
    with pytest.raises(InvalidInput):
        localmgmt.set_pin(e.store, pgp.PW1, b"12345")
    with pytest.raises(InvalidInput):
        localmgmt.set_pin(e.store, pgp.PW3, b"1234567")
    with pytest.raises(InvalidInput):
        localmgmt.set_pin(e.store, 7, b"12345678")
    e.reboot().select()
    assert e.verify(0x81, b"246810") == 0x9000
    assert e.verify(0x83, b"13579135") == 0x9000
    assert localmgmt.status(e.store)["rc_set"]
    localmgmt.set_pin(e.store, pgp.RC, b"")
    assert not localmgmt.status(e.store)["rc_set"]
    assert localmgmt.status(e.store)["rc_retries"] == 0


def test_unblock_locally():
    e = Env()
    e.select()
    for _ in range(3):
        e.verify(0x83, b"00000000")
    assert localmgmt.status(e.store)["pw3_retries"] == 0
    localmgmt.unblock(e.store, pgp.PW3)
    assert localmgmt.status(e.store)["pw3_retries"] == 3
    assert e.verify(0x83, b"12345678") == 0x9000
    with pytest.raises(InvalidInput):
        localmgmt.unblock(e.store, 9)


def test_delete_keys_and_factory_reset():
    e = Env()
    run(localmgmt.generate_keys(e.store, localmgmt.PROFILE_25519, T))
    localmgmt.delete_keys(e.store, (pgp.DEC,))
    st = localmgmt.status(e.store)
    assert [k["present"] for k in st["keys"]] == [True, False, True]
    assert st["keys"][1]["fingerprint"] == "" and st["keys"][1]["created"] == 0
    localmgmt.set_pin(e.store, pgp.PW1, b"999999")
    localmgmt.factory_reset(e.store)
    st = localmgmt.status(e.store)
    assert not any(k["present"] for k in st["keys"])
    assert st["pw1_retries"] == 3 and not st["terminated"]
    e.select()
    assert e.verify(0x81, b"123456") == 0x9000
    with pytest.raises(InvalidInput):
        localmgmt.public_key(e.store, pgp.SIG)


def test_status_terminated():
    e = Env()
    e.store.terminate()
    st = localmgmt.status(e.store)
    assert st["terminated"] and st["signatures"] == 0
    with pytest.raises(PolicyDenied):
        localmgmt.set_pin(e.store, pgp.PW1, b"123456")


def test_i18n_complete():
    keys = [k for k in i18n.keys() if k.startswith("openpgp.")]  # noqa: SIM118 - i18n.keys() is a function
    assert len(keys) > 40
    assert not [k for k in i18n.missing_translations() if k.startswith("openpgp.")]
