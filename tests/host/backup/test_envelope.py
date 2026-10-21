# SPDX-License-Identifier: GPL-3.0-only
import contextlib
import hashlib

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from feuristic.apps.backup import envelope
from feuristic.apps.backup.errors import (
    AuthenticationFailed,
    BackupFormatError,
    PlaintextError,
    UnsupportedParameters,
    UnsupportedVersion,
    WeakPassphrase,
)
from feuristic.core import cbor
from feuristic.core.errors import InvalidInput
from feuristic.platform import crypto

from ..aio import run
from .fakes import PASSPHRASE, make_raw_envelope

ITEM = {"type": "fake", "v": 1, "name": "alice", "secret": bytes(range(32))}
SALT = bytes(range(16))


def _key(passphrase=PASSPHRASE, salt=SALT):
    return run(envelope.derive_key(passphrase, salt))


def _seal(key=None, kind=envelope.KIND_IDENTITY, items=(ITEM,), **kw):
    return envelope.seal(key if key is not None else _key(), SALT, kind, list(items), **kw)


# ---------------------------------------------------------------------------
# constants mandated by the spec
# ---------------------------------------------------------------------------


def test_spec_constants():
    # spec §8.2: PBKDF2-HMAC-SHA-256, 600 000 iterations, 16-byte salt, 12-byte nonce
    assert envelope.ITERATIONS == 600_000
    assert envelope.SALT_LEN == 16
    assert envelope.NONCE_LEN == 12
    assert envelope.TAG_LEN == 16
    assert envelope.KEY_LEN == 32
    assert envelope.PASSPHRASE_MIN_LEN == 12
    assert envelope.MAGIC == b"FEBK"
    assert envelope.VERSION == 1


def test_real_kdf_matches_reference():
    """600 000 iterations through the incremental API equal hashlib's PBKDF2."""
    progress = []
    key = run(envelope.derive_key(PASSPHRASE, SALT, progress=lambda d, t: progress.append((d, t))))
    assert bytes(key) == hashlib.pbkdf2_hmac("sha256", PASSPHRASE, SALT, 600_000)
    assert progress[0] == (0, 600_000)
    assert progress[-1] == (600_000, 600_000)
    assert len(progress) == 1 + (600_000 + envelope.KDF_CHUNK - 1) // envelope.KDF_CHUNK


# ---------------------------------------------------------------------------
# passphrase policy
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pw",
    [b"a" * 12, b" " * 12, b"~" * 128, b"Tr0ub4dor&3 horse", bytearray(b"twelve chars")],
)
def test_passphrase_ok(pw):
    envelope.check_passphrase(pw)


@pytest.mark.parametrize(
    "pw",
    [
        b"",
        b"a" * 11,
        b"a" * 129,
        b"twelve char\x7f",
        b"twelve char\x1f",
        b"twelve chars\n",
        "twelve chars ok".encode("utf-16"),
        "mot de passe été".encode(),
        "twelve chars",  # str is not accepted: must be bytes
        None,
        123456789012,
    ],
)
def test_passphrase_rejected(pw):
    with pytest.raises(WeakPassphrase):
        envelope.check_passphrase(pw)


def test_passphrases_match():
    assert envelope.passphrases_match(b"abcdefghijkl", bytearray(b"abcdefghijkl"))
    assert not envelope.passphrases_match(b"abcdefghijkl", b"abcdefghijkm")
    assert not envelope.passphrases_match(b"abcdefghijkl", b"abcdefghijklm")


def test_derive_key_rejects_bad_input(fast_kdf):
    with pytest.raises(WeakPassphrase):
        run(envelope.derive_key(b"short", SALT))
    with pytest.raises(InvalidInput):
        run(envelope.derive_key(PASSPHRASE, b"\x00" * 15))
    with pytest.raises(InvalidInput):
        run(envelope.derive_key(PASSPHRASE, SALT, iterations=0))


def test_derive_key_progress_and_yield(fast_kdf):
    seen = []
    yields = []

    async def yield_fn():
        yields.append(1)

    key = run(envelope.derive_key(PASSPHRASE, SALT, lambda d, t: seen.append(d), yield_fn))
    assert isinstance(key, bytearray)
    assert bytes(key) == hashlib.pbkdf2_hmac("sha256", PASSPHRASE, SALT, 1000)
    assert seen == [0, 300, 600, 900, 1000]
    assert len(yields) == 3  # not after the last step
    # chunking does not change the result
    assert bytes(run(envelope.derive_key(PASSPHRASE, SALT, iterations=1))) == hashlib.pbkdf2_hmac(
        "sha256", PASSPHRASE, SALT, 1
    )


# ---------------------------------------------------------------------------
# round trip
# ---------------------------------------------------------------------------


def test_roundtrip_identity(fast_kdf):
    key = _key()
    env = _seal(key, created=1_800_000_000)
    c = envelope.open_with_key(env, key)
    assert c.kind == envelope.KIND_IDENTITY
    assert c.items == [ITEM]
    assert c.created == 1_800_000_000
    assert c.seq is None and c.count is None
    h = envelope.parse_header(env)
    assert h.salt == SALT and len(h.nonce) == 12 and len(h.backup_id) == 8
    assert h.iterations == 1000
    assert c.backup_id == h.backup_id
    # via passphrase
    c2 = run(envelope.open_envelope(env, PASSPHRASE))
    assert c2.items == [ITEM]


def test_roundtrip_full(fast_kdf):
    key = _key()
    env = _seal(key, kind=envelope.KIND_FULL, seq=2, count=5)
    c = envelope.open_with_key(env, key)
    assert (c.kind, c.seq, c.count, c.created) == (envelope.KIND_FULL, 2, 5, None)
    assert envelope.kind_name(c.kind) == "full"
    assert envelope.kind_name(99) == "?"


def test_borrowed_plaintext_arena_is_wiped_and_never_aliases_returned_items(fast_kdf, monkeypatch):
    from feuristic.core import store

    key = _key()
    item = dict(ITEM, secret=b"s" * 4096)
    raw = bytearray(_seal(key, items=[item]))
    original = bytes(raw)
    arena = bytearray(5440)
    previous = store.use_write_buffer(arena)

    def no_full_plaintext_copy(*args):
        raise AssertionError("borrowed open allocated a second plaintext")

    monkeypatch.setattr(crypto, "aes256_gcm_decrypt", no_full_plaintext_copy)
    try:
        contents = envelope.open_with_key(raw, key)
        assert contents.items == [item] and bytes(raw) == original and not any(arena)
        raw[-1] ^= 1
        with pytest.raises(AuthenticationFailed):
            envelope.open_with_key(raw, key)
        assert not any(arena) and contents.items == [item]
        with pytest.raises(PlaintextError):
            envelope.open_with_key(make_raw_envelope(key, SALT, b"\xff"), key)
        assert not any(arena)
    finally:
        store.use_write_buffer(previous)


def test_layout(fast_kdf):
    key = _key()
    env = _seal(key, backup_id=b"\xaa" * 8)
    assert env[:4] == b"FEBK" and env[4] == 1
    hlen = int.from_bytes(env[5:7], "big")
    hdr = cbor.decode(env[7 : 7 + hlen], canonical=True)
    assert sorted(hdr) == [1, 2, 3, 4, 5, 6, 7]
    assert hdr[1] == 1 and hdr[2] == b"\xaa" * 8 and hdr[3] == 1 and hdr[4] == 1000
    assert hdr[5] == SALT and hdr[6] == 1 and len(hdr[7]) == 12
    ct, tag = env[7 + hlen : -16], env[-16:]
    pt = crypto.aes256_gcm_decrypt(bytes(key), hdr[7], ct, tag, env[: 7 + hlen])
    assert pt == cbor.encode({"v": 1, "kind": "identity", "items": [ITEM]})


def test_unique_nonce_and_id_per_seal(fast_kdf):
    key = _key()
    headers = [envelope.parse_header(_seal(key)) for _ in range(20)]
    assert len({h.nonce for h in headers}) == 20
    assert len({h.backup_id for h in headers}) == 20


def test_key_independent_of_device(fast_kdf):
    """Same passphrase + salt ⇒ same key on any device (spec §8.3): the KDF
    uses nothing but its inputs."""
    assert bytes(_key()) == hashlib.pbkdf2_hmac("sha256", PASSPHRASE, SALT, 1000)


def test_seal_rejects_bad_args(fast_kdf):
    key = _key()
    with pytest.raises(InvalidInput):
        envelope.seal(b"short", SALT, 1, [ITEM])
    with pytest.raises(InvalidInput):
        envelope.seal(key, SALT, 3, [ITEM])
    with pytest.raises(InvalidInput):
        envelope.seal(key, SALT, 1, [ITEM], seq=1, count=1)
    with pytest.raises(InvalidInput):
        envelope.seal(key, SALT, 2, [ITEM])  # full needs seq/count
    with pytest.raises(InvalidInput):
        envelope.seal(key, SALT, 1, [ITEM, ITEM])
    with pytest.raises(InvalidInput):
        envelope.seal(key, SALT, 1, [{"type": "BAD", "v": 1}])
    with pytest.raises(InvalidInput):
        envelope.seal(key, SALT, 1, [dict(ITEM, blob=bytes(70000))])
    with pytest.raises(InvalidInput):
        envelope.encode_header(1, b"\x00" * 7, SALT, bytes(12))
    with pytest.raises(InvalidInput):
        envelope.encode_header(5, b"\x00" * 8, SALT, bytes(12))


# ---------------------------------------------------------------------------
# authentication / tampering
# ---------------------------------------------------------------------------


def test_wrong_passphrase(fast_kdf):
    env = _seal()
    with pytest.raises(AuthenticationFailed):
        run(envelope.open_envelope(env, b"wrong horse battery staple"))
    with pytest.raises(WeakPassphrase):
        run(envelope.open_envelope(env, b"short"))


def test_tamper_every_byte(fast_kdf):
    """Flipping any bit anywhere is detected: before authentication by the
    strict header checks, otherwise by the GCM tag. Never a plaintext."""
    key = _key()
    env = _seal(key)
    for pos in range(len(env)):
        for bit in (0, 7):
            bad = bytearray(env)
            bad[pos] ^= 1 << bit
            with pytest.raises((AuthenticationFailed, BackupFormatError)):
                envelope.open_with_key(bytes(bad), key)


def _resealed_header(env, **changes):
    """Re-encode the header with changed (but well-formed) fields, keep the body."""
    h = envelope.parse_header(env)
    fields = {
        "kind": h.kind,
        "backup_id": h.backup_id,
        "salt": h.salt,
        "nonce": h.nonce,
    }
    fields.update(changes)
    aad = envelope.encode_header(fields["kind"], fields["backup_id"], fields["salt"], fields["nonce"])
    return aad + env[h.body_offset :]


@pytest.mark.parametrize(
    "change",
    [
        {"kind": 2},
        {"backup_id": b"\x00" * 8},
        {"salt": b"\x55" * 16},
        {"nonce": b"\x00" * 12},
    ],
)
def test_header_field_changes_fail_authentication(fast_kdf, change):
    key = _key()
    env = _seal(key)
    bad = _resealed_header(env, **change)
    envelope.parse_header(bad)  # still a well-formed header
    with pytest.raises(AuthenticationFailed):
        envelope.open_with_key(bad, key)
    if "salt" in change:  # with the passphrase a different key is derived
        with pytest.raises(AuthenticationFailed):
            run(envelope.open_envelope(bad, PASSPHRASE))


def test_ciphertext_and_tag_tamper(fast_kdf):
    key = _key()
    env = _seal(key)
    hlen = envelope.parse_header(env).body_offset
    for pos in (hlen, hlen + 5, len(env) - 17, len(env) - 16, len(env) - 1):
        bad = bytearray(env)
        bad[pos] ^= 0x80
        with pytest.raises(AuthenticationFailed):
            envelope.open_with_key(bytes(bad), key)
    with pytest.raises(BackupFormatError):
        envelope.open_with_key(env[:-1][: hlen + 16], key)  # truncated
    with pytest.raises(AuthenticationFailed):
        envelope.open_with_key(env[:-1], key)
    with pytest.raises(AuthenticationFailed):
        envelope.open_with_key(env + b"\x00", key)


def test_swapped_tag_between_envelopes(fast_kdf):
    key = _key()
    a, b = _seal(key), _seal(key)
    with pytest.raises(AuthenticationFailed):
        envelope.open_with_key(a[:-16] + b[-16:], key)


# ---------------------------------------------------------------------------
# header parsing (pre-authentication, strict)
# ---------------------------------------------------------------------------


def _header_bytes(h: dict, version=1, magic=b"FEBK"):
    raw = cbor.encode(h)
    return magic + bytes((version,)) + len(raw).to_bytes(2, "big") + raw + b"\x00" * 40


GOOD_H = {1: 1, 2: b"\x01" * 8, 3: 1, 4: 1000, 5: SALT, 6: 1, 7: b"\x02" * 12}


def test_header_good(fast_kdf):
    h = envelope.parse_header(_header_bytes(GOOD_H))
    assert h.kind == 1 and h.iterations == 1000


@pytest.mark.parametrize(
    ("mutation", "exc"),
    [
        ({1: 0}, BackupFormatError),
        ({1: 3}, BackupFormatError),
        ({1: True}, BackupFormatError),
        ({2: b"\x01" * 7}, BackupFormatError),
        ({2: "id"}, BackupFormatError),
        ({3: 2}, UnsupportedParameters),
        ({4: 999}, UnsupportedParameters),
        ({4: 600_000}, UnsupportedParameters),  # fast_kdf: only the configured count
        ({4: -1}, UnsupportedParameters),
        ({5: b"\x00" * 15}, BackupFormatError),
        ({5: b"\x00" * 17}, BackupFormatError),
        ({6: 2}, UnsupportedParameters),
        ({7: b"\x00" * 16}, BackupFormatError),
        ({8: 0}, BackupFormatError),  # unknown key
    ],
)
def test_header_invalid_fields(fast_kdf, mutation, exc):
    h = dict(GOOD_H)
    h.update(mutation)
    with pytest.raises(exc):
        envelope.parse_header(_header_bytes(h))


def test_header_missing_field(fast_kdf):
    for k in GOOD_H:
        h = dict(GOOD_H)
        del h[k]
        with pytest.raises(BackupFormatError):
            envelope.parse_header(_header_bytes(h))


def test_header_prefix_errors(fast_kdf):
    with pytest.raises(BackupFormatError):
        envelope.parse_header(_header_bytes(GOOD_H, magic=b"FEBX"))
    with pytest.raises(UnsupportedVersion):
        envelope.parse_header(_header_bytes(GOOD_H, version=2))
    with pytest.raises(UnsupportedVersion):
        envelope.parse_header(_header_bytes(GOOD_H, version=0))
    assert issubclass(UnsupportedVersion, BackupFormatError)
    with pytest.raises(BackupFormatError):
        envelope.parse_header(b"")
    with pytest.raises(BackupFormatError):
        envelope.parse_header(b"FEBK")
    with pytest.raises(BackupFormatError):
        envelope.parse_header("FEBK not bytes")
    with pytest.raises(BackupFormatError):
        envelope.parse_header(b"FEBK\x01\x00\x00" + bytes(40))  # H = 0
    with pytest.raises(BackupFormatError):
        envelope.parse_header(b"FEBK\x01\x00\x61" + bytes(200))  # H = 97 > 96
    with pytest.raises(BackupFormatError):
        envelope.parse_header(b"FEBK\x01" + bytes(70000))  # too long


def test_header_non_canonical_rejected(fast_kdf):
    good = cbor.encode(GOOD_H)
    # kind encoded with a 1-byte argument (0x18 0x01) instead of the short form
    non_canonical = good.replace(b"\x01\x01", b"\x01\x18\x01", 1)
    assert non_canonical != good
    env = b"FEBK\x01" + len(non_canonical).to_bytes(2, "big") + non_canonical + bytes(40)
    with pytest.raises(BackupFormatError):
        envelope.parse_header(env)
    # keys out of canonical order
    items = b"".join(cbor.encode(k) + cbor.encode(GOOD_H[k]) for k in (2, 1, 3, 4, 5, 6, 7))
    raw = b"\xa7" + items
    env = b"FEBK\x01" + len(raw).to_bytes(2, "big") + raw + bytes(40)
    with pytest.raises(BackupFormatError):
        envelope.parse_header(env)


def test_header_body_too_short(fast_kdf):
    raw = cbor.encode(GOOD_H)
    env = b"FEBK\x01" + len(raw).to_bytes(2, "big") + raw + bytes(16)  # tag only, no ciphertext
    with pytest.raises(BackupFormatError):
        envelope.parse_header(env)


@settings(max_examples=300)
@given(st.binary(max_size=200))
def test_header_fuzz(data):
    with contextlib.suppress(BackupFormatError):
        envelope.parse_header(b"FEBK\x01" + data)


# ---------------------------------------------------------------------------
# plaintext validation (after authentication)
# ---------------------------------------------------------------------------


def test_non_canonical_plaintext_rejected_even_if_authenticated(fast_kdf):
    key = _key()
    good = cbor.encode({"v": 1, "kind": "identity", "items": [ITEM]})
    assert envelope.open_with_key(make_raw_envelope(key, SALT, good), key).items == [ITEM]
    # 1) map keys in non-canonical order ("v" must come first: shortest key)
    pt = b"\xa3" + cbor.encode("kind") + cbor.encode("identity") + cbor.encode("v") + b"\x01"
    pt += cbor.encode("items") + cbor.encode([ITEM])
    with pytest.raises(PlaintextError):
        envelope.open_with_key(make_raw_envelope(key, SALT, pt), key)
    # 2) non-shortest integer
    pt2 = good.replace(cbor.encode("v") + b"\x01", cbor.encode("v") + b"\x18\x01", 1)
    assert pt2 != good
    with pytest.raises(PlaintextError):
        envelope.open_with_key(make_raw_envelope(key, SALT, pt2), key)
    # 3) trailing bytes, indefinite length, float, tag
    for raw in (good + b"\x00", b"\xbf\xff", b"\xfb" + bytes(8), b"\xc1\x00", b"\xf7"):
        with pytest.raises(PlaintextError):
            envelope.open_with_key(make_raw_envelope(key, SALT, raw), key)


def _pt(**fields):
    base = {"v": 1, "kind": "identity", "items": [ITEM]}
    base.update(fields)
    return {k: v for k, v in base.items() if v is not None}


@pytest.mark.parametrize(
    ("pt", "kind"),
    [
        (["not", "a", "map"], 1),
        (_pt(v=2), 1),
        (_pt(v=True), 1),
        (_pt(kind="full"), 1),  # header says identity
        (_pt(kind="identity"), 2),  # header says full
        (_pt(kind="other"), 1),
        (_pt(items=[]), 1),
        (_pt(items=[ITEM, ITEM]), 1),  # identity: exactly one item
        (_pt(items=ITEM), 1),
        (_pt(items=["x"]), 1),
        (_pt(items=[{"type": "fake"}]), 1),
        (_pt(items=[{"type": "Fake", "v": 1}]), 1),
        (_pt(items=[{"type": "fake", "v": 0}]), 1),
        (_pt(items=[{"type": "fake", "v": 256}]), 1),
        (_pt(items=[{"type": "fake", "v": True}]), 1),
        (_pt(items=[{"type": "fake", "v": 1, 5: 1}]), 1),
        (_pt(extra=1), 1),
        (_pt(created=-1), 1),
        (_pt(created=2**32), 1),
        (_pt(created="today"), 1),
        (_pt(seq=1, count=1), 1),  # seq/count only for full
        (_pt(kind="full"), 2),  # full without seq/count
        (_pt(kind="full", seq=0, count=3), 2),
        (_pt(kind="full", seq=4, count=3), 2),
        (_pt(kind="full", seq=1, count=0), 2),
        (_pt(kind="full", seq=1, count=1025), 2),
        (_pt(kind="full", seq=1, count=2, items=[ITEM] * 17), 2),
    ],
)
def test_plaintext_schema_rejections(fast_kdf, pt, kind):
    key = _key()
    env = make_raw_envelope(key, SALT, cbor.encode(pt), kind=kind)
    with pytest.raises(PlaintextError):
        envelope.open_with_key(env, key)


def test_plaintext_full_with_several_items_accepted(fast_kdf):
    """Decoders accept up to 16 items per envelope (forward compatibility)."""
    key = _key()
    pt = _pt(kind="full", seq=1, count=1, items=[ITEM] * 16)
    c = envelope.open_with_key(make_raw_envelope(key, SALT, cbor.encode(pt), kind=2), key)
    assert len(c.items) == 16


def test_plaintext_depth_limit(fast_kdf):
    key = _key()
    deep = []
    for _ in range(6):
        deep = [deep]
    item_ok = dict(ITEM, deep=[[[[[]]]]])
    item_bad = dict(ITEM, deep=[[[[[[0]]]]]])
    env = make_raw_envelope(key, SALT, cbor.encode(_pt(items=[item_ok])))
    assert envelope.open_with_key(env, key).items == [item_ok]
    env = make_raw_envelope(key, SALT, cbor.encode(_pt(items=[item_bad])))
    with pytest.raises(PlaintextError):
        envelope.open_with_key(env, key)


# ---------------------------------------------------------------------------
# key cache
# ---------------------------------------------------------------------------


def test_key_cache_and_wipe(fast_kdf):
    cache = envelope.KeyCache()
    env = _seal()
    run(envelope.open_envelope(env, PASSPHRASE, cache=cache))
    assert len(cache) == 1
    key = cache.get(SALT)
    assert bytes(key) == hashlib.pbkdf2_hmac("sha256", PASSPHRASE, SALT, 1000)
    # second open reuses the key: no derivation (progress never called)
    calls = []
    run(envelope.open_envelope(env, PASSPHRASE, progress=lambda d, t: calls.append(d), cache=cache))
    assert calls == []
    cache.wipe()
    assert key == bytearray(32)
    assert len(cache) == 0 and cache.get(SALT) is None


def test_key_cache_not_poisoned_by_wrong_passphrase(fast_kdf):
    cache = envelope.KeyCache()
    env = _seal()
    with pytest.raises(AuthenticationFailed):
        run(envelope.open_envelope(env, b"wrong horse battery", cache=cache))
    assert len(cache) == 0
    assert run(envelope.open_envelope(env, PASSPHRASE, cache=cache)).items == [ITEM]
    assert len(cache) == 1
