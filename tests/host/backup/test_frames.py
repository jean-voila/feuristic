# SPDX-License-Identifier: GPL-3.0-only
import contextlib
import random

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from feuristic.apps.backup import frames
from feuristic.apps.backup.crc32 import crc32_bytes
from feuristic.apps.backup.errors import (
    FrameChecksumError,
    FrameConflict,
    FrameError,
    FrameFormatError,
    FrameIdMismatch,
    FrameIncomplete,
    FrameLimitExceeded,
    FrameTotalMismatch,
)
from feuristic.core import base45

BID = bytes.fromhex("0011223344556677")
BID2 = bytes.fromhex("8899aabbccddeeff")


def _env(n, seed=1):
    return random.Random(seed).randbytes(n)


def test_capacities():
    assert frames.chunk_capacity(frames.PROFILE_DENSE) == 156
    assert frames.chunk_capacity(frames.PROFILE_LARGE) == 22
    with pytest.raises(ValueError):
        frames.chunk_capacity("tiny")
    assert frames.frame_count(156, "dense") == 1
    assert frames.frame_count(157, "dense") == 2
    assert frames.frame_count(22 * 999, "large") == 999


def test_frame_binary_layout():
    text = frames.encode_frame(BID, 2, 3, b"chunk")
    assert text.startswith("FB1:")
    binary = base45.decode(text[4:])
    assert binary[:8] == BID
    assert binary[8:10] == b"\x00\x02"
    assert binary[10:12] == b"\x00\x03"
    assert binary[12:-4] == b"chunk"
    assert binary[-4:] == crc32_bytes(binary[:-4])
    f = frames.parse_frame(text)
    assert (f.backup_id, f.index, f.total, f.chunk) == (BID, 2, 3, b"chunk")
    assert frames.parse_frame(text.encode()).chunk == b"chunk"
    assert "2/3" in repr(f)


def test_encode_frame_bounds():
    for args in [
        (BID[:7], 1, 1, b"x"),
        (BID, 0, 1, b"x"),
        (BID, 2, 1, b"x"),
        (BID, 1, 1000, b"x"),
        (BID, 1, 1, b""),
    ]:
        with pytest.raises(ValueError):
            frames.encode_frame(*args)


@pytest.mark.parametrize("profile", ["dense", "large"])
@pytest.mark.parametrize("n", [1, 2, 21, 22, 23, 155, 156, 157, 500, 1234])
def test_split_reassemble_in_order(profile, n):
    env = _env(n)
    texts = frames.split(env, BID, profile)
    assert len(texts) == frames.frame_count(n, profile)
    max_chars = frames.PROFILES[profile][1]
    sizes = []
    for i, t in enumerate(texts):
        assert len(t) <= max_chars
        f = frames.parse_frame(t)
        assert f.index == i + 1 and f.total == len(texts) and f.backup_id == BID
        sizes.append(len(f.chunk))
    assert max(sizes) - min(sizes) <= 1  # balanced
    r = frames.Reassembler()
    for t in texts:
        assert r.add(t) is True
    assert r.is_complete() and r.missing() == []
    assert r.assemble() == env


def test_split_errors():
    with pytest.raises(ValueError):
        frames.split(b"", BID)
    with pytest.raises(ValueError):
        frames.split(bytes(65537), BID)
    with pytest.raises(ValueError):
        frames.split(bytes(22 * 999 + 1), BID, "large")


def test_max_size_envelope_dense():
    env = _env(65536)
    texts = frames.split(env, BID, "dense")
    assert len(texts) == 421
    r = frames.Reassembler()
    for t in reversed(texts):
        r.add(t)
    assert r.assemble() == env


def test_shuffled_with_duplicates():
    env = _env(2000)
    texts = frames.split(env, BID, "large")
    rng = random.Random(7)
    stream = texts + rng.sample(texts, 30)
    rng.shuffle(stream)
    r = frames.Reassembler(BID)
    results = [r.add(t) for t in stream]
    assert results.count(True) == len(texts)
    assert results.count(False) == 30
    assert r.assemble() == env


def test_missing_reported_and_blocks():
    texts = frames.split(_env(1000), BID, "dense")  # 7 frames
    r = frames.Reassembler()
    assert r.missing() == []  # unknown total before the first frame
    assert not r.is_complete()
    for i in (0, 2, 3, 6):
        r.add(texts[i])
    assert r.missing() == [2, 5, 6]
    assert r.missing(limit=2) == [2, 5]
    with pytest.raises(FrameIncomplete) as ei:
        r.assemble()
    assert ei.value.missing == [2, 5, 6]
    with pytest.raises(FrameIncomplete):
        frames.Reassembler().assemble()


def test_mismatched_backup_id():
    a = frames.split(_env(400), BID, "dense")
    b = frames.split(_env(400, 2), BID2, "dense")
    r = frames.Reassembler()
    r.add(a[0])
    with pytest.raises(FrameIdMismatch):
        r.add(b[1])
    r2 = frames.Reassembler(BID)
    with pytest.raises(FrameIdMismatch):
        r2.add(b[0])
    assert r2.received == 0 and r2.total is None


def test_total_mismatch():
    r = frames.Reassembler()
    r.add(frames.encode_frame(BID, 1, 3, b"a"))
    with pytest.raises(FrameTotalMismatch):
        r.add(frames.encode_frame(BID, 2, 4, b"b"))
    assert r.received == 1


def test_conflicting_duplicate():
    r = frames.Reassembler()
    r.add(frames.encode_frame(BID, 1, 2, b"aaa"))
    assert r.add(frames.encode_frame(BID, 1, 2, b"aaa")) is False
    with pytest.raises(FrameConflict):
        r.add(frames.encode_frame(BID, 1, 2, b"aab"))
    assert r.received == 1 and r.bytes_received == 3


def test_checksum_errors():
    text = frames.encode_frame(BID, 1, 1, b"payload bytes")
    binary = bytearray(base45.decode(text[4:]))
    for pos in range(len(binary)):
        bad = bytearray(binary)
        bad[pos] ^= 0x01
        with pytest.raises(FrameChecksumError):
            frames.parse_frame("FB1:" + base45.encode(bytes(bad)))


@pytest.mark.parametrize(
    "text",
    [
        "",
        "FB1:",
        "FB2:" + base45.encode(bytes(20)),
        "fb1:" + base45.encode(bytes(20)),
        "XFB1:",
        "FB1:" + "A",  # dangling Base45 character
        "FB1:" + "GGW",
        "FB1:" + base45.encode(bytes(16)),  # too short (no chunk)
        "FB1:abc",
        "FB1:" + "0" * 2000,  # too long
        "FB1:é",
    ],
)
def test_format_errors(text):
    with pytest.raises(FrameFormatError):
        frames.parse_frame(text)


def test_format_errors_index_range():
    def raw(index, total):
        body = BID + index.to_bytes(2, "big") + total.to_bytes(2, "big") + b"x"
        return "FB1:" + base45.encode(body + crc32_bytes(body))

    for idx, tot in [(0, 1), (2, 1), (1, 0), (1, 1000), (1000, 1000)]:
        with pytest.raises(FrameFormatError):
            frames.parse_frame(raw(idx, tot))
    assert frames.parse_frame(raw(999, 999)).index == 999
    with pytest.raises(FrameFormatError):
        frames.parse_frame(12345)


def test_limits():
    r = frames.Reassembler(max_frames=5)
    with pytest.raises(FrameLimitExceeded):
        r.add(frames.encode_frame(BID, 1, 6, b"a"))
    r = frames.Reassembler(max_bytes=5)
    r.add(frames.encode_frame(BID, 1, 3, b"abc"))
    with pytest.raises(FrameLimitExceeded):
        r.add(frames.encode_frame(BID, 2, 3, b"def"))
    # duplicates are recognised before the byte budget
    assert r.add(frames.encode_frame(BID, 1, 3, b"abc")) is False
    r.add(frames.encode_frame(BID, 2, 3, b"de"))
    assert r.bytes_received == 5


@settings(max_examples=60, deadline=None)
@given(st.binary(min_size=1, max_size=1500), st.sampled_from(["dense", "large"]), st.randoms())
def test_hypothesis_roundtrip_any_order(env, profile, rnd):
    texts = frames.split(env, BID, profile)
    rnd.shuffle(texts)
    r = frames.Reassembler()
    for t in texts + texts[: len(texts) // 2]:
        r.add(t)
    assert r.assemble() == env


@settings(max_examples=300)
@given(st.binary(max_size=300))
def test_parse_fuzz_only_frame_errors(data):
    for candidate in (data, b"FB1:" + data):
        with contextlib.suppress(FrameError):
            frames.parse_frame(candidate)
