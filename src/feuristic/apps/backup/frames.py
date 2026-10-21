# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Numbered QR frames carrying an encrypted envelope (spec §8.2; format doc §5).

Frame text::

    "FB1:" || Base45( backup_id(8) | index(u16 BE) | total(u16 BE) | chunk | crc32(4) )

* ``index`` is 1-based (``1 ≤ index ≤ total ≤ 999``);
* ``crc32`` is the CRC-32/ISO-HDLC of all preceding binary bytes (a
  transport checksum against misreads — authenticity comes from the GCM tag);
* the prefix and Base45 alphabet are both inside the QR alphanumeric set, so
  a frame is a single alphanumeric-mode QR segment.

Display profiles for the 128 × 64 screen (ECC level M):

=========  ===========  ==============  ==============  ===========
profile    QR version   modules (side)  max text chars  chunk bytes
=========  ===========  ==============  ==============  ===========
dense      ≤ 9          ≤ 53            262             156
large      ≤ 3          ≤ 29            61              22
=========  ===========  ==============  ==============  ===========

Reassembly accepts frames in any order, ignores exact duplicates and
rejects (with specific errors) a different backup id, a different total, a
conflicting duplicate, a bad CRC or exceeded bounds. Nothing is assembled
until every index is present.
"""

from micropython import const

from ...core import base45
from .crc32 import crc32_bytes
from .errors import (
    FrameChecksumError,
    FrameConflict,
    FrameFormatError,
    FrameIdMismatch,
    FrameIncomplete,
    FrameLimitExceeded,
    FrameTotalMismatch,
)

PREFIX = "FB1:"
_PREFIX_B = b"FB1:"
BACKUP_ID_LEN = const(8)
CRC_LEN = const(4)
HEADER_LEN = const(12)  # backup id + index + total
OVERHEAD = const(HEADER_LEN + CRC_LEN)

MAX_FRAMES = const(999)
MAX_TOTAL_BYTES = const(65536)
#: largest frame text accepted by the parser (frames re-encoded at a higher
#: QR version by third-party tools remain readable; we never emit > 262)
MAX_FRAME_TEXT = const(1024)

PROFILE_DENSE = "dense"
PROFILE_LARGE = "large"
#: profile -> (max QR version at ECC M, max alphanumeric characters incl. prefix)
PROFILES = {
    PROFILE_DENSE: (9, 262),
    PROFILE_LARGE: (3, 61),
}


class Frame:
    """A parsed, CRC-verified frame."""

    def __init__(self, backup_id: bytes, index: int, total: int, chunk: bytes) -> None:
        self.backup_id = backup_id
        self.index = index
        self.total = total
        self.chunk = chunk

    def __repr__(self) -> str:
        return f"Frame({self.backup_id.hex()}, {self.index}/{self.total}, {len(self.chunk)}B)"


def chunk_capacity(profile: str) -> int:
    """Maximum chunk bytes per frame for ``profile``."""
    if profile not in PROFILES:
        raise ValueError("unknown frame profile")
    max_chars = PROFILES[profile][1] - len(PREFIX)
    return base45.max_decoded_length(max_chars) - OVERHEAD


def frame_count(envelope_len: int, profile: str) -> int:
    """Number of frames :func:`split` produces for an envelope of that size."""
    cap = chunk_capacity(profile)
    return (envelope_len + cap - 1) // cap


def encode_frame(backup_id: bytes, index: int, total: int, chunk: bytes) -> str:
    """Encode one frame text."""
    if len(backup_id) != BACKUP_ID_LEN:
        raise ValueError("backup id length")
    if not 1 <= total <= MAX_FRAMES or not 1 <= index <= total:
        raise ValueError("frame index/total")
    if len(chunk) < 1:
        raise ValueError("empty chunk")
    body = bytes(backup_id) + index.to_bytes(2, "big") + total.to_bytes(2, "big") + bytes(chunk)
    return PREFIX + base45.encode(body + crc32_bytes(body))


def split(envelope, backup_id, profile: str = PROFILE_DENSE) -> list:
    """Split ``envelope`` into frame texts for ``profile``.

    Chunks are balanced (their sizes differ by at most one byte) so every QR
    of a sequence has the same version. Raises ``ValueError`` if the envelope
    is empty or would need more than :data:`MAX_FRAMES` frames / bytes.
    """
    data = bytes(envelope)
    n = len(data)
    if n == 0:
        raise ValueError("empty envelope")
    if n > MAX_TOTAL_BYTES:
        raise ValueError("envelope too large for frames")
    total = frame_count(n, profile)
    if total > MAX_FRAMES:
        raise ValueError("too many frames")
    base = n // total
    extra = n - base * total  # the first `extra` chunks get one more byte
    out = []
    pos = 0
    for i in range(total):
        size = base + (1 if i < extra else 0)
        out.append(encode_frame(backup_id, i + 1, total, data[pos : pos + size]))
        pos += size
    return out


def parse_frame(text) -> Frame:
    """Parse and verify one frame text (``str`` or ASCII bytes)."""
    if isinstance(text, str):
        raw = text.encode()
        if len(raw) != len(text):
            raise FrameFormatError("non-ASCII frame")
    elif isinstance(text, (bytes, bytearray, memoryview)):
        raw = bytes(text)
    else:
        raise FrameFormatError("frame type")
    if len(raw) > MAX_FRAME_TEXT:
        raise FrameFormatError("frame too long")
    if raw[: len(_PREFIX_B)] != _PREFIX_B:
        raise FrameFormatError("frame prefix")
    try:
        binary = base45.decode(raw[len(_PREFIX_B) :], MAX_FRAME_TEXT)
    except base45.Base45Error:
        raise FrameFormatError("frame encoding")
    if len(binary) < OVERHEAD + 1:
        raise FrameFormatError("frame too short")
    body = binary[: len(binary) - CRC_LEN]
    if crc32_bytes(body) != binary[len(binary) - CRC_LEN :]:
        raise FrameChecksumError("frame checksum")
    index = int.from_bytes(body[8:10], "big")
    total = int.from_bytes(body[10:12], "big")
    if not 1 <= total <= MAX_FRAMES or not 1 <= index <= total:
        raise FrameFormatError("frame index/total")
    return Frame(bytes(body[0:8]), index, total, bytes(body[HEADER_LEN:]))


class Reassembler:
    """Collects the frames of **one** backup (one backup id).

    ``add`` returns True for a new frame and False for an exact duplicate;
    any inconsistency raises a :class:`~feuristic.apps.backup.errors.FrameError`
    subclass and leaves the state unchanged.
    """

    def __init__(
        self, backup_id=None, max_frames: int = MAX_FRAMES, max_bytes: int = MAX_TOTAL_BYTES
    ) -> None:
        self.backup_id = None if backup_id is None else bytes(backup_id)
        self.total = None
        self.max_frames = max_frames
        self.max_bytes = max_bytes
        self._chunks = None
        self.received = 0
        self.bytes_received = 0

    def add(self, frame) -> bool:
        if not isinstance(frame, Frame):
            frame = parse_frame(frame)
        if self.backup_id is not None and frame.backup_id != self.backup_id:
            raise FrameIdMismatch("frame from another backup")
        if self.total is not None and frame.total != self.total:
            raise FrameTotalMismatch("frame total differs")
        if self.total is None and frame.total > self.max_frames:
            raise FrameLimitExceeded("too many frames")
        if self._chunks is not None:
            prev = self._chunks[frame.index - 1]
            if prev is not None:
                if prev == frame.chunk:
                    return False
                raise FrameConflict("conflicting duplicate frame")
        if self.bytes_received + len(frame.chunk) > self.max_bytes:
            raise FrameLimitExceeded("backup too large")
        # all checks passed: commit
        if self._chunks is None:
            self.backup_id = frame.backup_id
            self.total = frame.total
            self._chunks = [None] * frame.total
        self._chunks[frame.index - 1] = frame.chunk
        self.received += 1
        self.bytes_received += len(frame.chunk)
        return True

    def is_complete(self) -> bool:
        return self.total is not None and self.received == self.total

    def missing(self, limit=None) -> list:
        """1-based indices still missing (at most ``limit`` of them).
        Empty before the first frame (the total is unknown)."""
        out = []
        if self._chunks is None:
            return out
        for i in range(self.total):
            if self._chunks[i] is None:
                out.append(i + 1)
                if limit is not None and len(out) >= limit:
                    break
        return out

    def assemble(self) -> bytes:
        """Return the envelope; raises :class:`FrameIncomplete` otherwise."""
        if not self.is_complete():
            raise FrameIncomplete(self.missing())
        return b"".join(self._chunks)


class PackedReassembler(Reassembler):
    """Same wire semantics using one arena and four bytes of index per frame.

    Small-screen exports contain many 22-byte chunks. A separate Python bytes
    object and list pointer for every chunk cost more RAM than the ciphertext
    itself. This representation retains out-of-order and duplicate detection
    without those per-frame objects. It is used by constrained device imports;
    the general reassembler and all format limits remain available unchanged.
    """

    def __init__(self, backup_id=None, max_frames=MAX_FRAMES, max_bytes=MAX_TOTAL_BYTES, arena=None):
        super().__init__(backup_id, max_frames, max_bytes)
        self._data = bytearray() if arena is None else arena
        self._index = None  # u16 offset + u16 length; length zero means absent

    def _entry(self, index):
        at = (index - 1) * 4
        table = self._index
        return (table[at] << 8) | table[at + 1], (table[at + 2] << 8) | table[at + 3]

    def add(self, frame) -> bool:
        if not isinstance(frame, Frame):
            frame = parse_frame(frame)
        if self.backup_id is not None and frame.backup_id != self.backup_id:
            raise FrameIdMismatch("frame from another backup")
        if self.total is not None and frame.total != self.total:
            raise FrameTotalMismatch("frame total differs")
        if self.total is None and frame.total > self.max_frames:
            raise FrameLimitExceeded("too many frames")
        if self._index is not None:
            offset, length = self._entry(frame.index)
            if length:
                if self._data[offset : offset + length] == frame.chunk:
                    return False
                raise FrameConflict("conflicting duplicate frame")
        if (
            self.bytes_received + len(frame.chunk) > min(self.max_bytes, MAX_TOTAL_BYTES)
            or len(frame.chunk) > 65535
        ):
            raise FrameLimitExceeded("backup too large")
        if self._index is None:
            # Native export balances chunk sizes to within one byte. Even if
            # the last/smaller chunk arrives first, this upper bound reserves
            # its complete envelope once, without reserving the transport's
            # entire 12 KiB for a 379-byte OTP. Unbalanced third-party frames
            # remain valid and may grow the bounded arena below.
            reserve = min(self.max_bytes, MAX_TOTAL_BYTES, frame.total * (len(frame.chunk) + 1))
            arena = self._data if len(self._data) >= reserve else bytearray(reserve)
            table = bytearray(4 * frame.total)
            self._data = arena
            self._index = table
            self.backup_id = frame.backup_id
            self.total = frame.total
        offset = self.bytes_received
        length = len(frame.chunk)
        if offset + length > len(self._data):
            capacity = min(self.max_bytes, MAX_TOTAL_BYTES, max(offset + length, 2 * len(self._data)))
            arena = bytearray(capacity)
            arena[:offset] = memoryview(self._data)[:offset]
            self._data = arena
        # Publish the index only after append succeeded: a MemoryError cannot
        # turn a missing chunk into an apparently complete/valid frame.
        self._data[offset : offset + length] = frame.chunk
        at = (frame.index - 1) * 4
        self._index[at] = offset >> 8
        self._index[at + 1] = offset & 255
        self._index[at + 2] = length >> 8
        self._index[at + 3] = length & 255
        self.received += 1
        self.bytes_received += length
        return True

    def missing(self, limit=None) -> list:
        out = []
        if self._index is not None:
            for index in range(1, self.total + 1):
                if self._entry(index)[1] == 0:
                    out.append(index)
                    if limit is not None and len(out) >= limit:
                        break
        return out

    def assemble(self):
        if not self.is_complete():
            raise FrameIncomplete(self.missing())
        # Firmware releases decoder buffers before assembling, and drops this
        # arena as soon as the complete envelope is returned to the caller.
        out = bytearray(self.bytes_received)
        position = 0
        for index in range(1, self.total + 1):
            offset, length = self._entry(index)
            out[position : position + length] = memoryview(self._data)[offset : offset + length]
            position += length
        return out
