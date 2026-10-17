# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""CRC-32 (ISO-HDLC / IEEE 802.3 / zlib) — transport checksum of backup frames.

Parameters (Rocksoft model): width 32, poly 0x04C11DB7 (reflected
0xEDB88320), init 0xFFFFFFFF, refin/refout true, xorout 0xFFFFFFFF,
check("123456789") = 0xCBF43926.

The CRC only detects accidental corruption of a QR frame (spec §8.2 "somme
de contrôle de transport"). It is **not** a security mechanism: integrity
and authenticity of a backup come from the AES-256-GCM tag of the envelope.

A 16-entry nibble table is used instead of the classic 256-entry table: on
MicroPython every value ≥ 2**30 is a heap-allocated big integer, so the
small table keeps RAM usage to a few hundred bytes.
"""

_POLY = 0xEDB88320


def _build_table() -> tuple:
    table = []
    for n in range(16):
        c = n
        for _ in range(4):
            c = (c >> 1) ^ _POLY if c & 1 else c >> 1
        table.append(c)
    return tuple(table)


_TABLE = _build_table()


def update(crc: int, data) -> int:
    """Continue a CRC computation (``crc`` is a previous :func:`crc32` result)."""
    c = crc ^ 0xFFFFFFFF
    t = _TABLE
    for b in bytes(data):
        c ^= b
        c = (c >> 4) ^ t[c & 0x0F]
        c = (c >> 4) ^ t[c & 0x0F]
    return c ^ 0xFFFFFFFF


def crc32(data) -> int:
    """CRC-32 of ``data`` as an unsigned 32-bit integer."""
    return update(0, data)


def crc32_bytes(data) -> bytes:
    """CRC-32 of ``data`` as 4 big-endian bytes (the on-wire form in frames)."""
    return crc32(data).to_bytes(4, "big")
