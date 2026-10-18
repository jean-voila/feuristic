# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Host-side CCID client over the emulator's bulk-pipe UDP interface.

Frames follow firmware/kernel/usb/inc/io/usb_bulk.h: host→device datagrams
are ``00 || packet`` (bulk OUT), device→host datagrams are ``00 || packet``
(bulk IN data) or ``01`` (zero-length packet).
"""

from __future__ import annotations

import socket
import struct

PC_TO_RDR_ICC_POWER_ON = 0x62
PC_TO_RDR_ICC_POWER_OFF = 0x63
PC_TO_RDR_GET_SLOT_STATUS = 0x65
PC_TO_RDR_XFR_BLOCK = 0x6F
RDR_TO_PC_DATA_BLOCK = 0x80


class CcidError(Exception):
    pass


class CcidClient:
    def __init__(self, port: int, timeout: float = 60.0) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)
        self.sock.connect(("127.0.0.1", port))
        self.seq = 0
        self.wtx_count = 0

    def close(self) -> None:
        self.sock.close()

    # -- transport -----------------------------------------------------------
    def _send_message(self, msg_type: int, data: bytes = b"", b7: int = 0, b8: int = 0, b9: int = 0) -> int:
        seq = self.seq
        self.seq = (self.seq + 1) & 0xFF
        msg = struct.pack("<BIBBBBB", msg_type, len(data), 0, seq, b7, b8, b9) + data
        for off in range(0, len(msg), 64):
            self.sock.send(b"\x00" + msg[off : off + 64])
        return seq

    def _recv_message(self) -> tuple:
        buf = b""
        need = None
        while need is None or len(buf) < need:
            frame = self.sock.recv(128)
            if frame == b"PONGPONG":
                continue
            if frame[:1] == b"\x01":  # ZLP
                if need is not None and len(buf) >= need:
                    break
                continue
            if frame[:1] != b"\x00":
                raise CcidError(f"unexpected frame {frame[:4].hex()}")
            buf += frame[1:]
            if need is None and len(buf) >= 10:
                need = 10 + struct.unpack("<I", buf[1:5])[0]
        hdr = buf[:10]
        msg_type, length, slot, seq, status, error, specific = struct.unpack("<BIBBBBB", hdr)
        return msg_type, seq, status, error, specific, buf[10 : 10 + length]

    def _exchange(self, msg_type: int, data: bytes = b"", **kw) -> tuple:
        seq = self._send_message(msg_type, data, **kw)
        while True:
            m = self._recv_message()
            if m[1] != seq:
                continue
            if m[2] & 0xC0 == 0x80:  # time extension requested
                self.wtx_count += 1
                continue
            if m[2] & 0x40:
                raise CcidError(f"command failed: status={m[2]:#x} error={m[3]:#x}")
            return m

    # -- API -----------------------------------------------------------------
    def power_on(self) -> bytes:
        return self._exchange(PC_TO_RDR_ICC_POWER_ON)[5]

    def power_off(self) -> None:
        self._exchange(PC_TO_RDR_ICC_POWER_OFF)

    def slot_status(self) -> int:
        return self._exchange(PC_TO_RDR_GET_SLOT_STATUS)[2]

    def transmit_raw(self, apdu: bytes) -> tuple:
        rsp = self._exchange(PC_TO_RDR_XFR_BLOCK, apdu)[5]
        if len(rsp) < 2:
            raise CcidError("short response")
        return rsp[:-2], (rsp[-2] << 8) | rsp[-1]

    def transmit(self, apdu: bytes) -> tuple:
        """Send an APDU, following 61xx response chaining. Returns (data, sw)."""
        data, sw = self.transmit_raw(apdu)
        out = data
        while sw & 0xFF00 == 0x6100:
            le = sw & 0xFF
            data, sw = self.transmit_raw(bytes([apdu[0] & 0xFC, 0xC0, 0, 0, le]))
            out += data
        return out, sw
