# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Host-side USB Mass Storage (Bulk-Only Transport / SCSI) client and a
minimal FAT12 writer, talking to the emulator's MSC bulk pipe over UDP.

The writer behaves like a simple OS driver: it reads the boot sector, the
FAT and the root directory, allocates contiguous clusters, writes the file
data, then the FAT (both copies) and the directory entry, and finally sends
SYNCHRONIZE CACHE.
"""

from __future__ import annotations

import socket
import struct

CBW_SIG = 0x43425355
CSW_SIG = 0x53425355


class MscError(Exception):
    pass


class MscClient:
    def __init__(self, port: int, timeout: float = 30.0) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)
        self.sock.connect(("127.0.0.1", port))
        self.tag = 1

    def close(self) -> None:
        self.sock.close()

    # -- BOT --------------------------------------------------------------
    def _send_packet(self, data: bytes) -> None:
        self.sock.send(b"\x00" + data)

    def _recv_frame(self) -> bytes:
        while True:
            f = self.sock.recv(128)
            if f == b"PONGPONG":
                continue
            return f

    def clear_halt(self, ep_in: bool = True) -> None:
        """Emulate CLEAR_FEATURE(ENDPOINT_HALT) (kernel event frame)."""
        self.sock.send(b"\x02" + (b"\x81" if ep_in else b"\x01"))

    def _recv_in(self, n: int) -> bytes:
        out = b""
        while len(out) < n:
            f = self._recv_frame()
            if f[:1] == b"\x00":
                out += f[1:]
            elif f[:1] == b"\x02":
                self.clear_halt(True)
            elif f[:1] == b"\x01":
                continue
        return out

    def command(self, cdb: bytes, data_in: int = 0, data_out: bytes = b"") -> tuple:
        """Run one SCSI command; returns (status, data)."""
        tag = self.tag
        self.tag += 1
        length = data_in or len(data_out)
        flags = 0x80 if data_in else 0x00
        cbw = struct.pack("<IIIBBB", CBW_SIG, tag, length, flags, 0, len(cdb)) + cdb.ljust(16, b"\0")
        self._send_packet(cbw)
        data = b""
        if data_out:
            for off in range(0, len(data_out), 64):
                self._send_packet(data_out[off : off + 64])
        elif data_in:
            # the device may send less (residue) and then the CSW
            buf = b""
            while True:
                f = self._recv_frame()
                if f[:1] == b"\x02":  # stalled: host clears the halt, then reads CSW
                    self.clear_halt(True)
                    break
                if f[:1] != b"\x00":
                    continue
                buf += f[1:]
                if len(buf) >= data_in:
                    break
                if len(f) - 1 < 64:
                    break
            if len(buf) > data_in and buf[data_in : data_in + 4] == struct.pack("<I", CSW_SIG):
                csw = buf[data_in:]
                data = buf[:data_in]
                return self._parse_csw(csw, tag), data
            data = buf
        csw = self._recv_in(13)
        return self._parse_csw(csw, tag), data

    @staticmethod
    def _parse_csw(csw: bytes, tag: int) -> int:
        sig, ctag, _residue, status = struct.unpack("<IIIB", csw[:13])
        if sig != CSW_SIG or ctag != tag:
            raise MscError(f"bad CSW {csw.hex()}")
        return status

    def request_sense(self) -> bytes:
        st, d = self.command(bytes([0x03, 0, 0, 0, 18, 0]), data_in=18)
        return d

    def start(self, attempts: int = 10) -> None:
        """Like an OS after enumeration: TEST UNIT READY until the power-on
        UNIT ATTENTION has been reported and cleared."""
        for _ in range(attempts):
            if self.test_unit_ready() == 0:
                return
            self.request_sense()
        raise MscError("unit never became ready")

    # -- SCSI helpers -----------------------------------------------------------
    def inquiry(self) -> bytes:
        st, d = self.command(bytes([0x12, 0, 0, 0, 36, 0]), data_in=36)
        assert st == 0
        return d

    def test_unit_ready(self) -> int:
        return self.command(bytes(6))[0]

    def read_capacity(self) -> tuple:
        st, d = self.command(bytes([0x25]) + bytes(9), data_in=8)
        assert st == 0
        last, bs = struct.unpack(">II", d)
        return last + 1, bs

    def read(self, lba: int, count: int = 1) -> bytes:
        st, d = self.command(struct.pack(">BBIBHB", 0x28, 0, lba, 0, count, 0), data_in=512 * count)
        if st != 0:
            raise MscError(f"READ failed at {lba}")
        return d

    def write(self, lba: int, data: bytes) -> None:
        assert len(data) % 512 == 0
        count = len(data) // 512
        st, _ = self.command(struct.pack(">BBIBHB", 0x2A, 0, lba, 0, count, 0), data_out=data)
        if st != 0:
            raise MscError(f"WRITE failed at {lba}")

    def sync(self) -> None:
        self.command(bytes([0x35]) + bytes(9))

    def eject(self) -> int:
        self.command(bytes([0x1E, 0, 0, 0, 0, 0]))  # allow medium removal
        return self.command(bytes([0x1B, 0, 0, 0, 0x02, 0]))[0]  # LoEj=1, Start=0


class Fat12Writer:
    def __init__(self, msc: MscClient) -> None:
        self.msc = msc
        bs = msc.read(0)
        if bs[510:512] != b"\x55\xaa":
            raise MscError("no boot sector signature")
        self.bps = struct.unpack("<H", bs[11:13])[0]
        self.spc = bs[13]
        self.reserved = struct.unpack("<H", bs[14:16])[0]
        self.nfats = bs[16]
        self.root_entries = struct.unpack("<H", bs[17:19])[0]
        self.fat_sectors = struct.unpack("<H", bs[22:24])[0]
        self.fat_lba = self.reserved
        self.root_lba = self.fat_lba + self.nfats * self.fat_sectors
        self.root_sectors = self.root_entries * 32 // self.bps
        self.data_lba = self.root_lba + self.root_sectors
        self.fat = bytearray(msc.read(self.fat_lba, self.fat_sectors))
        self.root = bytearray(msc.read(self.root_lba, self.root_sectors))

    def _get(self, n: int) -> int:
        off = n * 3 // 2
        v = self.fat[off] | (self.fat[off + 1] << 8)
        return (v >> 4) if n & 1 else (v & 0xFFF)

    def _set(self, n: int, val: int) -> None:
        off = n * 3 // 2
        if n & 1:
            self.fat[off] = (self.fat[off] & 0x0F) | ((val << 4) & 0xF0)
            self.fat[off + 1] = (val >> 4) & 0xFF
        else:
            self.fat[off] = val & 0xFF
            self.fat[off + 1] = (self.fat[off + 1] & 0xF0) | ((val >> 8) & 0x0F)

    def write_file(self, name83: str, data: bytes, order: str = "data-first") -> None:
        cluster_bytes = self.bps * self.spc
        n = max(1, (len(data) + cluster_bytes - 1) // cluster_bytes)
        max_cluster = len(self.fat) * 2 // 3
        start = None
        run = 0
        for c in range(2, max_cluster):
            if self._get(c) == 0:
                run += 1
                if run == n:
                    start = c - n + 1
                    break
            else:
                run = 0
        if start is None:
            raise MscError("volume full")
        for i in range(n):
            self._set(start + i, 0xFFF if i == n - 1 else start + i + 1)
        padded = data + bytes(n * cluster_bytes - len(data))
        base, ext = (name83.split(".") + [""])[:2]
        entry = (
            base.upper().ljust(8)[:8].encode()
            + ext.upper().ljust(3)[:3].encode()
            + bytes([0x20])
            + bytes(14)
            + struct.pack("<HI", start, len(data))
        )
        slot = next(i for i in range(0, len(self.root), 32) if self.root[i] in (0x00, 0xE5))
        self.root[slot : slot + 32] = entry

        def write_data() -> None:
            lba = self.data_lba + (start - 2) * self.spc
            for off in range(0, len(padded), 16 * 512):
                self.msc.write(lba + off // 512, padded[off : off + 16 * 512])

        def write_meta() -> None:
            for k in range(self.nfats):
                self.msc.write(self.fat_lba + k * self.fat_sectors, bytes(self.fat))
            self.msc.write(self.root_lba, bytes(self.root))

        if order == "data-first":
            write_data()
            write_meta()
        else:
            write_meta()
            write_data()
        self.msc.sync()

    def delete_file(self, name83: str) -> None:
        """Delete a synchronized 8.3 file, freeing its FAT chain for reuse."""
        base, ext = (name83.split(".") + [""])[:2]
        name = base.upper().ljust(8)[:8].encode() + ext.upper().ljust(3)[:3].encode()
        slot = next(
            i
            for i in range(0, len(self.root), 32)
            if self.root[i] not in (0x00, 0xE5) and self.root[i : i + 11] == name
        )
        cluster = struct.unpack_from("<H", self.root, slot + 26)[0]
        self.root[slot] = 0xE5
        # Remove the live entry before freeing/reusing its data clusters.
        self.msc.write(self.root_lba, bytes(self.root))
        while 2 <= cluster < 0xFF8:
            following = self._get(cluster)
            self._set(cluster, 0)
            cluster = following
        for index in range(self.nfats):
            self.msc.write(self.fat_lba + index * self.fat_sectors, bytes(self.fat))
        self.msc.sync()
