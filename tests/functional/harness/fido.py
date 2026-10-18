# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""python-fido2 device bound to the emulator's FIDO HID interface (UDP)."""

from __future__ import annotations

import socket

from fido2.hid import CtapHidDevice
from fido2.hid.base import CtapHidConnection, HidDescriptor


class UdpCtapHidConnection(CtapHidConnection):
    def __init__(self, port: int, timeout: float = 60.0) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)
        self.sock.connect(("127.0.0.1", port))

    def read_packet(self) -> bytes:
        while True:
            data = self.sock.recv(64)
            if data != b"PONGPONG":
                return data

    def write_packet(self, data: bytes) -> None:
        # python-fido2 prepends a report id byte (0x00); the emulator expects
        # raw 64-byte reports
        if len(data) == 65:
            data = data[1:]
        self.sock.send(bytes(data).ljust(64, b"\0"))

    def close(self) -> None:
        self.sock.close()


def open_device(port: int) -> CtapHidDevice:
    desc = HidDescriptor(f"udp:{port}", 0x1209, 0x0001, 64, 64, "feuristic security key", None)
    return CtapHidDevice(desc, UdpCtapHidConnection(port))
