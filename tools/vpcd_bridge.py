#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Expose the emulator's CCID reader to a real PC/SC stack via vsmartcard's vpcd.

pcscd + vpcd (package ``vsmartcard-vpcd``) provide a virtual reader that
waits for a "virtual card" on TCP port 35963. This bridge connects to it and
forwards every APDU to the feuristic emulator's emulated USB CCID interface,
so unmodified GnuPG, OpenSC, yubico-piv-tool... talk to the firmware.

    tools/vpcd_bridge.py --ccid-port 21331 [--vpcd 127.0.0.1:35963]

vpcd protocol: each message is a 2-byte big-endian length followed by the
payload. One-byte payloads are control codes (0 power off, 1 power on,
2 reset, 4 get ATR); anything else is a command APDU, answered with the
response APDU.
"""

from __future__ import annotations

import argparse
import os
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tests", "functional"))

from harness.ccid import CcidClient, CcidError  # noqa: E402

CTRL_OFF, CTRL_ON, CTRL_RESET, CTRL_ATR = 0, 1, 2, 4


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("vpcd closed the connection")
        buf += chunk
    return buf


def send_msg(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(struct.pack(">H", len(payload)) + payload)


def serve(ccid: CcidClient, vpcd: socket.socket, verbose: bool) -> None:
    atr = b""
    while True:
        (length,) = struct.unpack(">H", recv_exact(vpcd, 2))
        msg = recv_exact(vpcd, length)
        if length == 1:
            code = msg[0]
            if code in (CTRL_ON, CTRL_RESET):
                atr = ccid.power_on()
            elif code == CTRL_OFF:
                ccid.power_off()
            elif code == CTRL_ATR:
                if not atr:
                    atr = ccid.power_on()
                send_msg(vpcd, atr)
            continue
        try:
            data, sw = ccid.transmit_raw(msg)
            rsp = data + struct.pack(">H", sw)
        except CcidError:
            rsp = b"\x6f\x00"
        if verbose:
            print(f"> {msg.hex()}\n< {rsp.hex()}", file=sys.stderr)
        send_msg(vpcd, rsp)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ccid-port", type=int, required=True, help="emulator CCID UDP port (base + 7)")
    ap.add_argument("--vpcd", default="127.0.0.1:35963")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    host, port = args.vpcd.rsplit(":", 1)
    while True:
        try:
            with socket.create_connection((host, int(port)), timeout=None) as vpcd:
                vpcd.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                ccid = CcidClient(args.ccid_port, timeout=120)
                try:
                    serve(ccid, vpcd, args.verbose)
                finally:
                    ccid.close()
        except (ConnectionError, OSError) as e:
            print(f"vpcd bridge: {e}; retrying", file=sys.stderr)
            time.sleep(1)


if __name__ == "__main__":
    sys.exit(main())
