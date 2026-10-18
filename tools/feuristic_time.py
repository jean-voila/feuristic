#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Send the current time to a feuristic device in "time sync" mode.

Optional convenience: any serial terminal can send the same line (see
docs/protocols/time-sync-v1.md). Usage::

    tools/feuristic_time.py                 # auto-detect the CDC-ACM port
    tools/feuristic_time.py /dev/ttyACM0    # explicit port
    tools/feuristic_time.py --udp 21327     # emulator (base port + 3)

Exit status: 0 on "OK", 1 on "ERR <code>" or timeout.
"""

from __future__ import annotations

import argparse
import socket
import sys
import time

VID, PID = 0x1209, 0x0001
ERRORS = {
    "1": "syntax error",
    "2": "unsupported protocol version",
    "3": "time out of range",
    "4": "refused on the device",
    "5": "busy / session finished",
    "6": "line too long",
}


def line(now: int | None = None) -> bytes:
    return f"TIME 1 {int(time.time()) if now is None else now}\n".encode()


def find_port() -> str:
    from serial.tools import list_ports

    for p in list_ports.comports():
        if p.vid == VID and p.pid == PID:
            return p.device
    raise SystemExit("no feuristic device in time-sync mode found (Settings > TOTP time > Sync over USB)")


def via_serial(port: str, timeout: float) -> str:
    import serial

    with serial.Serial(port, 115200, timeout=timeout) as s:
        s.write(line())
        s.flush()
        return s.readline().decode(errors="replace").strip()


def via_udp(port: int, timeout: float) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.connect(("127.0.0.1", port))
        s.send(line())
        buf = b""
        while not buf.endswith(b"\n"):
            buf += s.recv(64)
        return buf.decode(errors="replace").strip()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("port", nargs="?", help="serial port (default: auto-detect)")
    ap.add_argument("--udp", type=int, help="emulator CDC-ACM UDP port")
    ap.add_argument("--timeout", type=float, default=120.0, help="seconds to wait (confirmation on device)")
    args = ap.parse_args()
    try:
        reply = (
            via_udp(args.udp, args.timeout)
            if args.udp
            else via_serial(args.port or find_port(), args.timeout)
        )
    except (TimeoutError, OSError) as e:
        print(f"no answer: {e}", file=sys.stderr)
        return 1
    if reply.startswith("OK "):
        print(f"time set: {reply[3:]}")
        return 0
    code = reply[4:] if reply.startswith("ERR ") else "?"
    print(f"device answered {reply!r} ({ERRORS.get(code, 'unknown error')})", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
