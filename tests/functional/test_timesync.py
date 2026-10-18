# SPDX-License-Identifier: GPL-3.0-only
"""R07 (emulated): temporary CDC-ACM time-sync mode and TOTP."""

import socket
import time

from harness.emulator import PORT_VCP


def _open_timesync(debug):
    debug.select("Settings")
    debug.wait_title("Settings")
    debug.select("TOTP time")
    debug.wait_title("TOTP time")
    assert "Time not synchronised" in debug.screen().text()
    debug.select("Sync over USB")


def _send(emu, payload: bytes, timeout: float = 20.0) -> bytes:
    emu.wait_ready(PORT_VCP, 20)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.connect(("127.0.0.1", emu.port(PORT_VCP)))
        s.send(payload)
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(64)
            if chunk != b"PONGPONG":
                buf += chunk
        return buf


def test_time_sync_first_set_then_back_to_normal(ready, emu):
    _open_timesync(ready)
    now = int(time.time())
    assert _send(emu, f"TIME 1 {now}\n".encode()) == f"OK {now}\n".encode()
    # back in the TOTP time menu, in normal USB mode, with the clock set
    s = ready.wait_title("TOTP time", timeout=20)
    assert "Time not synchronised" not in s.text()


def test_time_sync_rejects_garbage_then_accepts(ready, emu):
    _open_timesync(ready)
    assert _send(emu, b"HELLO\n").startswith(b"FEURISTIC")
    assert _send(emu, b"TIME 2 1800000000\n") == b"ERR 2\n"
    assert _send(emu, b"TIME 1 12\n") == b"ERR 3\n"
    now = int(time.time())
    assert _send(emu, f"TIME 1 {now}\n".encode()) == f"OK {now}\n".encode()


def test_backward_jump_requires_confirmation(ready, emu):
    import threading

    _open_timesync(ready)
    now = int(time.time())
    assert _send(emu, f"TIME 1 {now}\n".encode()).startswith(b"OK")
    ready.wait_title("TOTP time", timeout=20)
    ready.select("Sync over USB")
    stop = threading.Event()

    def approve():
        while not stop.is_set():
            s = ready.screen()
            if s.title not in ("", "TOTP time", "Time sync") and s.component != "":
                if (
                    "Confirm" in s.text()
                    or "confirm" in s.text()
                    or s.title.lower().startswith(("move", "set"))
                ):
                    ready.approve()
                    return
            stop.wait(0.3)

    t = threading.Thread(target=approve, daemon=True)
    t.start()
    try:
        reply = _send(emu, f"TIME 1 {now - 3600}\n".encode(), timeout=40)
    finally:
        stop.set()
    assert reply in (f"OK {now - 3600}\n".encode(), b"ERR 4\n")
