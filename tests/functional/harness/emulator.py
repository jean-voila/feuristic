# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Start/stop the feuristic unix emulator and talk to its UDP interfaces.

Port map (relative to the base port, see firmware/kernel/usb/usb_modes.c):
debuglink +1, FIDO HID +2, CDC-ACM +3, CCID +7, MSC +8.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CORE = ROOT / "upstream" / "trezor-firmware" / "core"
DEFAULT_BINARY = CORE / "build-xtask" / "artifacts" / "T3B1" / "firmware-emu"

PORT_DEBUG = 1
PORT_FIDO = 2
PORT_VCP = 3
PORT_CCID = 7
PORT_MSC = 8


def binary_path() -> Path:
    return Path(os.environ.get("FEURISTIC_EMU", DEFAULT_BINARY))


class Emulator:
    """A running emulator instance with its own profile (flash) directory."""

    def __init__(self, base_port: int = 21424, profile_dir: str | None = None, heap: str = "20M") -> None:
        self.base_port = base_port
        self._own_profile = profile_dir is None
        self.profile_dir = profile_dir or tempfile.mkdtemp(prefix="feuristic-emu-")
        self.heap = heap
        self.proc: subprocess.Popen | None = None
        self.log_path = Path(self.profile_dir) / "emulator.log"

    # -- lifecycle -----------------------------------------------------------
    def start(self, timeout: float = 30.0) -> None:
        env = dict(os.environ)
        env.update(
            {
                "TREZOR_PROFILE_DIR": self.profile_dir,
                "TREZOR_UDP_PORT": str(self.base_port),
                "SDL_VIDEODRIVER": "dummy",
                "TREZOR_DISABLE_ANIMATION": "1",
            }
        )
        log = open(self.log_path, "ab")  # noqa: SIM115 - kept open for the process lifetime
        self.proc = subprocess.Popen(
            [str(binary_path()), "-O0", "-X", f"heapsize={self.heap}", "-m", "main"],
            cwd=CORE / "src",
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        self.wait_ready(PORT_DEBUG, timeout)

    def stop(self) -> None:
        if self.proc is not None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
            self.proc = None

    def restart(self) -> None:
        """Simulate a power cycle: same flash, fresh RAM."""
        self.stop()
        self.start()

    def cleanup(self) -> None:
        self.stop()
        if self._own_profile:
            shutil.rmtree(self.profile_dir, ignore_errors=True)

    def log(self) -> str:
        try:
            return self.log_path.read_text(errors="replace")
        except FileNotFoundError:
            return ""

    # -- UDP helpers ---------------------------------------------------------
    def port(self, offset: int) -> int:
        return self.base_port + offset

    def wait_ready(self, offset: int, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(0.2)
            while time.monotonic() < deadline:
                if self.proc is not None and self.proc.poll() is not None:
                    raise RuntimeError("emulator exited:\n" + self.log()[-3000:])
                try:
                    s.sendto(b"PINGPING", ("127.0.0.1", self.port(offset)))
                    data, _ = s.recvfrom(64)
                    if data == b"PONGPONG":
                        return
                except OSError:
                    time.sleep(0.1)
        raise TimeoutError(f"emulator interface +{offset} not ready:\n" + self.log()[-3000:])

    def __enter__(self) -> Emulator:
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.cleanup()


class UdpPipe:
    """Datagram pipe to one emulated interface (one datagram = one packet/frame)."""

    def __init__(self, port: int, timeout: float = 5.0) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)
        self.addr = ("127.0.0.1", port)
        self.sock.connect(self.addr)

    def send(self, data: bytes) -> None:
        self.sock.send(data)

    def recv(self, timeout: float | None = None) -> bytes:
        if timeout is not None:
            self.sock.settimeout(timeout)
        return self.sock.recv(4096)

    def close(self) -> None:
        self.sock.close()
