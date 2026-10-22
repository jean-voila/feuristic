#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Capture README/artwork screens from the T2B1 emulator with disposable data.

Build the emulator first (`make emu MODEL=T2B1`), then run from the repository root:

    uv run python tools/capture_screens.py

Each screen is saved as a 128x64 PNG under docs/assets/screens/ and its white
pixel runs are merged into assets/design/screen-pixels.json for tools/artwork.js.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests" / "functional"))
os.environ.setdefault(
    "FEURISTIC_EMU", str(ROOT / "upstream/trezor-firmware/core/build-xtask/artifacts/T2B1/firmware-emu")
)

from conftest import enter_pin, onboard  # noqa: E402
from fido2.cose import ES256  # noqa: E402
from fido2.ctap2 import Ctap2  # noqa: E402
from harness.debug import Debug  # noqa: E402
from harness.emulator import PORT_DEBUG, PORT_FIDO, PORT_MSC, PORT_VCP, Emulator  # noqa: E402
from harness.fido import open_device  # noqa: E402
from harness.msc import Fat12Writer, MscClient  # noqa: E402
from PIL import Image  # noqa: E402
from test_import import qr_png  # noqa: E402
from test_menus_backup import _approve_hold, _qr_text, _text_entry  # noqa: E402
from trezorlib import models  # noqa: E402

SCREENS = ROOT / "docs" / "assets" / "screens"
PIXELS = ROOT / "assets" / "design" / "screen-pixels.json"
OTP_URI = "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
PHRASE = "correct horse battery staple"


class Capture:
    def __init__(self, debug: Debug) -> None:
        self.debug = debug
        self.tmp = Path(tempfile.mkdtemp(prefix="feuristic-shots-"))
        self.pixels = json.loads(PIXELS.read_text()) if PIXELS.exists() else {}

    def shot(self, name: str) -> None:
        """Repaint the current layout into a fresh directory and keep that frame."""
        target = self.tmp / name
        target.mkdir()
        self.debug.dl.start_recording(str(target))
        time.sleep(0.3)
        self.debug.dl.stop_recording()
        frames = sorted(target.glob("*.png"))
        if not frames:
            raise RuntimeError(f"no frame recorded for {name}")
        image = Image.open(frames[0]).convert("L")
        assert image.size == (128, 64), image.size
        image.convert("RGB").save(SCREENS / f"{name}.png")
        runs = []
        for y in range(64):
            x = 0
            while x < 128:
                if image.getpixel((x, y)) > 127:
                    start = x
                    while x < 128 and image.getpixel((x, y)) > 127:
                        x += 1
                    runs.append([start, y, x - start])
                else:
                    x += 1
        self.pixels[name] = {"width": 128, "height": 64, "runs": runs}
        print(f"captured {name}: {self.debug.screen()!r}")

    def save(self) -> None:
        PIXELS.write_text(json.dumps(self.pixels, separators=(",", ":")) + "\n")
        shutil.rmtree(self.tmp, ignore_errors=True)


def _wait_screen(debug: Debug, predicate, stop: threading.Event):
    while not stop.is_set():
        screen = debug.screen()
        if predicate(screen):
            return screen
        stop.wait(0.2)
    return None


def passkey(debug: Debug, emu: Emulator, cap: Capture) -> None:
    rp = {"id": "github.com", "name": "GitHub"}
    user = {"id": b"alice", "name": "alice@example.com", "displayName": "Alice"}
    stop = threading.Event()

    def confirm():
        if _wait_screen(debug, lambda s: s.title not in ("", "feuristic"), stop):
            time.sleep(0.5)
            cap.shot("passkey-create-en")
            debug.approve()

    worker = threading.Thread(target=confirm, daemon=True)
    worker.start()
    dev = open_device(emu.port(PORT_FIDO))
    try:
        Ctap2(dev).make_credential(
            b"\x11" * 32, rp, user, [{"type": "public-key", "alg": ES256.ALGORITHM}], options={"rk": True}
        )
    finally:
        stop.set()
        worker.join(10)
        dev.close()
    debug.wait_title("feuristic", timeout=20)


def sync_time(debug: Debug, emu: Emulator) -> None:
    debug.select("Settings")
    debug.wait_title("Settings")
    debug.select("TOTP time")
    debug.wait_title("TOTP time")
    debug.select("Sync over USB")
    emu.wait_ready(PORT_VCP, 20)
    now = int(time.time())
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(20)
        s.connect(("127.0.0.1", emu.port(PORT_VCP)))
        s.send(f"TIME 1 {now}\n".encode())
        reply = b""
        while not reply.endswith(b"\n"):
            chunk = s.recv(64)
            if chunk != b"PONGPONG":
                reply += chunk
    assert reply.startswith(b"OK"), reply
    debug.wait_title("TOTP time", timeout=20)
    debug.hold_left()
    debug.wait_title("Settings")
    debug.hold_left()
    debug.wait_title("feuristic")


def import_otp(debug: Debug, emu: Emulator) -> None:
    debug.select("Authentication")
    debug.wait_title("Authentication")
    debug.select("OTP")
    debug.wait_for(lambda s: s.title in ("One-time passwords", "OTP"))
    debug.select("Add QR over USB")
    emu.wait_ready(PORT_MSC, 20)
    msc = MscClient(emu.port(PORT_MSC))
    msc.start()
    try:
        Fat12Writer(msc).write_file("QR.PNG", qr_png(OTP_URI))
        debug.wait_for(lambda s: "GitHub" in s.text(), timeout=30)
        debug.approve()
        debug.wait_for(lambda s: "Eject" in s.text(), timeout=30)
        assert msc.eject() == 0
    finally:
        msc.close()
    debug.wait_title("One-time passwords", timeout=30)


def main() -> None:
    SCREENS.mkdir(parents=True, exist_ok=True)
    with Emulator(base_port=23400) as emu:
        debug = Debug(emu.port(PORT_DEBUG), model=models.T2B1)
        cap = Capture(debug)
        try:
            onboard(debug)
            debug.wait_title("feuristic")
            debug.select("Lock")
            debug.wait_for(lambda s: "FEURISTIC" in s.text())
            cap.shot("lock-en")
            debug.right()
            enter_pin(debug)
            debug.wait_title("feuristic")

            passkey(debug, emu, cap)
            debug.select("Authentication")
            debug.wait_title("Authentication")
            debug.select("Passkeys")
            debug.wait_title("Passkeys")
            debug.select("Services")
            debug.wait_for(lambda s: "github.com" in s.text())
            cap.shot("passkeys-en")
            for title in ("Passkeys", "Authentication", "feuristic"):
                debug.hold_left()
                debug.wait_title(title)

            sync_time(debug, emu)
            import_otp(debug, emu)
            debug.wait_for(lambda s: "GitHub" in s.text())
            debug.both()
            debug.select("View code")
            # A fresh period reads better than a code about to expire.
            debug.wait_for(lambda s: re.search(r"\b2\d s left", s.text()) is not None, timeout=40)
            cap.shot("otp-code-en")
            debug.left()  # one short press closes the refreshing code view
            debug.wait_title("GitHub: alice")
            debug.wait_for(lambda s: "s left" not in s.text(), timeout=3)
            for title in ("One-time passwords", "Authentication", "feuristic"):
                debug.hold_left()
                debug.wait_title(title)

            debug.select("Backup")
            debug.wait_title("Backup")
            debug.select("Export an identity")
            debug.wait_title("Choose identity type")
            debug.select("One-time passwords")
            debug.wait_title("One-time passwords")
            debug.both()
            debug.wait_title("QR readability")
            debug.select("Large modules")
            debug.wait_title("Export identity")
            _approve_hold(debug)
            debug.wait_title("Enter backup passphrase")
            debug.approve()
            _text_entry(debug, PHRASE)
            _text_entry(debug, PHRASE)
            enter_pin(debug)
            debug.wait_title("Backup", timeout=30)
            debug.approve()
            debug.wait_title("Identity 1 of 1")
            debug.approve()
            debug.wait_for(lambda s: _qr_text(s) is not None, timeout=10)
            cap.shot("backup-qr-en")
            cap.save()
        finally:
            debug.close()


if __name__ == "__main__":
    main()
