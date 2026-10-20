#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Measure full-capacity NORMAL operation in an isolated frozen emulator.

This creates disposable test identities in a temporary emulator profile,
then starts a second process to measure reconstruction at capacity. It never
opens a hardware device. Freeze SCRIPT as feuristic.fw.normal_memory_probe
using prepare_import_memory32.py for representative bytecode placement.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = r"""
import gc
import os
import micropython
from trezor import config, loop
from feuristic.fw import device, session, transports
from feuristic.apps.fido2 import credentials as cr
from feuristic.apps.fido2.context import NULL_CHANNEL
from feuristic.apps.fido2.largeblobs import serialize
from feuristic.platform import crypto

PHASE = os.getenv("FEURISTIC_NORMAL_PHASE") or "populate"
DISTINCT = os.getenv("FEURISTIC_NORMAL_DISTINCT") == "1"
WARM_CARD = os.getenv("FEURISTIC_NORMAL_WARM_CARD") == "1"
RESERVE = int(os.getenv("FEURISTIC_NORMAL_RESERVE") or "0")


def checkpoint(label):
    gc.collect()
    print("NORMAL_MEMORY", label, gc.mem_alloc(), gc.mem_free())
    if label in ("ready", "capacity", "reloaded", "done"):
        micropython.mem_info()


def run(coro):
    try:
        coro.send(None)
    except StopIteration as result:
        return result.value
    raise RuntimeError("unexpected probe suspension")


class Approve:
    async def confirm(self, prompt):
        return True

    async def select(self, title, options, timeout_ms=30000):
        assert len(options) == 100
        assert len(options[:4]) == 4
        return len(options) - 1

    async def notify(self, *args):
        pass


def rp(index):
    label = str(index)
    prefix = label + "a" * (63 - len(label)) if DISTINCT else "a" * 63
    return prefix + "." + "b" * 56 + ".example"


config.init()
assert config.unlock("", None)
session.register_strings()
if not device.is_initialized():
    device.initialize()
session._load_stores()
loop.schedule(session._clock_maintenance())
server = transports.fido_server()
card = transports._card_obj()
if WARM_CARD:
    for applet in card.dispatcher.applets:
        aid = applet.AID
        answer = run(card.dispatcher.transmit(bytes((0, 0xa4, 4, 0, len(aid))) + aid))
        assert answer[-2:] == b"\x90\x00"
ui = Approve()
auth = server.app.auth
auth.ctx.ui = ui
reserve = bytearray(RESERVE)
checkpoint("ready")
if PHASE == "populate":
    auth.pin.local_set_pin("123456")
    for index in range(100):
        auth.store.create_resident(
            rp(index), index.to_bytes(64, "big"), "n" * 64, "d" * 64,
            cr.ALG_ES256, (index + 1).to_bytes(32, "big"), 1, True, True,
        )
        if index % 25 == 24:
            checkpoint("credentials-" + str(index + 1))
    from feuristic.apps.otp.accounts import OtpAccounts
    from feuristic.apps.otp.uri import OtpParams
    otp = OtpAccounts()
    for index in range(32):
        label = str(index)
        name = label + "x" * (64 - len(label))
        uid = otp.add(OtpParams("hotp", "i" * 32, name, b"s" * 64, "SHA512", 8, counter=1000))
        run(otp.generate_hotp(uid, ui))
        if index % 8 == 7:
            checkpoint("otp-" + str(index + 1))
    otp = None
    checkpoint("before-largeblobs")
    for value in (b"x", b"y", b"z"):
        entries = [{1: value * 4074}]
        assert len(serialize(entries)) == 4096
        auth.large_blobs.write_entries(entries)
        checkpoint("largeblobs-" + value.decode())
    entries = None
    checkpoint("capacity")
else:
    assert PHASE == "reload"
    assert auth.store.count() == 100
    checkpoint("reloaded")
assert auth.store.count() == 100
from feuristic.apps.otp.accounts import OtpAccounts
assert len(OtpAccounts()) == 32
assert auth.large_blobs.entries() == [{1: b"z" * 4074}]
assert len(auth.store.rps()) == (100 if DISTINCT else 1)
first = auth.store.for_rp(crypto.sha256(rp(0).encode()))[-1]
assert first is not None
original_id = first.cred_id
auth.store.update_user(first, first.user_name, first.display_name)
first = None
result = run(auth.get_assertion({1: rp(0), 2: b"h" * 32, 5: {"up": True}}, NULL_CHANNEL))
assert result[1]["type"] == "public-key" and len(result[3]) > 60
assert result[1]["id"] == original_id
result = None
if not DISTINCT:
    result = run(auth.get_assertion({1: rp(0), 2: b"h" * 32, 5: {"up": False}}, NULL_CHANNEL))
    assert result[5] == 100
    result = None
    for index in range(99):
        result = auth.get_next_assertion()
        assert len(result[3]) > 60
        result = None
    assert len(auth.store.for_rp(crypto.sha256(rp(0).encode()))) == 100
checkpoint("done")
print("NORMAL_MEMORY_PROBE_OK", PHASE)
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emulator", required=True, type=Path)
    parser.add_argument("--container", help="run inside an existing Docker container")
    parser.add_argument("--heap", default="171492")
    parser.add_argument("--distinct-rps", action="store_true")
    parser.add_argument("--warm-card", action="store_true", help="select every real CCID application first")
    parser.add_argument(
        "--reserve", default=0, type=int, help="additional held bytes for headroom experiments"
    )
    parser.add_argument(
        "--live-script", action="store_true", help="count SCRIPT bytecode in RAM, conservatively"
    )
    args = parser.parse_args()
    (ROOT / "build").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="normal-memory32-", dir=ROOT / "build") as profile:
        for phase in ("populate", "reload"):
            env = {
                "TREZOR_PROFILE_DIR": profile,
                "SDL_VIDEODRIVER": "dummy",
                "MICROPYPATH": ".frozen:.",
                "FEURISTIC_NORMAL_PHASE": phase,
                "FEURISTIC_NORMAL_DISTINCT": str(int(args.distinct_rps)),
                "FEURISTIC_NORMAL_WARM_CARD": str(int(args.warm_card)),
                "FEURISTIC_NORMAL_RESERVE": str(args.reserve),
            }
            command = [
                str(args.emulator.resolve()),
                "-O0",
                "-X",
                "heapsize=" + args.heap,
                "-c",
                SCRIPT if args.live_script else "import feuristic.fw.normal_memory_probe",
            ]
            cwd = ROOT / "build/emu32-tree/core/src"
            if args.container:
                command = [
                    "docker",
                    "exec",
                    "-e",
                    "QEMU_LD_PREFIX=/usr/i686-linux-gnu",
                    "-e",
                    "LD_LIBRARY_PATH=/opt/feuristic/i686/lib:/usr/i686-linux-gnu/lib",
                    *[arg for key, value in env.items() for arg in ("-e", key + "=" + value)],
                    "-w",
                    str(cwd),
                    args.container,
                    *command,
                ]
            result = subprocess.run(command, cwd=cwd, env={**os.environ, **env}, check=False)
            if result.returncode:
                return result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
