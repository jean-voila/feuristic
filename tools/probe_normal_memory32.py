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

from memory_probe_source import checked_script

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = r"""
import gc
import os
import micropython
from trezor import config, loop
from feuristic.fw import device, session, transports
from feuristic.apps.fido2 import credentials as cr
from feuristic.apps.fido2.context import NULL_CHANNEL
from feuristic.core import cbor
from feuristic.platform import crypto

PHASE = os.getenv("FEURISTIC_NORMAL_PHASE") or "populate"
DISTINCT = os.getenv("FEURISTIC_NORMAL_DISTINCT") == "1"
WARM_CARD = os.getenv("FEURISTIC_NORMAL_WARM_CARD") == "1"
RESERVE = int(os.getenv("FEURISTIC_NORMAL_RESERVE") or "0")
EXPORT = os.getenv("FEURISTIC_NORMAL_EXPORT") == "1"


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


session.configure_gc()
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
reserve = [bytearray(min(256, RESERVE - offset)) for offset in range(0, RESERVE, 256)]
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
        auth.large_blobs.write_entries([{1: value * 4074}])
        checkpoint("largeblobs-local-" + value.decode())

    def ctap(command, request):
        reply = run(auth.dispatch(bytes((command,)) + cbor.encode(request), NULL_CHANNEL))
        assert reply[0] == 0, (command, reply[0])
        return cbor.decode(memoryview(reply)[1:]) if len(reply) > 1 else {}

    def lbw_token():
        peer = ctap(6, {1: 1, 2: 2})[1]
        secret = crypto.p256_generate()
        public = crypto.p256_public(secret)
        client = {1: 2, 3: -25, -1: 1, -2: public[1:33], -3: public[33:]}
        shared = crypto.sha256(crypto.p256_ecdh(secret, b"\x04" + peer[-2] + peer[-3]))
        encrypted = crypto.aes256_cbc_encrypt(shared, bytes(16), crypto.sha256(b"123456")[:16])
        answer = ctap(6, {1: 1, 2: 9, 3: client, 6: encrypted, 9: 16})
        return crypto.aes256_cbc_decrypt(shared, bytes(16), answer[2])

    def trailer(value):
        digest = crypto.Sha256(b"\x81\xa1\x01\x59\x0f\xea")
        for offset in range(0, 4074, 256):
            digest.update(value * min(256, 4074 - offset))
        return digest.digest()[:16]

    def blob_fragment(value, tag, offset):
        # The external client never lives on the MCU. Generate just its
        # current fragment here instead of retaining another 4KiB array.
        end = min(offset + 256, 4096)
        parts = []
        if offset < 6:
            parts.append(b"\x81\xa1\x01\x59\x0f\xea"[offset:min(end, 6)])
        if offset < 4080 and end > 6:
            parts.append(value * (min(end, 4080) - max(offset, 6)))
        if end > 4080:
            parts.append(tag[max(0, offset - 4080):end - 4080])
        return b"".join(parts)

    token = lbw_token()
    for value in (b"x", b"y", b"z"):
        tag = trailer(value)
        for offset in range(0, 4096, 256):
            fragment = blob_fragment(value, tag, offset)
            msg = b"\xff" * 32 + b"\x0c\x00" + offset.to_bytes(4, "little") + crypto.sha256(fragment)
            request = {2: fragment, 3: offset, 5: crypto.hmac_sha256(token, msg)[:16], 6: 1}
            if offset == 0:
                request[4] = 4096
            assert ctap(12, request) == {}
        for offset in range(0, 4096, 256):
            assert ctap(12, {1: 256, 3: offset})[1] == blob_fragment(value, tag, offset)
        checkpoint("largeblobs-ctap-" + value.decode())
    token = tag = fragment = msg = request = None
    checkpoint("capacity")
else:
    assert PHASE == "reload"
    assert auth.store.count() == 100
    checkpoint("reloaded")
assert auth.store.count() == 100
from feuristic.apps.otp.accounts import OtpAccounts
assert len(OtpAccounts()) == 32
entries = auth.large_blobs.entries()
assert len(entries) == 1 and len(entries[0]) == 1 and len(entries[0][1]) == 4074
for offset in range(0, 4074, 256):
    assert bytes(entries[0][1][offset:offset+256]) == b"z" * min(256, 4074-offset)
entries = None
rps = auth.store.rps()
assert len(rps) == (100 if DISTINCT else 1)
previous = ""
for name, digest, count in rps:
    assert name >= previous and digest == crypto.sha256(name.encode())
    assert count == (1 if DISTINCT else 100)
    previous = name
rps = None
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
if EXPORT:
    # Local export disconnects USB and releases NORMAL protocol sessions.
    transports.suspend()
    run(transports.wait_suspended())
    server = card = auth = None
    session.release_import_modules(keep_backup=True)
    checkpoint("export-offline")
    from feuristic.fw import backup_providers
    backup_providers.begin_export()
    from feuristic.apps.backup.export import begin_full_export

    async def passphrase(request):
        return bytearray(b"FeuristicProbePassphrase2026")

    for profile in ("dense", "large"):
        checkpoint("export-before-" + profile)
        export = run(begin_full_export(ui, passphrase, profile=profile))
        try:
            assert len(export) == 132
            checkpoint("export-snapshot-" + profile)
            for index in range(len(export)):
                built = export.build(index)
                assert built.seq == index + 1 and built.count == 132 and built.frames
                built.frames.clear()
                built = None
                if index % 25 == 24 or index == 131:
                    checkpoint("export-" + profile + "-" + str(index + 1))
        finally:
            export.close()
            export = None
        checkpoint("export-after-" + profile)
    backup_providers.end_export()
print("NORMAL_MEMORY_PROBE_OK", PHASE)
"""

# Frozen production builds remove assert statements; retain every probe action.
SCRIPT = checked_script(SCRIPT)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emulator", required=True, type=Path)
    parser.add_argument("--container", help="run inside an existing Docker container")
    parser.add_argument("--heap", default="171492")
    parser.add_argument("--distinct-rps", action="store_true")
    parser.add_argument("--export", action="store_true", help="export all 132 identities in both QR profiles")
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
                "FEURISTIC_NORMAL_EXPORT": str(int(args.export)),
            }
            command = [
                str(args.emulator.resolve()),
                "-O0",
                "-X",
                "heapsize=" + args.heap,
                "-c",
                SCRIPT
                if args.live_script
                else ('import sys; sys.path[:] = [".frozen"]; import feuristic.fw.normal_memory_probe'),
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
