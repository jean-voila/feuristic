#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Exercise native image/BOT -> packed collector -> authenticated provider restore.

Fixtures use the real maximum native identity factories from the host tests.
They are disposable test secrets. Run this only against an isolated emulator
profile. The -c probe bytecode is counted in the heap, conservatively adding
allocations absent from the frozen application. This is not physical testing.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import subprocess
import sys
from pathlib import Path

from memory_probe_source import checked_script

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = r"""
import gc
import os
import micropython
import feuristic_import
from trezor import config, loop, utils
from feuristic.fw import device, session, usbmodes
from feuristic.fw.import_mode import _State, _controller, _readme, _usb_task
from feuristic.apps.importer.session import (
    ImportSession, DEVICE_MAX_BYTES, DEVICE_MAX_ENVELOPES, DEVICE_MAX_SETS
)


def checkpoint(label):
    gc.collect()
    print("RESTORE_MEMORY", label, gc.mem_alloc(), gc.mem_free())
    if label in ("bootstrap", "decoder", "released-1", "resumed-192"):
        if os.getenv("FEURISTIC_MEMORY_DUMP") == "1":
            micropython.mem_info(1)
        else:
            micropython.mem_info()


def run(coro):
    try:
        coro.send(None)
    except StopIteration as result:
        return result.value
    raise RuntimeError("unexpected probe suspension")


class Approve:
    async def confirm(self, prompt):
        checkpoint("confirm-" + prompt.kind)
        return True

    async def notify(self, *args):
        pass


async def phrase(request):
    checkpoint("phrase")
    return bytearray(b"Memory probe passphrase")


def command(cdb, data=None, read=0, buffer=None):
    cbw = bytearray(31)
    cbw[:4] = b"USBC"
    cbw[4:8] = b"\x01\x00\x00\x00"
    cbw[8:12] = (read if data is None else len(data)).to_bytes(4, "little")
    cbw[12] = 128 if read else 0
    cbw[14] = len(cdb)
    cbw[15:15+len(cdb)] = cdb
    native.feed(b"\x00" + cbw)
    if data is not None:
        for offset in range(0, len(data), 64):
            native.feed(b"\x00" + data[offset:offset+64])
    output = bytearray() if buffer is None else buffer
    output_offset = 0
    status = None
    while True:
        packet = native.tx()
        if packet is None:
            break
        if packet[:1] == b"\x00":
            if len(packet) == 14 and packet[1:5] == b"USBS":
                status = packet[-1]
            elif read:
                if buffer is None:
                    output.extend(packet[1:])
                else:
                    output[output_offset:output_offset+len(packet)-1] = packet[1:]
                    output_offset += len(packet)-1
        native.tx_done()
    assert status is not None
    if buffer is not None and status == 0:
        assert output_offset == read
    return status, output


def read_sector(lba):
    status, data = command(
        b"\x28\x00" + lba.to_bytes(4, "big") + b"\x00\x00\x01\x00", read=512, buffer=host_sector
    )
    assert status == 0 and len(data) == 512
    return data


def write_sector(lba, data):
    assert len(data) == 512
    status, _ = command(b"\x2a\x00" + lba.to_bytes(4, "big") + b"\x00\x00\x01\x00", data)
    assert status == 0


def image(path, cluster):
    # One-cluster PNGs; rewrite one directory slot to model deleting each
    # previously received file. Received ciphertext remains in the collector.
    start = 29 + (cluster - 2) * 8
    with open(path, "rb") as source:
        size = source.seek(0, 2)
        source.seek(0)
        assert 0 < size <= 4096
        for offset in range(0, size, 512):
            count = source.readinto(host_sector)
            for padding in range(count, 512):
                host_sector[padding] = 0
            write_sector(start + offset // 512, host_sector)
    sector = (cluster * 3 // 2) // 512
    fat = read_sector(1 + sector)
    offset = (cluster * 3 // 2) % 512
    assert offset < 511
    if cluster & 1:
        fat[offset] = (fat[offset] & 15) | 240
        fat[offset+1] = 255
    else:
        fat[offset] = 255
        fat[offset+1] = (fat[offset+1] & 240) | 15
    write_sector(1 + sector, fat)
    write_sector(13 + sector, fat)
    root = read_sector(25)
    entry = bytearray(32)
    entry[:11] = b"MEMORY  PNG"
    entry[11] = 32
    entry[26:28] = cluster.to_bytes(2, "little")
    entry[28:32] = size.to_bytes(4, "little")
    root[96:128] = entry
    write_sector(25, root)
    assert command(b"\x35" + bytes(9))[0] == 0
    while native.event() is not None:
        pass
    # FAT/directory buffers belong to the simulated external host. They do
    # not coexist with QR collection in the actual 65-byte USB poller.
    fat = root = entry = source = None
    gc.collect()
    result = native.decode()
    if result is None or result[0] != "qr":
        raise RuntimeError("image decode failed: " + str(result))
    assert collector.add_payload(result[1]).accepted


session.configure_gc()
os.mount(os.VfsPosix(), "/")
config.init()
config.unlock("", None)
session.register_strings()
device.initialize()
session._load_stores()
if WARM_NORMAL:
    from feuristic.fw import transports
    transports.fido_server()
    transports._card_obj()
    checkpoint("normal-protocols")
from feuristic.fw import transports
transports.suspend()
run(transports.wait_suspended())
session.release_import_modules()
if hasattr(session, "_clock_maintenance"):
    loop.schedule(session._clock_maintenance())
usbmodes.current = lambda: usbmodes.IMPORT
checkpoint("bootstrap")
from feuristic.apps.backup.restore import StreamingRestore
# The simulated external host reuses one sector, reserved before decoding.
# A real device receives only the 65-byte USB frames, never these host copies.
host_sector = bytearray(512)
collector = ImportSession(max_backups=1, max_bytes=DEVICE_MAX_BYTES, compact=True, reserve_bytes=5440)
streamed = StreamingRestore(
    Approve(), phrase, max_envelopes=DEVICE_MAX_ENVELOPES, max_sets=DEVICE_MAX_SETS,
    reserve_ledger=True,
)
native = feuristic_import.Session(_readme(), OUTPUT_SIDE, 1)
from feuristic.ui import screens
from feuristic.ui.backup_progress import Derivation
import trezorui_api
state = _State("backup")
progress = Derivation()
idle_controller = _controller(native, collector, state, streamed, progress)
idle_usb = _usb_task(native, collector, state)
idle_usb_buffer = bytearray(65)
idle_context = trezorui_api.show_warning(
    title="Import", button="Continue", description=state.message, allow_cancel=True
)
idle_layout = screens.NavLayout(idle_context.__enter__())
idle_screen = idle_layout.get_result()
idle_screen.send(None)
command(bytes(6))
command(b"\x03\x00\x00\x00\x12\x00", read=18)
checkpoint("decoder")
cluster = 4
for identity in range(IDENTITIES):
    with open(FIXTURES + "/" + str(identity) + ".list") as listing:
        for line in listing:
            image(FIXTURES + "/" + line.strip(), cluster)
            cluster += 1
            if (cluster * 3 // 2) % 512 == 511:
                cluster += 1
    checkpoint("received-" + str(identity+1))
    assert native.pause_decode()
    raw = collector.take_complete()
    assert raw is not None
    checkpoint("paused-" + str(identity+1))
    modules = utils.unimport_begin()
    from feuristic.core import store as record_store
    old_buffer = record_store.use_write_buffer(collector._arena)
    try:
        report = run(streamed.restore_envelope(raw))
    finally:
        record_store.use_write_buffer(old_buffer)
    if report.failed is not None:
        print("RESTORE_FAILED", report.failed)
        raise AssertionError("provider restore failed")
    raw = None
    session.release_import_stores()
    utils.unimport_end(modules)
    checkpoint("released-" + str(identity+1))
    assert native.resume_decode()
    checkpoint("resumed-" + str(identity+1))
assert len(streamed.report.restored) == IDENTITIES
assert streamed.incomplete_sets() == []
streamed.close()
idle_screen.close()
idle_layout.stop()
idle_context.__exit__(None, None, None)
idle_usb.close()
idle_controller.close()
native.close()
print("RESTORE_MEMORY_PROBE_OK", IDENTITIES)
# The restored records are all five real maximum-size providers. Exercise
# their export too, after releasing the importer exactly as the UI does.
streamed = collector = report = native = state = progress = raw = None
idle_screen = idle_layout = idle_context = idle_usb = idle_controller = None
idle_usb_buffer = host_sector = modules = listing = None
session.release_import_modules(keep_backup=True)
gc.collect()
from feuristic.fw import backup_providers
from feuristic.apps.backup.export import begin_full_export

class MaxEntries:
    # Force two-byte sequence/count and a maximal timestamp without retaining
    # 192 duplicate UID tuples. This is the native-export byte bound fixture.
    def __init__(self, entries):
        self.entries = entries

    def __len__(self):
        return 192

    def __getitem__(self, index):
        return self.entries[index % 5]

maximum_sizes = {"openpgp":5127, "fido2":4847, "piv":2500, "otp":379, "aes":241}
backup_providers.begin_export()
for profile in ("dense", "large"):
    exported = run(begin_full_export(Approve(), phrase, profile=profile))
    try:
        assert len(exported) == 5
        exported.entries = MaxEntries(exported.entries)
        exported.created = 0xFFFFFFFF
        for index in range(185, 190):
            built = exported.build(index)
            assert built.frames and built.count == 192
            if built.type == "fido2":
                assert built.envelope_len in (4721, maximum_sizes["fido2"])
            else:
                assert built.envelope_len == maximum_sizes[built.type]
            with screens._qr_layout("Backup", built.frames[0]) as qr:
                qr_layout = screens._QrLayout(qr)
                qr_wait = qr_layout.get_result()
                qr_wait.send(None)
                qr_wait.close()
                qr_layout.stop()
            print("MAX_EXPORT_MEMORY", profile, built.type, built.envelope_len, len(built.frames))
            built.frames.clear()
            built = qr_layout = qr_wait = qr = None
            checkpoint("max-export-" + profile)
    finally:
        exported.close()
        exported = None
backup_providers.end_export()
print("MAX_EXPORT_MEMORY_PROBE_OK")
"""

# Frozen production builds remove assert statements; retain every probe action.
SCRIPT = checked_script(SCRIPT)


def fixtures(directory: Path, identities: int, profile: str, fido_blobs: int) -> None:
    import segno

    sys.path[:0] = [str(ROOT / "tests/host/shims"), str(ROOT / "src"), str(ROOT)]
    from tests.host.aio import run
    from tests.host.backup import test_native_export_bounds as bounds

    from feuristic.apps.backup import envelope, frames
    from feuristic.platform import testing

    directory.mkdir(parents=True, exist_ok=True)
    salt = b"memory-probe-123"
    key = run(envelope.derive_key(b"Memory probe passphrase", salt))
    items = []
    for factory in (
        bounds.openpgp,
        bounds.fido2_many_blobs if fido_blobs == 64 else bounds.fido2,
        bounds.piv,
        bounds.otp,
        bounds.aes,
    ):
        testing.reset_all()
        provider, uid = factory()
        item = provider.export_identity(uid)
        provider.validate(item)
        items.append(item)
    for index in range(identities):
        item = items[index] if index < len(items) else items[-1]
        raw = envelope.seal(
            key,
            salt,
            envelope.KIND_FULL,
            [item],
            seq=(index + identities - 5) % identities + 1,
            count=identities,
            created=0xFFFFFFFF,
            backup_id=(index + 1).to_bytes(8, "big"),
        )
        names = []
        for frame_index, text in enumerate(
            reversed(frames.split(raw, (index + 1).to_bytes(8, "big"), profile))
        ):
            name = f"{index}-{frame_index}.png"
            buffer = io.BytesIO()
            segno.make(
                text, version=3 if profile == "large" else 9, error="m", boost_error=False, micro=False
            ).save(buffer, kind="png", scale=8, border=4)
            (directory / name).write_bytes(buffer.getvalue())
            names.append(name)
        (directory / f"{index}.list").write_text("\n".join(names) + "\n")
        print(f"fixture {index + 1}: {item['type']} {len(raw)} envelope bytes, {len(names)} PNGs", flush=True)

    (directory / "manifest.json").write_text(
        json.dumps({"identities": identities, "profile": profile, "fido_blobs": fido_blobs}) + "\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emulator", type=Path)
    parser.add_argument("--fixtures", type=Path, default=ROOT / "build/restore-memory-fixtures")
    parser.add_argument("--profile-dir", type=Path, default=ROOT / "build/restore-memory-profile")
    parser.add_argument("--heap", default="171492")
    parser.add_argument("--output-side", type=int, choices=(128, 192, 256, 320, 384, 512, 720), default=256)
    parser.add_argument("--identities", type=int, default=192)
    parser.add_argument("--profile", choices=("dense", "large"), default="dense")
    parser.add_argument("--fido-blobs", type=int, choices=(1, 64), default=64)
    parser.add_argument("--cold", action="store_true", help="omit NORMAL protocol warmup (diagnostic only)")
    parser.add_argument(
        "--frozen-probe", action="store_true", help="binary includes isolated frozen memory_probe module"
    )
    parser.add_argument("--generate-only", action="store_true")
    parser.add_argument("--reuse-fixtures", action="store_true")
    args = parser.parse_args()
    if not 5 <= args.identities <= 192:
        parser.error("identities must be 5..192 to cover every maximum provider")
    if not args.reuse_fixtures:
        fixtures(args.fixtures, args.identities, args.profile, args.fido_blobs)
    if args.generate_only:
        return 0
    if args.reuse_fixtures:
        manifest = json.loads((args.fixtures / "manifest.json").read_text())
        expected = {"identities": args.identities, "profile": args.profile, "fido_blobs": args.fido_blobs}
        if manifest != expected:
            parser.error("fixture manifest differs; regenerate or select matching fixture options")
    if args.emulator is None:
        parser.error("--emulator is required unless --generate-only")
    args.profile_dir.mkdir(parents=True, exist_ok=True)
    if any(args.profile_dir.iterdir()):
        parser.error("profile directory must be empty; choose a fresh disposable profile")
    env = dict(
        os.environ,
        TREZOR_PROFILE_DIR=str(args.profile_dir.resolve()),
        SDL_VIDEODRIVER="dummy",
        MICROPYPATH=".frozen:.",
        FEURISTIC_MEMORY_FIXTURES=str(args.fixtures.resolve()),
        FEURISTIC_MEMORY_IDENTITIES=str(args.identities),
        FEURISTIC_MEMORY_WARM="0" if args.cold else "1",
        FEURISTIC_MEMORY_OUTPUT=str(args.output_side),
    )
    constants = (
        f"FIXTURES={str(args.fixtures.resolve())!r}\nIDENTITIES={args.identities}\n"
        f"WARM_NORMAL={not args.cold!r}\nOUTPUT_SIDE={args.output_side}\n"
    )
    return subprocess.run(
        [
            str(args.emulator.resolve()),
            "-O0",
            "-X",
            "heapsize=" + args.heap,
            "-c",
            (
                'import sys; sys.path[:] = [".frozen"]; import feuristic.fw.memory_probe'
                if args.frozen_probe
                else constants + SCRIPT
            ),
        ],
        cwd=ROOT / "upstream/trezor-firmware/core/src",
        env=env,
        check=False,
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
