#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Measure real MicroPython import allocations, optionally in a frozen emulator.

This probes allocation lifetimes, not physical Safe 3 RAM. A unix emulator uses
64-bit objects and allocates the fmsc state on its heap; T2B1 instead puts the
20,080-byte fmsc/cache/reorder state in CCM. Use --frozen binary build inputs
recorded alongside the output; a source-based emulator loads bytecode in RAM.
The probe never opens real USB or reads a hardware device.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORE = ROOT / "upstream/trezor-firmware/core"

SCRIPT = r"""
import gc
import feuristic_import
from trezor import config
from feuristic.fw import device, session
from feuristic.apps.backup import frames
from feuristic.apps.importer.session import DEVICE_MAX_BYTES, MAX_SESSION_BYTES, ImportSession


def checkpoint(label):
    gc.collect()
    print("IMPORT_MEMORY", label, gc.mem_alloc(), gc.mem_free())


config.init()
config.unlock("", None)
session.register_strings()
device.initialize()
session._load_stores()
checkpoint("bootstrap")
native = feuristic_import.Session(b"Memory probe: disposable data", OUTPUT_SIDE, 1)
checkpoint("native")
collector = ImportSession(max_bytes=DEVICE_MAX_BYTES if PER_IDENTITY else MAX_SESSION_BYTES, compact=COMPACT)
size = ENVELOPE_BYTES
cap = frames.chunk_capacity(PROFILE)
total = (size + cap - 1) // cap
base = size // total
extra = size - base * total
for identity in range(IDENTITIES):
    backup_id = (identity + 1).to_bytes(8, "big")
    for index in range(total):
        count = base + (1 if index < extra else 0)
        text = frames.encode_frame(backup_id, index + 1, total, b"x" * count)
        event = collector.add_payload(text.encode())
        if not event.accepted:
            raise RuntimeError("collector rejected bounded probe data")
    if identity in (0, 31, 99, IDENTITIES - 1):
        checkpoint("collected-" + str(identity + 1))
    if PER_IDENTITY:
        assert native.pause_decode()
        raw = collector.take_complete()
        checkpoint("one-identity-consumed")
        raw = None
        session.release_import_stores()
        gc.collect()
        assert native.resume_decode()
if not PER_IDENTITY:
    if RELEASE_DECODER:
        native.close()
        native = None
        checkpoint("decoder-released")
    action = collector.action()
    checkpoint("bulk-action-ciphertext-copy")
    del action
collector.finish()
if native is not None:
    native.close()
del collector
native = None
checkpoint("closed")
print("IMPORT_MEMORY_PROBE_OK")
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emulator", type=Path, required=True)
    parser.add_argument("--heap", default="20M")
    parser.add_argument("--output-side", type=int, default=512, choices=(256, 320, 384, 512, 720))
    parser.add_argument("--identities", type=int, default=153)
    parser.add_argument("--envelope-bytes", type=int, default=400)
    parser.add_argument("--profile", default="large", choices=("large", "dense"))
    parser.add_argument("--release-decoder", action="store_true")
    parser.add_argument("--per-identity", action="store_true")
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.identities <= 192 or not 1 <= args.envelope_bytes <= 65536:
        parser.error("identities must be 1..192 and envelope bytes 1..65536")
    constants = (
        f"OUTPUT_SIDE={args.output_side}\nIDENTITIES={args.identities}\n"
        f"ENVELOPE_BYTES={args.envelope_bytes}\nPROFILE={args.profile!r}\n"
        f"RELEASE_DECODER={args.release_decoder!r}\nPER_IDENTITY={args.per_identity!r}\nCOMPACT={args.compact!r}\n"
    )
    with tempfile.TemporaryDirectory(prefix="feuristic-import-memory-") as profile:
        env = dict(os.environ, TREZOR_PROFILE_DIR=profile, SDL_VIDEODRIVER="dummy", MICROPYPATH=".frozen:.")
        # -c works with frozen emulators, which intentionally refuse live files.
        result = subprocess.run(
            [str(args.emulator.resolve()), "-O0", "-X", "heapsize=" + args.heap, "-c", constants + SCRIPT],
            cwd=CORE / "src",
            env=env,
            check=False,
        )
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
