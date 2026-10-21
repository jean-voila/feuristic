#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Prepare an isolated frozen i686 probe tree without modifying firmware sources.

The host emulator has two intentional 64-bit assumptions: the insecure test
PRNG guard and the secp256k1 preallocated context size. Only this generated
Linux-hosted tree adapts them for i686. The probe can put MSC state in .bss,
matching the hardware's off-heap CCM placement, while retaining its real ABI.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path

from probe_normal_memory32 import SCRIPT as NORMAL_SCRIPT
from probe_restore_memory import SCRIPT

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--msc-on-heap", action="store_true", help="use unmodified Unix MSC allocation")
    args = parser.parse_args()
    upstream = ROOT / "upstream/trezor-firmware"
    destination = ROOT / "build/emu32-tree"
    destination.mkdir(parents=True, exist_ok=True)
    for entry in upstream.iterdir():
        if entry.name in (".git", ".venv", "core"):
            continue
        link = destination / entry.name
        if not link.exists():
            link.symlink_to(entry.resolve(), target_is_directory=entry.is_dir())
    core = destination / "core"
    core.mkdir(exist_ok=True)
    for entry in (upstream / "core").iterdir():
        if entry.name in ("embed", "src", "vendor") or entry.name.startswith("build"):
            continue
        link = core / entry.name
        if not link.exists():
            link.symlink_to(entry.resolve(), target_is_directory=entry.is_dir())
    for name in ("embed", "src"):
        target = core / name
        if not target.exists():
            shutil.copytree(upstream / "core" / name, target, symlinks=True)
            for link in target.rglob("*"):
                if link.is_symlink():
                    original = upstream / "core" / link.relative_to(core)
                    link.unlink()
                    link.symlink_to(original.resolve(), target_is_directory=original.is_dir())
    vendor = core / "vendor"
    if vendor.is_symlink():
        vendor.unlink()
    vendor.mkdir(exist_ok=True)
    for entry in (upstream / "core/vendor").iterdir():
        target = vendor / entry.name
        if target.exists():
            continue
        if entry.name == "trezor-crypto":
            shutil.copytree(entry.resolve(), target, symlinks=True)
        else:
            target.symlink_to(entry.resolve(), target_is_directory=entry.is_dir())
    for original, target in (
        (ROOT / "src/feuristic", core / "src/feuristic"),
        (ROOT / "firmware", core / "embed/feuristic"),
    ):
        if target.is_symlink():
            target.unlink()
        elif target.exists():
            shutil.rmtree(target)
        shutil.copytree(original, target, copy_function=shutil.copy)
    # The freezer's dependency checks use mtimes. Restoring an older source
    # snapshot must never reuse .mpy files from a later diagnostic variant.
    outputs = ROOT / "build/emu32-arm/i686-unknown-linux-gnu/debug/build"
    for output in outputs.glob("upymod-*/out"):
        for artifact in output.rglob("*"):
            if artifact.suffix in (".i", ".mpy") and "feuristic" in artifact.parts:
                artifact.unlink()
        for name in ("frozen_mpy.c", "frozen_mpy.c.dep"):
            (output / name).unlink(missing_ok=True)
    prefix = (
        'import os\nFIXTURES=os.getenv("FEURISTIC_MEMORY_FIXTURES")\n'
        'IDENTITIES=int(os.getenv("FEURISTIC_MEMORY_IDENTITIES"))\n'
        'WARM_NORMAL=os.getenv("FEURISTIC_MEMORY_WARM") != "0"\n'
        'OUTPUT_SIDE=int(os.getenv("FEURISTIC_MEMORY_OUTPUT"))\n'
    )
    (core / "src/feuristic/fw/memory_probe.py").write_text(prefix + SCRIPT)
    (core / "src/feuristic/fw/normal_memory_probe.py").write_text(NORMAL_SCRIPT)
    random_source = vendor / "trezor-crypto/rand_insecure.c"
    source = random_source.read_text()
    random_source.write_text(
        source.replace("sizeof(void *) == 8,", "(sizeof(void *) == 8 || sizeof(void *) == 4),")
    )
    build_source = core / "embed/crypto/build.rs"
    source = build_source.read_text()
    build_source.write_text(source.replace('Some("208")', 'Some("180")'))
    if not args.msc_on_heap:
        glue = core / "embed/feuristic/upymod/modfeuristic_import/modfeuristic_import.c"
        source = (
            glue.read_text()
            .replace(
                "#if (defined(STM32F427xx) || defined(STM32F429xx)) && !defined(TREZOR_EMULATOR)",
                "#if defined(STM32F427xx) || defined(STM32F429xx)",
            )
            .replace(
                'static import_static_t g_static __attribute__((section(".no_dma_buffers")));',
                "static import_static_t g_static;",
            )
            .replace('section(".no_dma_buffers"), ', "")
        )
        glue.write_text(source)
    sources = {}
    for directory in (
        ROOT / "src/feuristic",
        ROOT / "firmware",
        ROOT / "lib/fimg",
        ROOT / "lib/fqr",
        ROOT / "lib/fmsc",
    ):
        for path in directory.rglob("*"):
            if path.is_file() and path.suffix in (".py", ".c", ".h"):
                sources[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest = {
        "msc_off_heap": not args.msc_on_heap,
        "abi": "i686",
        "sources_sha256": sources,
        "probe_sha256": hashlib.sha256(SCRIPT.encode()).hexdigest(),
        "normal_probe_sha256": hashlib.sha256(NORMAL_SCRIPT.encode()).hexdigest(),
        "isolated_adaptations": [
            "host PRNG guard accepts pointer32",
            "secp context verified 180 bytes",
            "MSC and image context .bss replace CCM" if not args.msc_on_heap else "MSC unchanged",
        ],
    }
    (destination / "source-snapshot.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
