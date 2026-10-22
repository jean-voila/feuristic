#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Verify model images and reproducibility, then package corresponding source."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
from pathlib import Path

import sbom

ROOT = Path(__file__).resolve().parent.parent
MODELS = ("T2B1", "T3B1")


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def validate_image(path: Path, model: str) -> dict:
    from trezorlib import firmware
    from trezorlib.firmware.core import VendorFirmware

    image = firmware.parse(path.read_bytes())
    if not isinstance(image, VendorFirmware) or image.model().value.decode() != model:
        raise ValueError(f"Firmware model mismatch: {path.name}; expected {model}")
    image.verify()
    return {"model": model, "sha256": digest(path), "firmware_fingerprint": image.digest().hex()}


def verify_pair(image: Path, repeated: Path, model: str) -> dict:
    metadata = validate_image(image, model)
    if metadata["sha256"] != digest(repeated):
        raise ValueError(f"Reproducibility mismatch: {model}")
    sidecar = image.with_suffix(image.suffix + ".sha256").read_text().split()
    if sidecar != [metadata["sha256"], image.name]:
        raise ValueError(f"Invalid checksum sidecar: {image.name}")
    return metadata


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n")


def source_archive(target: Path, prefix: str) -> None:
    tracked = (
        subprocess.check_output(["git", "ls-files", "--recurse-submodules", "-z"], cwd=ROOT)
        .decode()
        .split("\0")
    )
    with tarfile.open(target, "w:gz", dereference=False) as archive:
        for name in sorted(filter(None, tracked)):
            path = ROOT / name
            if path.is_file() or path.is_symlink():
                archive.add(path, arcname=f"{prefix}/{name}", recursive=False)


def package(inputs: Path, output: Path) -> None:
    from importlib.util import module_from_spec, spec_from_file_location

    spec = spec_from_file_location("version", ROOT / "src/feuristic/version.py")
    version = module_from_spec(spec)
    spec.loader.exec_module(version)
    revision = git("rev-parse", "HEAD")
    if output.exists() and any(output.iterdir()):
        raise ValueError("Output directory must be empty")
    output.mkdir(parents=True, exist_ok=True)
    images = []
    metadata = []
    for model in MODELS:
        name = f"feuristic-{version.VERSION}-{model}-{revision[:12]}.bin"
        image = inputs / "firmware" / name
        repeated = inputs / "repro" / name.replace(".bin", "-repro.bin")
        info = verify_pair(image, repeated, model)
        info["file"] = name
        metadata.append(info)
        shutil.copy2(image, output / name)
        shutil.copy2(image.with_suffix(".bin.sha256"), output / (name + ".sha256"))
        images.append(output / name)
    patches = {
        name: digest(ROOT / "patches" / name)
        for name in (ROOT / "patches/series").read_text().split()
        if name.endswith(".patch")
    }
    repository = os.environ.get("GITHUB_REPOSITORY", "jean-voila/feuristic")
    run_id = os.environ.get("GITHUB_RUN_ID", "local")
    provenance = {
        "classification": "development candidate; not a stable or manufacturer-signed release",
        "version": version.VERSION,
        "source": {"repository": "https://github.com/jean-voila/feuristic", "commit": revision},
        "upstream_base": git("ls-tree", "HEAD", "upstream/trezor-firmware").split()[2],
        "patch_sha256": patches,
        "ci_run": f"https://github.com/{repository}/actions/runs/{run_id}",
        "images": metadata,
        "verification": "trezorlib vendor/code signatures; three matching Nix builds per model",
        "hardware": "T2B1 macOS initial campaign; full R01–R16 and T3B1 hardware qualification pending",
    }
    write_json(output / "PROVENANCE.json", provenance)
    write_json(output / f"feuristic-{version.VERSION}.spdx.json", sbom.build(images))
    for name in ("LICENSE", "NOTICE", "SECURITY.md"):
        shutil.copy2(ROOT / name, output / name)
    source_archive(output / f"feuristic-{version.VERSION}-source.tar.gz", f"feuristic-{version.VERSION}")
    (output / "BUILDING.txt").write_text(
        "feuristic development firmware for Trezor Safe 3\n\n"
        f"Source commit: {revision}\n"
        "The source archive includes modified upstream sources, dependency licenses, patches and lockfiles.\n"
        "For the identical Git/Nix build context, clone the repository and check out this commit.\n"
        "Run tools/ci/fetch-upstream.sh, then tools/ci/nix-build.sh firmware t2b1 (or t3b1).\n"
        "See docs/developer/building.md and docs/developer/release.md in the archive.\n"
        "Verify SHA256SUMS before installation. Installing unlocks and erases the device.\n"
        "Read docs/user/install.md. These images use public development signing keys.\n"
    )
    sums = [f"{digest(path)}  {path.name}\n" for path in sorted(output.iterdir()) if path.is_file()]
    (output / "SHA256SUMS").write_text("".join(sums))
    print(f"Packaged {len(images)} verified images in {output}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    package(args.input, args.output)


if __name__ == "__main__":
    main()
