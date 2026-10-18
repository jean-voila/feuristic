#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Generate an SPDX 2.3 (JSON) software bill of materials for a feuristic build.

Lists the firmware components that end up in the binary: feuristic itself,
the pinned upstream Trezor firmware (with the commit and the applied patch
series), the upstream submodules compiled into the firmware, and the code
vendored under lib/third_party. Optional ``--firmware`` files are added with
their SHA-256 checksums.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import subprocess
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UPSTREAM = ROOT / "upstream" / "trezor-firmware"

# upstream submodules that are compiled into feuristic firmware images
FIRMWARE_SUBMODULES = {
    "vendor/micropython": "MIT",
    "vendor/QR-Code-generator": "MIT",
    "vendor/secp256k1-zkp": "MIT",
    "vendor/cmsis_5": "Apache-2.0",
    "vendor/cmsis_device_u5": "Apache-2.0",
    "vendor/stm32u5xx_hal_driver": "BSD-3-Clause",
    "vendor/mldsa-native": "Apache-2.0 OR ISC OR MIT",
}
THIRD_PARTY_LICENSES = {"bearssl": "MIT"}


def git(*args: str, cwd: Path = ROOT) -> str:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True).stdout.strip()


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def spdx_id(name: str) -> str:
    return "SPDXRef-" + "".join(c if c.isalnum() else "-" for c in name)


def package(name: str, version: str, license_id: str, url: str, comment: str = "") -> dict:
    pkg = {
        "SPDXID": spdx_id(name),
        "name": name,
        "versionInfo": version,
        "downloadLocation": url,
        "filesAnalyzed": False,
        "licenseConcluded": license_id,
        "licenseDeclared": license_id,
        "copyrightText": "NOASSERTION",
        "supplier": "NOASSERTION",
    }
    if comment:
        pkg["comment"] = comment
    return pkg


def build(firmware_files: list[Path]) -> dict:
    from importlib import util

    spec = util.spec_from_file_location("v", ROOT / "src/feuristic/version.py")
    mod = util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    version = mod.VERSION
    rev = git("rev-parse", "HEAD")
    base = git("ls-tree", "HEAD", "upstream/trezor-firmware").split()[2]
    patches = (ROOT / "patches" / "series").read_text().split()
    patches = [p for p in patches if p.endswith(".patch")]

    packages = [
        package(
            "feuristic", version, "GPL-3.0-only", "https://github.com/jean-voila/feuristic", f"git {rev}"
        ),
        package(
            "trezor-firmware",
            base,
            "GPL-3.0-only AND LGPL-3.0-only AND MIT",
            "https://github.com/trezor/trezor-firmware",
            "pinned upstream (core/, storage/: GPL-3.0; crypto/: mostly MIT); "
            f"modified by {len(patches)} feuristic patches: {', '.join(patches)}",
        ),
    ]
    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": spdx_id("feuristic"),
        },
        {
            "spdxElementId": spdx_id("feuristic"),
            "relationshipType": "CONTAINS",
            "relatedSpdxElement": spdx_id("trezor-firmware"),
        },
    ]
    for path, lic in FIRMWARE_SUBMODULES.items():
        sub = UPSTREAM / path
        try:
            commit = git("rev-parse", "HEAD", cwd=sub)
            url = git("config", "--get", "remote.origin.url", cwd=sub)
        except subprocess.CalledProcessError:
            continue
        name = path.split("/")[-1]
        packages.append(package(name, commit, lic, url))
        relationships.append(
            {
                "spdxElementId": spdx_id("trezor-firmware"),
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": spdx_id(name),
            }
        )
    for d in sorted((ROOT / "lib" / "third_party").glob("*")):
        if not d.is_dir():
            continue
        readme = next(iter(d.glob("README*")), None)
        comment = readme.read_text()[:600] if readme else ""
        lic = THIRD_PARTY_LICENSES.get(d.name, "NOASSERTION")
        packages.append(package(d.name, "vendored", lic, "NOASSERTION", comment))
        relationships.append(
            {
                "spdxElementId": spdx_id("feuristic"),
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": spdx_id(d.name),
            }
        )

    files = []
    for fw in firmware_files:
        files.append(
            {
                "SPDXID": spdx_id("file-" + fw.name),
                "fileName": fw.name,
                "checksums": [{"algorithm": "SHA256", "checksumValue": sha256(fw)}],
                "licenseConcluded": "GPL-3.0-only",
                "copyrightText": "NOASSERTION",
            }
        )
        relationships.append(
            {
                "spdxElementId": spdx_id("feuristic"),
                "relationshipType": "GENERATES",
                "relatedSpdxElement": spdx_id("file-" + fw.name),
            }
        )

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"feuristic-{version}",
        "documentNamespace": f"https://github.com/jean-voila/feuristic/spdx/{version}-{rev[:12]}-{uuid.uuid4()}",
        "creationInfo": {
            "created": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "creators": ["Tool: feuristic-tools/sbom.py"],
        },
        "packages": packages,
        "files": files,
        "relationships": relationships,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", required=True)
    ap.add_argument("--firmware", nargs="*", default=[], type=Path)
    args = ap.parse_args()
    doc = build(args.firmware)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"wrote {out} ({len(doc['packages'])} packages)")


if __name__ == "__main__":
    main()
