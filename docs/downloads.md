---
title: Download Trezor Safe 3 firmware
description: Download Feuristic firmware binaries for Trezor Safe 3 T2B1 and T3B1, verify SHA-256 checksums and follow the custom firmware installation guide.
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Download Feuristic firmware

[Open GitHub Releases](https://github.com/jean-voila/feuristic/releases){ .md-button .md-button--primary }

Use a **tagged development pre-release** while hardware acceptance is unfinished.
Pre-releases may not appear behind GitHub's `/releases/latest` link; open the
release list and choose the version explicitly. While the repository is private,
you must be signed in with repository access to download its assets.

| Your internal model | Download |
|---|---|
| **T2B1** | `feuristic-<version>-T2B1-<commit>.bin` |
| **T3B1** | `feuristic-<version>-T3B1-<commit>.bin` |

A release includes both binaries, SHA-256 sidecars, `SHA256SUMS`, an SPDX SBOM,
build provenance, corresponding source and licenses. Debug builds are not
installation candidates. The GitHub-generated source ZIP alone does not contain
Git submodule contents; use the supplied corresponding-source archive.

## Verify before installing

Download `SHA256SUMS` and your `.bin` into the same directory.

=== "macOS"

    ```sh
    shasum -a 256 -c SHA256SUMS --ignore-missing
    ```

=== "Linux"

    ```sh
    sha256sum --ignore-missing -c SHA256SUMS
    ```

=== "Windows PowerShell"

    ```powershell
    Get-FileHash .\feuristic-*-T2B1-*.bin -Algorithm SHA256
    ```

    Compare the result with the matching line in `SHA256SUMS`. Use T3B1 instead
    if that is the internal model reported by your device.

Checksums confirm integrity relative to the release manifest. Development
images use public upstream development keys and retain the mandatory unsafe
vendor warning; they are not manufacturer-signed firmware.

## Install and recover

Follow [installation](user/install.md). Trezor Suite can select a local custom
firmware file, and `trezorctl firmware update --filename <file.bin>` uploads it
from a terminal. Do not drag the binary onto the temporary QR import volume.

For a failed application boot, re-enter the official bootloader and upload a
known-good binary of the correct model. Do not replace the boardloader or
bootloader. Reinstalling official firmware does not restore factory attestation.
