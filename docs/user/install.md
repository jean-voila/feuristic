---
title: Install custom firmware on Trezor Safe 3
description: Install feuristic on Trezor Safe 3 T2B1 or T3B1 using the official bootloader, Trezor Suite or trezorctl. Model checks, irreversible unlock, updates and recovery.
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Install feuristic on Trezor Safe 3

**Release 0.x for T2B1 and T3B1.** Core workflows passed an initial
physical T2B1/macOS campaign; full hardware qualification remains in progress. Read the
[hardware results](../acceptance/campaign-2026-10-21-T2B1-macos.md).

## Install in three steps

1. **Download and verify.** Read the internal model with `trezorctl get-features`.
   Download that model’s `.bin` from [Releases](https://github.com/jean-voila/feuristic/releases)
   and [verify its checksum](../downloads.md). Back up the existing wallet.
2. **Unlock and upload.** Enter the bootloader with the left button held while
   reconnecting. Activate **Init connection**, unlock once with
   `trezorctl device unlock-bootloader`, and confirm the irreversible erase.
   Reconnect in bootloader mode. In Suite, open **Settings → Device → Danger Area
   → Install custom firmware** and select or drag the `.bin` into the upload box.
   Confirm the device prompts. The detailed CLI route below was tested on
   T2B1 with bootloader 2.1.16.
3. **Start feuristic.** Accept the third-party warning, choose English or French
   and create a test PIN. Continue with the [user guide](guide.md).

A firmware binary is uploaded through the bootloader. The temporary feuristic
OTP drive imports QR images; it does not install firmware.

## Understand the irreversible effects

Use a dedicated test device without funds or production identities. Keep its
existing wallet backup elsewhere. feuristic cannot restore a Trezor seed and
does not migrate wallets.

**Unlocking permanently erases storage and the secrets used for original
manufacturer attestation.** Reinstalling official firmware does not restore
those secrets. The original authenticity proof and FIDO attestation are no
longer usable. feuristic continues with the remaining storage protections and
uses its own FIDO attestation profile, without manufacturer certification.

The pinned upstream sources document these effects:

- [Unlock workflow](https://github.com/trezor/trezor-firmware/blob/66ac7295aaa0aa9fb427a0cc035b34dd61b6d472/core/embed/projects/bootloader/workflow/wf_unlock_bootloader.c): local confirmation, `erase_storage`, then `secret_unlock_bootloader`.
- [STM32F4 secrets](https://github.com/trezor/trezor-firmware/blob/66ac7295aaa0aa9fb427a0cc035b34dd61b6d472/core/embed/sec/secret/stm32f4/secret.c) and [STM32U5 secrets](https://github.com/trezor/trezor-firmware/blob/66ac7295aaa0aa9fb427a0cc035b34dd61b6d472/core/embed/sec/secret/stm32u5/secret.c): secret or private-slot erasure.
- [Optiga initialisation](https://github.com/trezor/trezor-firmware/blob/66ac7295aaa0aa9fb427a0cc035b34dd61b6d472/core/embed/sec/optiga/optiga_init.c): loss of the protected channel and attestations when the pairing secret is unavailable.
- [T2B1 vendor header](https://github.com/trezor/trezor-firmware/blob/66ac7295aaa0aa9fb427a0cc035b34dd61b6d472/core/embed/models/T2B1/vendorheader/vendor_unsafe.json) and [T3B1 vendor header](https://github.com/trezor/trezor-firmware/blob/66ac7295aaa0aa9fb427a0cc035b34dd61b6d472/core/embed/models/T3B1/vendorheader/vendor_unsafe.json): mandatory `UNSAFE, DO NOT USE!` warning, delay and user acknowledgement.

The warning appears at startup. Removing it or presenting the firmware as
manufacturer trusted is not part of installation.

## Prepare the binary and host tools

The commands below run from a prepared repository checkout. Follow
[build setup](../developer/building.md) in a fresh checkout if needed.
`trezorctl` comes from the pinned upstream Python package through `uv`.

```sh
uv run trezorctl --help
uv run trezorctl device unlock-bootloader --help
uv run trezorctl firmware update --help
```

Use a reliable USB data cable and stable power. Close Suite, browsers and
other device clients when using the CLI route.

Choose a downloaded image explicitly, or build the **exact model**, for example:

```sh
make firmware MODEL=T2B1
FEURISTIC_TEST_MODEL=T2B1
FEURISTIC_TEST_VERSION=$(uv run --quiet python -c "import sys; sys.path.insert(0,'src'); from feuristic.version import VERSION; print(VERSION)")
FEURISTIC_TEST_REV=$(git rev-parse --short=12 HEAD)
FW="$PWD/dist/feuristic-$FEURISTIC_TEST_VERSION-$FEURISTIC_TEST_MODEL-$FEURISTIC_TEST_REV.bin"
```

For a downloaded image, set `FW` to its absolute path instead. Do not install a
`DEBUG.bin`. In the directory containing the image and its checksum file, run:

```sh
shasum -a 256 -c "$(basename "$FW").sha256"
uv run trezorctl firmware update --dry-run --filename "$FW"
```

On Linux use `sha256sum`. The checksum sidecar contains a basename, so run its
check from the download directory. The dry run requires a detectable device;
it validates host-side steps without writing firmware. These images use public
upstream development signing keys. A checksum proves integrity relative to its
manifest, not the publisher’s identity. Diagnose model, header or signature
errors before flashing; do not bypass checks with `--raw` or `--skip-check`.

## Detailed CLI installation

1. Record the internal model, bootloader version, source commit and binary
   SHA-256 in the [acceptance record](../acceptance/README.md).
2. Unplug and reconnect while holding **left**. If a submenu offers **Factory
   Reset**, **Exit menu** and **Reboot Trezor**, select **Exit menu** with left/right
   and confirm with both buttons. On the main bootloader screen, choose
   **Init connection** on the left to enable USB. Before this, `trezorctl` may
   detect no device. Follow the actual screen if another bootloader differs.
3. After accepting the irreversible effects, run:

   ```sh
   uv run trezorctl device unlock-bootloader
   ```

   Confirm on the device. Cancellation before confirmation avoids erasure; it
   cannot recover erased secrets afterward. When **Bootloader unlocked / Please
   reconnect the device** appears, reconnect and repeat step 2, including
   **Init connection**. An already unlocked device does not need another unlock.
4. Install the verified image while still in the bootloader:

   ```sh
   uv run trezorctl firmware update --filename "$FW"
   ```

5. Check the model and warning on the device, confirm and wait until transfer
   and installation finish. Keep the cable connected. Reboot if requested.
6. Accept the third-party boot warning. First setup asks for language and PIN.
   An already configured device should show **FEURISTIC / Press any button...**
   before PIN entry. Follow [R01](../acceptance/R01.md) before further testing.
   Record failures as candidate defects; successful installation alone does
   not qualify the firmware.

The [official Trezor procedure](https://trezor.io/support/troubleshooting/device-issues/install-custom-firmware-on-trezor-safe-3)
describes file upload through Suite and bootloader confirmations. It does not
validate feuristic. The CLI procedure above uses the pinned upstream tools.

## Updates and recovery

Before updating, export identities and test restoration on another test device.
Storage preservation across development versions is not guaranteed. Recheck
the model and checksum, enter the bootloader and reuse `firmware update
--filename`. Do not unlock an already unlocked bootloader again.

If the application fails to start, use the official bootloader: hold left while
connecting and upload a known-good image for the exact model. Do not replace the
boardloader or bootloader and do not use SWD/DFU commands meant for blank boards.
Follow current manufacturer instructions to return to official firmware; this
does not recover erased identities or factory attestation.
