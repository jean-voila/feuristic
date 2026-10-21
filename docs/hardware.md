---
title: Supported Trezor hardware
description: Check Trezor Safe 3 T2B1 and T3B1 firmware compatibility. Safe 5, Safe 7, Model T and Model One are not supported by Feuristic.
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Supported Trezor hardware

| Device | Internal model | Feuristic |
|---|---|---|
| Trezor Safe 3, revision A | **T2B1** · STM32F427 | Build target; first physical T2B1/macOS campaign completed |
| Trezor Safe 3, revision B | **T3B1** · STM32U585 | Build and emulator target; physical acceptance incomplete |
| Trezor Safe 5 | T3T1 | Not supported |
| Trezor Safe 7 | Other hardware | Not supported |
| Trezor Model T / Model One | T2T1 / T1B1 | Not supported |

Two devices sold as Safe 3 can require different binaries. Read `internal_model`
with `trezorctl get-features` while the official firmware or bootloader is
running. After installing Feuristic, use **Settings → Hardware / version**.

```sh
trezorctl get-features
```

Never choose a binary based on casing color or the retail product name alone.
The installer must report the exact model before uploading.

## What changes when you install it?

The Safe 3 becomes a security key and smart card. Feuristic does not implement
Bitcoin wallets, signing cryptocurrency transactions, wallet-seed recovery or
migration from Trezor Suite. The official bootloader remains the recovery path.

See [installation](user/install.md) for storage erasure, bootloader unlock and
the permanent loss of original manufacturer attestation.
