---
title: Trezor custom firmware questions
description: Answers about installing custom firmware on Trezor Safe 3, Safe 5 compatibility, passkeys, OpenPGP, PIV, wallet backups and firmware recovery.
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Trezor custom firmware questions

## What is feuristic?

feuristic is independent, GPL-3.0-only custom firmware for the Trezor Safe 3.
It replaces the wallet application with FIDO2 passkeys, OpenPGP, PIV, OTP,
AES-GCM and encrypted identity backups. It is not made or endorsed by Trezor.

## Does it work on Trezor Safe 5 or Safe 7?

No. Only Safe 3 **T2B1 and T3B1** are build targets. Safe 5, Safe 7, Model T and
Model One require other hardware support. Do not flash a Safe 3 image onto them.

## Can I still use it as a Bitcoin wallet?

No. feuristic has no wallet application and cannot restore a Trezor recovery
seed. Back up any existing wallet before the irreversible installation.

## Can I install it by copying a .bin onto a USB drive?

No. Download the exact model's binary, then upload it through the bootloader
using Trezor Suite's custom firmware option or `trezorctl`. The temporary
feuristic USB drive accepts QR images for OTP and backup import only.

## Does installation erase the device?

Yes. Bootloader unlocking erases storage and permanently removes original
manufacturer attestation and pairing secrets. See [installation](user/install.md).
Returning to official firmware does not restore that attestation.

## Why does it display “UNSAFE, DO NOT USE!”?

The official bootloader displays this mandatory warning for the development
vendor header. It remains visible on these candidates. A passing checksum or a
project signature is not a manufacturer endorsement.

## Do I need a companion application?

No. Use standard WebAuthn, GnuPG and PC/SC clients. Codes, configuration,
confirmations and QR exports are on-device. Optional repository tools can
synchronise the clock and help development.

## Are my passkeys exportable?

Discoverable passkeys can be exported in encrypted identity backups. Do not
treat them as non-exportable credentials. Non-discoverable credentials are not
listed as backup identities. Read the [FIDO2 protocol](protocols/fido2.md).

## Is there a stable release?

Version 0.1.0 is the first public release: optimized images without debuglink.
It is not yet hardware qualified. A first T2B1/macOS campaign passed core
workflows; the full two-model and operating-system acceptance matrix, required
for 1.0, is incomplete. See [test results](acceptance/campaign-2026-10-21-T2B1-macos.md).

## Can I report a vulnerability publicly?

Do not put secrets or vulnerability details in a public issue. Follow the
[security policy](security.md) and the private reporting channel it documents.
