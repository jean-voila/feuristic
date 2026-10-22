---
title: Hardware acceptance tests R01–R16
description: The R01–R16 hardware acceptance procedures for feuristic on Trezor Safe 3 T2B1 and T3B1, and which results come from real devices.
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Hardware acceptance R01–R16

**Initial status of the complete campaign: NOT EXECUTED on hardware.** Host and
emulator tests provide separate preparatory evidence. A procedure’s presence
does not qualify a physical device.

An [initial partial T2B1/macOS campaign](campaign-2026-10-21-T2B1-macos.md)
records physical tests and fixes on 21 October 2026 UTC. Complete-procedure
statuses below remain unchanged until every step passes.

A stable release requires every criterion on **both T2B1 and T3B1**, on every
specified OS. Use two sacrificial devices, disposable secrets, reliable data
cables, macOS/Windows/Linux, two ordinary cameras/phones for R13 and controlled
actual power cuts for R04/R12. Unlocking irreversibly erases data and original
attestation; follow [installation](../user/install.md).

## Campaign record

Keep a private evidence folder per commit/model/OS. Record UTC date, operator,
exact model/device reference, bootloader/firmware versions, full source commit,
image SHA-256, source cleanliness/diff, tool/OS versions, power/cable, commands,
steps, observed results, deviations and evidence links. Mark each test `PASS`,
`FAIL` or `NOT EXECUTED`; a skip is not a pass. Keep originals private and redact
PINs, keys, QR backup photos and APDUs before publication.

For OS-related criteria, record T2B1/macOS, T2B1/Windows, T2B1/Linux,
T3B1/macOS, T3B1/Windows and T3B1/Linux separately. Other criteria require at least
one physical run per model. R14 requires both cross-revision directions. After
a defect or image change, repeat affected criteria and identify the new hash.

| Criterion | Procedure | T2B1 | T3B1 |
|---|---|---|---|
| R01 | [Boot, buttons, PIN, FR/EN](R01.md) | NOT EXECUTED | NOT EXECUTED |
| R02 | [FIDO and passkeys](R02.md) | NOT EXECUTED | NOT EXECUTED |
| R03 | [CTAP 2.1 and extensions](R03.md) | NOT EXECUTED | NOT EXECUTED |
| R04 | [Capacity, endurance, power cuts](R04.md) | NOT EXECUTED | NOT EXECUTED |
| R05 | [MSC import per OS](R05.md) | NOT EXECUTED | NOT EXECUTED |
| R06 | [Hostile images/QR](R06.md) | NOT EXECUTED | NOT EXECUTED |
| R07 | [CDC-ACM clock](R07.md) | NOT EXECUTED | NOT EXECUTED |
| R08 | [TOTP/HOTP vectors](R08.md) | NOT EXECUTED | NOT EXECUTED |
| R09 | [OpenPGP/GnuPG interop](R09.md) | NOT EXECUTED | NOT EXECUTED |
| R10 | [PIV/OpenSC interop](R10.md) | NOT EXECUTED | NOT EXECUTED |
| R11 | [GET CHALLENGE randomness](R11.md) | NOT EXECUTED | NOT EXECUTED |
| R12 | [AES-GCM/nonces](R12.md) | NOT EXECUTED | NOT EXECUTED |
| R13 | [Camera readability and multi-QR](R13.md) | NOT EXECUTED | NOT EXECUTED |
| R14 | [Cross-revision backups](R14.md) | NOT EXECUTED | NOT EXECUTED |
| R15 | [Consent, PINs, erasure](R15.md) | NOT EXECUTED | NOT EXECUTED |
| R16 | [Build, licenses, SBOM, reproducibility](R16.md) | NOT EXECUTED | NOT EXECUTED |

## Shared software preparation

Follow [building](../developer/building.md) and [testing](../developer/testing.md)
to pin tools and run lint, host/C tests, ARM cross checks, fuzzing and both
emulators before flashing. Do not export real data to prepare a campaign.
PID `1209:0001` is provisional; [CCID](../protocols/ccid.md) documents Linux
libccid binding. Temporary modes suspend FIDO/CCID and require client reopening
after re-enumeration. An emulator’s virtual reader is not a physical USB reader.

## Publication decision

An unexecuted cell, camera-readability failure, memory overflow, loss of
atomicity, nonce reuse or export without consent blocks qualification. The
responsible maintainer attaches evidence and signs the campaign decision;
changing a table without executing tests is prohibited. The
[release checklist](../release-checklist.md) adds PID, signing/provenance and
source/license distribution gates.
