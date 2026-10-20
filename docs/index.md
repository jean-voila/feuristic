<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Feuristic documentation

**Development candidate: no real-hardware qualification yet.** The
[specification](spec/cahier-des-charges-v1.0.md) fixes the product requirements;
[acceptance R01–R16](acceptance/README.md) records what must actually be tested
on both Safe 3 revisions before a stable release.

| Reader | Start here |
|---|---|
| Hardware tester | [Installation and irreversible unlock](user/install.md), [French guide](user/guide-fr.md), [English guide](user/guide-en.md), [acceptance](acceptance/README.md) |
| Developer | [Building](developer/building.md), [testing](developer/testing.md), [emulator](developer/emulator.md), [patches](developer/patches.md), [handoff](developer/handoff.md) |
| Reviewer | [Architecture](architecture.md), [threat model](threat-model.md), [security history](security-history.md), [release checklist](release-checklist.md), [release procedure](developer/release.md) |

Protocols: [FIDO2](protocols/fido2.md), [CCID](protocols/ccid.md),
[OpenPGP](protocols/openpgp.md), [PIV](protocols/piv.md),
[AES-GCM/RNG](protocols/aes-gcm-iso7816-v1.md), [time sync](protocols/time-sync-v1.md),
[otpauth](protocols/otpauth.md), [backup format](protocols/backup-format-v1.md),
[OTP backups](protocols/backup-otp.md), [OpenPGP backups](protocols/backup-openpgp.md),
[PIV backups](protocols/backup-piv.md), [AES backups](protocols/backup-aes.md).

Decisions: [pinned upstream](adr/0001-upstream-integration.md),
[exclusive USB modes](adr/0002-exclusive-usb-modes.md),
[streaming import](adr/0003-streaming-image-import.md),
[backup envelope](adr/0004-backup-envelope.md).

Implementation notes: [MicroPython](developer/micropython-compat.md),
[shared storage](developer/storage-budget.md), [QR decoder](developer/lib-fqr.md),
[image decoder](developer/lib-fimg.md), [import RAM](developer/import-memory.md),
[backup readiness](developer/backup-readiness.md), [FAT12/SCSI](developer/lib-fmsc.md),
[RSA](developer/rsa.md). Project policy: [security](../SECURITY.md),
[contributing](../CONTRIBUTING.md), [license](../LICENSE), [notices](../NOTICE).
