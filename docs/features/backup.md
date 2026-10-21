---
title: Encrypted QR backup and restore
description: Back up Feuristic identities as encrypted QR sequences on Trezor Safe 3 and restore from PNG or JPEG images through temporary USB mass storage.
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Encrypted QR backup and restore

Feuristic displays encrypted identity backups as QR sequences. Capture every
frame, keep the backup phrase separately and test restoration with disposable
identities before relying on it. The phrase must be 12–128 printable ASCII
characters and differ from the device PIN.

Restore through **Backup → Restore** by copying QR images onto the temporary
USB drive. Confirm each complete identity on the device. Keep the volume mounted
between identities; finish the import, review its result and eject from the OS.

Discoverable FIDO credentials, OpenPGP, PIV, OTP and AES identities have defined
backup profiles. A QR photo plus its phrase can recover the private keys.
A plain OTP export exposes its seed directly.

See the [user guide](../user/guide-en.md),
[encrypted envelope specification](../protocols/backup-format-v1.md) and
[acceptance plan](../acceptance/R13.md). Real-camera and inter-revision recovery
are remaining qualification work; the format specification is not proof that
those physical tests have passed.
