---
title: TOTP and HOTP codes on Trezor Safe 3
description: Import otpauth QR images over USB and display TOTP and HOTP codes on Trezor Safe 3 with Feuristic. Supports PNG, baseline JPEG and serial clock sync.
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# TOTP and HOTP

Open **Authentication → OTP → Add QR over USB** and copy one `otpauth://` QR
image onto the temporary FAT12 drive. Read the account and parameters on the
device, confirm, then eject the volume from the computer.

- PNG or baseline JPEG; progressive JPEG and HEIC are unsupported.
- At most 256 KiB and 1024 × 1024 pixels, with one relevant QR per image.
- SHA1/SHA256/SHA512, 6/7/8 digits; TOTP periods from 15 to 300 seconds.
- HOTP increments its persistent counter only after a physical confirmation.

## Set the time for TOTP

Choose **Settings → TOTP time → Sync over USB**. Send the current Unix time
through the temporary serial port using any terminal, or run:

```sh
uv run python tools/feuristic_time.py
```

The clock is retained while USB modes change, but is lost on power removal.
Unsynchronised devices show a request to set the time instead of inventing a
code. See [time sync](../protocols/time-sync-v1.md) and the
[OTP URI profile](../protocols/otpauth.md).
