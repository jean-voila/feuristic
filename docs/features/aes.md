---
title: AES-GCM encryption and hardware random bytes
description: Use Feuristic's AES-256-GCM smart-card profile and ISO 7816 GET CHALLENGE on Trezor Safe 3, with device-generated nonces and physical consent.
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# AES-GCM and random bytes

Create an AES key under **Cryptography → AES**. Each of the 16 identifiers has
a name, enabled state and confirmation policy: every operation or once per
card session. Lock, reset and USB mode changes end session authorisations.

The public [AES-GCM APDU profile](../protocols/aes-gcm-iso7816-v1.md) specifies
SELECT, MSE and PSO encipher/decipher. It supports up to **3584 bytes of text**
and **256 bytes of AAD** per operation. The device chooses and persists its
nonce counter before use. A rejected authentication tag returns no plaintext.
This is a versioned smart-card profile, not a claimed bulk-encryption interface.

`GET CHALLENGE` provides 1–32 random bytes through ISO 7816, with health checks
and rate limits. **Cryptography → Randomness** shows health information and a
local self-test. Different observed outputs are not an entropy certification.
