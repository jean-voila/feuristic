---
title: OpenPGP and GnuPG on Trezor Safe 3
description: Use Feuristic's OpenPGP Card 3.4 with GnuPG for Ed25519 signatures, X25519 decryption and RSA-2048 on Trezor Safe 3.
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# OpenPGP with GnuPG

Feuristic exposes an **OpenPGP Card 3.4** over the native CCID smart-card
interface. It supports Ed25519 signing/authentication, X25519 decryption and
RSA-2048. No trezor-agent is required.

```sh
gpg --card-status
gpg --card-edit
```

Use a disposable `GNUPGHOME` while testing. If necessary, configure scdaemon with
`disable-ccid` and `pcsc-shared` to use PC/SC. Synchronise the device clock before
local key generation: OpenPGP fingerprints include key creation dates.

**Cryptography → OpenPGP** manages keys and card PINs. Initial PW1 is `123456`;
initial PW3 is `12345678`. Change them before useful identities are added.
These are separate from the device PIN.

GnuPG certificate creation involves key-generation and certification-signature
requests. Read each device prompt. Signature/decryption prompts expire after
30 seconds; an expired or refused request must fail.

Read the [user guide](../user/guide.md), [OpenPGP protocol](../protocols/openpgp.md)
and [physical test report](../acceptance/campaign-2026-10-21-T2B1-macos.md).
