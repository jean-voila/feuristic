---
title: PIV smart card and certificates on Trezor Safe 3
description: Feuristic provides PIV slots 9A, 9C, 9D and 9E, P-256 and RSA-2048, native CCID and PC/SC for standard PIV and PKCS#11 clients.
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# PIV smart card and certificates

Feuristic implements PIV over CCID/PC/SC with **P-256 and RSA-2048** keys.
Slots are 9A (authentication), 9C (signature), 9D (key agreement) and 9E
(card authentication). Use standard PIV/OpenSC clients where compatible.

Generate and manage identities under **Cryptography → PIV → Identities**.
Certificates are uploaded by a PIV client and must match the generated key.
The [PIV reference](../protocols/piv.md) specifies APDUs, limits and PIN policies.

The factory PIN is `123456`, PUK is `12345678`, and the initial AES-192
administration key is `010203040506070801020304050607080102030405060708`.
Change these credentials before storing useful identities.

The first physical T2B1 campaign verified administration authentication,
P-256 generation and a signature against its public key. Complete certificate,
OpenSC and operating-system acceptance remains unfinished.
