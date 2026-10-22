---
title: Shared storage budget (R04)
description: How passkeys, OTP accounts, largeBlob and card keys share the 64 KiB storage sector on Trezor Safe 3, and the R04 capacity regression test.
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Shared storage budget (R04)

Both models share a 64 KiB active norcow sector. Application count limits do
not allocate separate sectors. The R04 regression test fills 100 discoverable
credentials, 32 HOTP accounts and the full 4096-byte serialized largeBlob
array, with the FIDO PIN configured.

`tests/host/fido2/test_capacity_budget.py` uses unmodified python-fido2 through
the real feuristic CTAPHID/CTAP implementation. Each credential has
`credProtect=3`, `hmac-secret` and `largeBlobKey`. The maximum-fields case uses
a 128-byte RP ID, 64-byte user IDs and both 64-byte account names. Each OTP
has a 64-byte secret; its maximum metadata is a 32-byte issuer and a 64-byte
account. Every HOTP counter is advanced and persisted.

The test writes three different full largeBlob arrays, retaining both A/B
copies, then replaces a credential and an OTP record. It checks capacity
refusal, preservation of existing data and reloading of the stores.

Measured with the T3B1 norcow live-item model on 18 October 2026:

| Input profile | Live application bytes | Free bytes before the 1024-byte system reserve |
|---|---:|---:|
| Typical field lengths | 32,768 | 32,752 |
| Maximum field lengths | 62,688 | 2,832 |

The model allows 65,520 bytes after the sector header. Protected values carry
a 12-byte IV and 16-byte tag; public counters carry neither. T3B1 small items
up to 12 stored bytes fit in one 16-byte block; large items need a header
block and blocks for the value plus its validity byte. These rules come from
the pinned upstream `storage/storage.c` and `storage/norcow_blockwise.h`.
They conservatively bound T2B1's smaller bitwise format. Boundary examples
are tested in `tests/host/core/test_storage_budget.py`.

`tests/upy/test_capacity.py` independently exercises maximum fields on the
emulator's actual encrypted norcow, including twenty copy-on-write update
cycles to force compaction. It passes for T2B1 and T3B1 emulators. This checks
the storage implementation rather than only a Python size estimate.

The worst-case scenario leaves little room for other identities. These
measurements do **not** promise that maximum-size OpenPGP data, four maximum
PIV certificates and all AES slots also coexist with maximum-size R04 data.
Those stores share the remaining space and must refuse additions safely.
Hardware flash interruption and acceptance tests remain unexecuted.
