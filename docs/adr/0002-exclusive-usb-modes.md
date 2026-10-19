<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# ADR-0002: Exclusive normal, time-sync and QR-import USB modes

Status: accepted. Date: 2026-10-17; documented during handoff on 2026-10-18.

## Context

FIDO HID, CCID, standard CDC-ACM and MSC cannot all fit the smallest model's
endpoint and memory budgets at once. Importing hostile images also requires
bounded decoder memory without keeping every protocol object live.

## Decision

Expose HID FIDO plus one CCID reader in normal mode. Enter CDC-ACM alone only
from Settings → TOTP time → Sync over USB. Enter FAT12 MSC alone only from
Add QR via USB or Restore. Each switch detaches/re-enumerates the device and
invalidates transport sessions. Keep identical behavior on T2B1 and T3B1.

The MCU kernel moves bounded packets; application parsing remains
unprivileged. Decode incoming images as a stream, then interpret a complete,
synchronized QR, then request local confirmation before persistent writes.
Keep MSC present until clean host eject in the normal completion path.
The volume exposes no secret store and does not retain copied image data.

## Consequences

FIDO/smart-card clients are temporarily unavailable during import or time sync
and may require reconnecting after return. TOTP time survives a logical mode
switch but not power loss. The operator must copy backup images one at a time
and eject when requested; filesystem write ordering remains a hardware OS
acceptance gate. Standard serial/PCSC/MSC software suffices without a dedicated
companion. Debug builds add an unsafe debuglink interface that must be absent
from qualification artifacts. Details: [architecture](../architecture.md),
[streaming ADR](0003-streaming-image-import.md), [CCID](../protocols/ccid.md),
[time protocol](../protocols/time-sync-v1.md), [R05](../acceptance/R05.md).
