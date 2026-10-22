---
title: "ADR 0001: pinned upstream and patch series"
description: Why feuristic pins an unmodified trezor-firmware release and applies a reviewable patch series instead of forking the boot chain, HAL and UI.
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# ADR-0001: Pinned upstream plus reviewable patch series

Status: accepted. Date: 2026-10-17; documented during handoff on 2026-10-18.

## Context

Both Safe 3 revisions need the existing boot chain, HAL, protected norcow,
Optiga, MicroPython and Rust two-button UI. Forking or copying the whole stack
would hide security updates and duplicate large bodies of code.

## Decision

Pin the unmodified upstream release `core/v2.12.5` as a Git submodule. Keep
integration changes as ordered `git format-patch` files in `patches/series`.
Own application and native sources in the superproject and link them into the
build via the patch series. Never record the locally patched commit as the
superproject's upstream base merely because a build used it.

## Consequences

Every upstream modification has an independently reviewable rationale and a
reproducible base. Changes in upstream APIs, storage and linker layouts require
both-model builds and renewed acceptance. The preparation helper checks out
`feuristic/patched` inside the submodule; it is suitable for deliberately
prepared build environments, not automatic execution under a no-branch-change
policy. See [patch maintenance](../developer/patches.md).

Upstream components retain their licenses; the project code is GPL-3.0-only.
The third-party firmware requires irreversible bootloader unlock and does not
inherit manufacturer attestation or release signing. See
[installation](../user/install.md) and [release policy](../developer/release.md).
