---
title: Release checklist
description: Source, build, verification and distribution gates checked before each feuristic release for Trezor Safe 3 T2B1 and T3B1.
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Release checklist

Classification: **public 0.x release, not hardware qualified; real-hardware
R01–R16 results remain NON EXÉCUTÉ until evidence is recorded**. Unchecked items are explicit
release gates, not instructions to remove requirements. A stable release needs
every applicable item below and the complete two-model acceptance matrix.

## Source and build

- [ ] Clean source commit/version and complete corresponding source archived.
- [ ] Pinned upstream base, nested submodules, lockfiles and patch series reviewed.
- [ ] Both model builds pass in the reference Nix environment; flash/RAM maps retained.
- [ ] No debuglink/debug handlers or secret logs in any USB mode of final binaries.
- [ ] Upstream development signing replaced by a reviewed private vendor identity for stable distribution; mandatory unsafe boot warning preserved.
- [ ] Dedicated USB PID allocation and real host-driver registration documented; 1209:0001 remains a test identity until then.

## Verification

- [ ] Lint, SPDX, MicroPython compatibility, host coverage, C ASan/UBSan and ARM cross checks pass.
- [ ] Parser fuzz campaign reviewed; no unresolved crash or security defect.
- [ ] Both model emulators and standard GnuPG/OpenSC interoperability actually execute without hidden skips.
- [ ] Reproducibility: two clean firmware hashes match for each model, with logs; independent builder result recorded separately.
- [ ] [R01](acceptance/R01.md), [R02](acceptance/R02.md), [R03](acceptance/R03.md), [R04](acceptance/R04.md) pass on both real models.
- [ ] [R05](acceptance/R05.md), [R06](acceptance/R06.md), [R07](acceptance/R07.md), [R08](acceptance/R08.md) pass on both real models and specified OS matrix.
- [ ] [R09](acceptance/R09.md), [R10](acceptance/R10.md), [R11](acceptance/R11.md), [R12](acceptance/R12.md) pass with standard clients, physical USB and recorded power interruptions.
- [ ] [R13](acceptance/R13.md) real OLED/camera readability passes both profiles/models; every backup frame is recoverable.
- [ ] [R14](acceptance/R14.md) all categories restore T2B1→T3B1 and T3B1→T2B1, with use verified.
- [ ] [R15](acceptance/R15.md) consent/PIN/timeout/wipe/cleanup evidence reviewed with runtime limits stated.
- [ ] [R16](acceptance/R16.md) source, SBOM, licenses and provenance reviewed; acceptance owner signs results.

## Distribution

- [ ] Matching binaries, SHA256 sidecars and aggregate manifest for both models verified.
- [ ] SPDX SBOM covers actual linked components and firmware hashes; dependency licenses retained alongside LICENSE/NOTICE.
- [ ] Source archive includes required submodule contents or exact obtainable revisions and build scripts sufficient to reproduce.
- [ ] Provenance binds source, toolchain, test evidence and binary hashes; verification key and signing process documented.
- [ ] Installation states irreversible bootloader/attestation effects and exact model selection.
- [ ] Guides FR/EN describe actual menus, shared storage, QR limitations, defaults and recovery consequences.
- [ ] Threat model/security history/release notes reflect actual remaining issues and all test skips.
- [ ] Tag equals source VERSION; release workflow artifacts reviewed as a draft before any deliberate publication.

The [acceptance register](acceptance/README.md) and
[release procedure](developer/release.md) define the required evidence. A
candidate can be distributed privately for these tests with unmet hardware
gates clearly stated, and 0.x releases may be published with those gates listed;
neither may be labelled stable (1.0) or hardware qualified.
