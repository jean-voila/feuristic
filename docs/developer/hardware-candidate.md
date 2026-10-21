<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Hardware test candidates

T2B1 and T3B1 development images must come from the same identified clean source
commit, with full CI and reproducibility checks. A candidate bundle associates
each `.bin` with SHA-256, SBOM and provenance naming the source, CI run and
executed software checks. Use the selected candidate or release bundle, not
unrelated older images in `dist/`.

1. Identify T2B1/T3B1 precisely and read [installation and its irreversible
   effects](../user/install.md).
2. Verify candidate SHA-256 before installing. Images use public upstream
   development signing keys and retain the mandatory unsafe warning; these
   are not private distribution signatures.
3. Execute [R01–R16](../acceptance/README.md) on both revisions, recording model,
   image hash, OS and evidence. Include MSC copies, both QR profiles,
   cross-revision restore and power interruptions.

32-bit host probes and emulators provide software evidence. They do not verify
physical USB, OLED/camera readability or real MCU peak RAM. The initial partial
T2B1 campaign does not complete the acceptance procedures. Stable publication
requires the [release checklist](../release-checklist.md).
