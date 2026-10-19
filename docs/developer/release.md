<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Candidate and release procedure

**Current classification: development candidate, hardware acceptance not
executed.** No stable release is permitted until [R01–R16](../acceptance/README.md)
pass for both T2B1 and T3B1, including every specified OS combination. An
unexecuted test, a skip and a model-only proof are not a pass.

## Build and provenance

Use a recorded clean commit, the pinned upstream base, exported patch hashes,
`uv.lock`, upstream lockfiles and CI's Nix environment. Preserve build logs,
ELF/map and flash/RAM reports, tool versions, OS/architecture, CI run URL and
all test summaries. Tag/version changes and publishing are deliberate maintainer
actions; this document does not authorize a tag, push or public upload.

```sh
tools/ci/nix-build.sh firmware t2b1
tools/ci/collect-firmware.sh T2B1
tools/ci/nix-build.sh firmware t3b1
tools/ci/collect-firmware.sh T3B1
python3 tools/sbom.py --output dist/feuristic.spdx.json --firmware dist/*.bin
(cd dist && sha256sum *.bin *.spdx.json > SHA256SUMS)
```

On macOS `shasum -a 256` replaces `sha256sum`. The SBOM generator emits SPDX
2.3 JSON with component revisions/patch names and optional firmware hashes.
Its timestamp and random namespace mean regenerated SBOM JSON is not expected
to be byte-identical; firmware reproducibility is a separate check. Review
component coverage against the actual linked image and retain original
licenses. `NOASSERTION` is not proof of a completed license review.

On the reference Linux/Nix environment:

```sh
tools/ci/reproducible.sh T2B1
tools/ci/reproducible.sh T3B1
```

Each helper removes `core/build-xtask`, builds twice and compares SHA-256.
Do not run it against another build using that directory. Retain both logs and
hashes; obtain an independent builder's matching hash before claiming broader
reproducibility. A script's existence is not a successful run.

## Signing and vendor identity

`make firmware` disables debuglink and uses optimized Python, but upstream
`xtask` defaults to non-production development signing (`postbuild.rs`,
`cargo.rs`). The public development keys and unsafe vendor headers are useful
for disposable hardware testing. They provide **no private release-signing
identity**. Do not describe these binaries as manufacturer signed or as a
private vendor release.

Before a stable distribution, maintainers must adopt and review a private
vendor-signing key procedure, generated outside source control with offline
protection, recovery/rotation rules and a published verification key. Review
both model-specific vendor headers, sign the exact candidate images using the
upstream `headertool` mechanisms, verify them independently and bind hashes to
the published source/provenance. A private project key never turns into a
SatoshiLabs signature: preserve the mandatory unsafe boot warning and do not
attempt to bypass bootloader trust flags. Never ship development private keys
as a secret or commit actual private signing material.

The USB identity is currently **1209:0001, pid.codes test PID**, not an assigned
project identity. Dedicated PID allocation and host-driver registration remain
stable-release blockers. Do not invent an assignment, reuse Trezor's PID or
claim universal libccid binding before physical testing.

## Distribution gates

Use [the release checklist](../release-checklist.md). Include binaries for both
models, per-file and aggregate SHA-256, SPDX SBOM, complete corresponding
source with required submodule revisions and patches, build instructions,
[LICENSE](../../LICENSE), [NOTICE](../../NOTICE), dependency licenses,
security policy, release notes and signed/protected provenance.

The tag workflow `.github/workflows/release.yml` checks that `v<VERSION>`
matches `src/feuristic/version.py`, builds both models, generates the SBOM and
creates a **draft pre-release**. It does not run every acceptance test and is
not evidence that all CI jobs succeeded for the tag. Keep it draft until the
checks and artifacts have been reviewed. Rewrite
[release notes](../release-notes-template.md) for the actual candidate and list
unexecuted hardware gates explicitly. Public promotion is a separate action.

## Debug exclusion and security review

Verify the final artifacts have no debuglink interface in all three USB modes,
no debug-only protocol handlers and no logging of secrets. Emulator storage,
20 MiB heap settings and debug input injection must not be used as release
assurances. Review [threat model](../threat-model.md),
[security history](../security-history.md), backup recovery limits, default
application PINs, all parser fuzz findings and real peak MCU RAM evidence.
