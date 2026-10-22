---
title: Security history
description: Security-relevant fixes in feuristic releases, with dates, severity and credit.
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
# Security history

Security-relevant fixes, by release. Report vulnerabilities as described in
[SECURITY.md](../SECURITY.md).

| Release | Date | Issue | Severity | Credit |
|---|---|---|---|---|
| — | — | No security advisories yet (pre-release). | — | — |

## Host tooling dependency — 22 October 2026

The root and patched upstream host lockfiles now pin certifi 2026.10.19, addressing
[GHSA-6q48-6c7w-9gw2](https://github.com/certifi/python-certifi/security/advisories/GHSA-6q48-6c7w-9gw2).
The affected CA bundle belongs to Python host tooling, not the embedded firmware.
The compromised emSign ECC Root CA - G3 is absent from the updated bundle;
an HTTPS request with certificate verification and the documentation build pass.

The upstream patch exempts only certifi from its 30-day package release delay
so the corrected CA bundle can be selected. All other package versions and the
upstream delay remain unchanged. Both frozen environments pass verified HTTPS
checks with the compromised root absent.

Published `v0.1.0-dev` firmware images are unchanged. Their source archive
retains its historical host lockfiles. Use current `main` with the normal
upstream preparation procedure for corrected host tooling and build environments.
The dependency update does not rewrite the original release's build record.

## Development hardening — October 2026

These fixes are in the development candidate; they are not a published
security advisory or evidence of physical acceptance.

- Native Caesar confirmations now require both buttons on the final page.
  Dangerous actions require an uninterrupted hold; releasing either button
  cancels the hold and short attempts cannot accumulate.
- Lock closes and drops protocol pollers as well as operation workers, releasing
  their retained private references. USB mode transitions suspend normal
  transports, and cancellation schedules independent recovery to NORMAL.
- Image-import construction cleans partial allocations, enforces a single native
  owner and prevents an old finalizer from wiping a newer session. Decoder
  pause wipes/frees scratch buffers; new writes fail explicitly until resume.
- Device restoration retains one bounded identity at a time, authenticates and
  validates the complete current envelope before mutation, and records replay
  conflicts with bounded session metadata. Earlier confirmed identities remain
  restored if a later one is incomplete or invalid.
- On 19 October, monotonic application time was extended across MCU tick wraps,
  sampled by an independent heartbeat in all USB/lock modes. Long powered
  sessions no longer move TOTP time backwards or revive expired FIDO tokens,
  reset windows or presence latches. Ambiguous sampling fails closed until reboot.
- Unvalidated/public USB packets no longer refresh the five-minute idle timer.
  Physical UI activity retains its upstream timer hook; host PING/RNG traffic
  cannot keep an unattended device unlocked indefinitely.
- AES encryption now uses a 64-bit device/key/epoch namespace plus a 32-bit
  index. The persisted allocator and backup floor remain 64-bit; epochs change
  before the index wraps. Legacy ciphertexts remain decryptable. Residual
  namespace collision risk is 2⁻⁶⁴ per pair of contexts, with a birthday bound
  across many contexts, rather than the previous 32-bit clone-prefix bound.

Remaining runtime zeroization limits are documented in the
[threat model](threat-model.md); R15 remains unexecuted on hardware.
