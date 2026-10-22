<!-- SPDX-License-Identifier: GPL-3.0-only -->
## feuristic development candidate

Custom firmware for **Trezor Safe 3 T2B1 and T3B1**. Independent project,
not made or signed by Trezor Company / SatoshiLabs. Installing requires an
irreversible bootloader unlock and erases the wallet and manufacturer attestation.

- FIDO2 passkeys, OpenPGP, PIV, TOTP/HOTP, AES-GCM and encrypted QR backups.
- Visible FEURISTIC welcome screen and corrected TOTP countdown.
- Initial physical T2B1/macOS campaign: FIDO, OpenPGP, PIV, AES, OTP and persistence.
- Full R01–R16, T3B1 hardware and remaining host combinations are **not qualified**.
- Public development signing keys and provisional USB identity remain in use.

Download the image matching the internal model, verify `SHA256SUMS`, then follow
[installation](https://jean-voila.github.io/feuristic/user/install/).
Do not use production identities. The bootloader warning remains.

This workflow runs the complete CI suite and compares three Nix builds per
model before creating the draft. `PROVENANCE.json` records source and build
references. The source archive includes patched upstream sources and dependency
licenses; the SPDX SBOM records included components. Review the linked workflow
run for the exact automated results and the
[hardware report](https://jean-voila.github.io/feuristic/acceptance/campaign-2026-10-21-T2B1-macos/)
for the physical test scope.
