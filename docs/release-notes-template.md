<!-- SPDX-License-Identifier: GPL-3.0-only -->
## feuristic: a security key for your Trezor Safe 3

Open-source firmware that turns a **Trezor Safe 3 (T2B1 or T3B1)** into a USB
security key. These are optimized release builds without debuglink, verified
against three reproducible Nix builds per model.

- **Passkeys you can back up.** Unlike a YubiKey, you can save your passkeys in
  an encrypted QR backup and restore them onto a Safe 3 running feuristic.
- **See what you approve.** The screen names the site before you confirm.
- **2FA codes on the device.** TOTP/HOTP accounts imported from a QR image.
- **SSH, Git and email.** OpenSSH `ed25519-sk` keys, OpenPGP card for GnuPG,
  PIV, AES-256-GCM. Menus in English and French.

### Which file do I need?

Run `trezorctl get-features` and read the internal model:

| Internal model | Download |
|---|---|
| **T2B1** | `feuristic-<version>-T2B1-<commit>.bin` |
| **T3B1** | `feuristic-<version>-T3B1-<commit>.bin` |

Verify `SHA256SUMS`, then follow the
[installation guide](https://jean-voila.github.io/feuristic/user/install/).

### Before you install

- Installing **erases the wallet**. Back up your recovery seed first.
- The bootloader unlock is **one-time and irreversible**. It removes Trezor's
  genuine-device attestation, and the standard `UNSAFE, DO NOT USE!` boot
  warning appears.
- This independent project is not made or signed by Trezor Company / SatoshiLabs.
- Core features passed a [physical T2B1/macOS campaign](https://jean-voila.github.io/feuristic/acceptance/campaign-2026-10-21-T2B1-macos/).
  T3B1 hardware, Windows/Linux and camera restores are still being tested.
  Keep a second way to sign in to important accounts.

### Release contents

Both images, SHA-256 sidecars, `SHA256SUMS`, an SPDX SBOM, `PROVENANCE.json`
and the corresponding source archive with dependency licenses. The images use
upstream's public development signing keys and the provisional USB identity
1209:0001. See the [changelog](https://github.com/jean-voila/feuristic/blob/main/CHANGELOG.md)
for changes and the [security policy](https://github.com/jean-voila/feuristic/security/policy)
for private vulnerability reporting.
