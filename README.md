# feuristic

**An open-source security-key firmware for the Trezor Safe 3.**
FIDO2 passkeys, OpenPGP card, PIV, TOTP/HOTP, AES-256-GCM and a hardware
RNG, configured entirely on the device with its two buttons. No companion
app, no cloud, no account, no cryptocurrency.

> **Status: work in progress (0.1.0-dev).** Protocol implementations have
> host and emulator tests; several device management menus and release
> documents are still incomplete. See the verified
> [development handoff](docs/developer/handoff.md). It has **not yet been
> validated on real hardware**. Hardware acceptance tests R01–R16 must pass
> on both revisions before a stable release.

> **Third-party firmware.** feuristic is not made, endorsed or signed by
> SatoshiLabs / Trezor Company. Installing it requires an irreversible
> bootloader unlock and shows an "UNSAFE, DO NOT USE!" vendor warning at
> every boot (enforced by the official bootloader). Read
> [docs/user/install.md](docs/user/install.md) first.

| | |
|---|---|
| Hardware | Trezor Safe 3 **T2B1** (rev. A, STM32F427) and **T3B1** (rev. B, STM32U585) |
| Licence | GPL-3.0-only (upstream components keep their licences, see [NOTICE](NOTICE)) |
| Based on | [trezor-firmware](https://github.com/trezor/trezor-firmware) `core/v2.12.5` + a reviewed [patch series](patches/) |

## Features

| | Standard | Host software |
|---|---|---|
| Passkeys / security key | FIDO2, WebAuthn, **CTAP 2.1** (clientPIN, credentialManagement, credProtect, largeBlobs, hmac-secret), U2F | browsers, Windows/macOS/Linux, libfido2, OpenSSH `-sk` keys |
| One-time passwords | TOTP (RFC 6238), HOTP (RFC 4226), `otpauth://` | none — codes shown on the device |
| OpenPGP | OpenPGP Card 3.4 (Ed25519 / X25519, RSA-2048) | GnuPG (no `trezor-agent`) |
| PIV / certificates | NIST SP 800-73-4 (P-256, RSA-2048) | OpenSC, PKCS#11, TLS client auth |
| Encryption | AES-256-GCM over ISO 7816-8 (device-generated nonces) | any PC/SC client ([protocol](docs/protocols/aes-gcm-iso7816-v1.md)) |
| Randomness | ISO 7816-4 `GET CHALLENGE`, SP 800-90B health tests | any PC/SC client |
| Backup | encrypted QR sequences shown on the screen; restore from photos | none (copy images to a temporary USB drive) |

USB modes are exclusive: **normal** (FIDO HID + CCID smart-card reader),
temporary **time sync** (CDC-ACM serial, `TIME 1 <unix>`), temporary
**QR import** (FAT12 mass storage). See [docs/architecture.md](docs/architecture.md).

## Repository layout

```
upstream/trezor-firmware   pinned upstream (git submodule, unmodified)
patches/                   feuristic patch series applied to upstream
firmware/                  feuristic kernel (USB classes) and MicroPython C modules
lib/                       portable C libraries: QR decoder, PNG/JPEG, FAT12/SCSI, RSA
src/feuristic/             the application (MicroPython, frozen into the firmware)
tests/                     host, C, fuzz, MicroPython and emulator functional tests
docs/                      architecture, protocols, user and developer guides, ADRs
```

## Quick start (developers)

```bash
make setup                 # submodules, patch series, Python environment
make test-host             # ~2,000 CPython unit tests
make test-c                # C libraries with ASan/UBSan
make emu && make test-functional   # emulator + end-to-end tests
make firmware MODEL=T2B1   # or T3B1 → dist/feuristic-<version>-<model>-<rev>.bin
```

Full instructions: [docs/developer/building.md](docs/developer/building.md).
Testing strategy: [docs/developer/testing.md](docs/developer/testing.md).

## Documentation

* Users: [installation](docs/user/install.md) · [guide (EN)](docs/user/guide-en.md) · [guide (FR)](docs/user/guide-fr.md)
* Security: [threat model](docs/threat-model.md) · [security policy](SECURITY.md)
* Protocols: [FIDO2](docs/protocols/fido2.md) · [OpenPGP](docs/protocols/openpgp.md) · [PIV](docs/protocols/piv.md) · [AES-GCM profile](docs/protocols/aes-gcm-iso7816-v1.md) · [time sync](docs/protocols/time-sync-v1.md) · [backup format](docs/protocols/backup-format-v1.md) · [CCID](docs/protocols/ccid.md)
* Design decisions: [docs/adr](docs/adr/)

## En bref (français)

feuristic transforme un Trezor Safe 3 en clé de sécurité USB libre : passkeys
FIDO2/CTAP 2.1, carte OpenPGP, PIV, codes TOTP/HOTP, chiffrement AES-256-GCM
et générateur aléatoire matériel. Tout se configure sur l'appareil, avec ses
deux boutons, en français ou en anglais. Aucune application compagnon,
aucun cloud, aucune fonction de cryptomonnaie. **Version de développement :
non encore validée sur matériel réel.** Guide utilisateur :
[docs/user/guide-fr.md](docs/user/guide-fr.md).
