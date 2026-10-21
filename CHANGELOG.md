# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- First implementation of the feuristic firmware for the Trezor Safe 3
  (T2B1 and T3B1), based on trezor-firmware `core/v2.12.5`.
- FIDO2 / CTAP 2.1 security key (clientPIN v1/v2, credentialManagement,
  credProtect, largeBlobs, hmac-secret, U2F), 100 discoverable credentials.
- OpenPGP Card 3.4 (Ed25519/X25519, RSA-2048), PIV (P-256, RSA-2048),
  feuristic AES-256-GCM ISO 7816-8 profile, GET CHALLENGE with SP 800-90B
  health tests, behind a USB CCID reader.
- TOTP/HOTP accounts (32), `otpauth://` import/export.
- Exclusive USB modes: normal (HID + CCID), time sync (CDC-ACM),
  QR import (FAT12 mass storage, decode-on-receive).
- Encrypted QR backup/restore (canonical CBOR, PBKDF2-HMAC-SHA256 600k,
  AES-256-GCM, Base45 frames).
- Two-button menus in English and French; 5-minute auto-lock.
- Visible FEURISTIC welcome screen before PIN entry and corrected TOTP countdown.
- MkDocs documentation, editable Sketch artwork and verified release bundles.
- Test suites: CPython unit tests, C unit tests with sanitizers, libFuzzer
  targets, MicroPython tests on the emulator, end-to-end functional tests.

### Known limitations
- Full hardware acceptance R01–R16 remains pending on both revisions. An initial
  physical T2B1/macOS campaign passed core FIDO, OpenPGP, PIV, AES and OTP
  workflows, persistence checks and two UI fixes; see the hardware report.
- USB VID/PID is the pid.codes test PID until a dedicated one is assigned.
