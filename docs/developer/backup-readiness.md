<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Backup readiness audit — R13 / R14

Audit of the working tree on 19 October 2026. Physical acceptance remains
**not executed**: [R13](../acceptance/R13.md) requires real OLED/camera tests;
[R14](../acceptance/R14.md) requires both physical transfer directions and
cryptographic use of the restored identities.

## Delivered software contracts

| Contract | Implementation and evidence |
|---|---|
| Local export only | `ui/app_backup.py` selects one identity or a full export, displays the recovery warning, checks double passphrase entry and reauthenticates the device PIN before derivation. No QR payload is returned to a USB caller. |
| Exact versioned bytes | `apps/backup/envelope.py`: canonical CBOR, PBKDF2-HMAC-SHA256 with 600,000 iterations, random 16-byte salt, AES-256-GCM with fresh 12-byte nonce and authenticated header. The bytes contain no hardware revision selector or device-derived wrapping requirement. |
| Honest export state | `ExportSession.build()` constructs an envelope and invokes `on_exported()` before returning its frames. Failure to update export state returns no QR. This records production of an export; it does not prove that photographs were taken. |
| Readability profiles | Large modules: QR version ≤3, at most 61 alphanumeric characters and 22 envelope bytes per frame. Dense: version ≤9, at most 262 characters and 156 envelope bytes per frame. Both need physical camera acceptance. |
| QR sequence controls | Identity/frame counts, previous/next, finish after viewing all frames, long-left cancellation and a real 60-second display timeout. The full export builds and displays one identity at a time. |
| Long OTP URI | A standard `otpauth://` that exceeds the renderer limit takes the encrypted fragmented-backup path, including its own warning, passphrase and PIN checks. |
| Complete identity before mutation | The collector accepts arbitrary frame order and identical duplicates. A missing frame cannot produce a restorable envelope. `StreamingRestore` authenticates and validates every item of the current envelope before writing any current item. |
| Bounded device receiver | One active identity, at most 999 frames and 12 KiB ciphertext, using `PackedReassembler`. All maximal native identity exports fit this budget in both profiles. The generic format/parser retains its larger documented bounds. |
| Explicit input backpressure | Decoder buffers are wiped before passphrase/KDF/restore; the bitmap and shared QR reservation stay allocated until close to prevent fragmentation. A pause starts only at an image and BOT command boundary. New writes fail immediately with NOT READY 04/07, full unaccepted residue and an OUT halt. Reads, sense and eject still work. The host retries a refused copy after the next-identity invitation. |
| Streaming full restore | One completed identity is consumed at a time; prior confirmed identities remain restored if a later identity is missing or damaged. A bounded key cache avoids repeated derivation for the same salt. Backup IDs, envelope hashes and full-set sequence bits reject conflicts and identify incomplete sets. Done requests explicit completion, with a warning for missing data. |
| Cleanup and mode recovery | Mutable passphrase/key/cache and native image buffers are wiped. Session construction cleans partial allocations synchronously; an old finalizer cannot wipe a new context. Closing the actual import workflow closes its native owner and schedules independent recovery to NORMAL, including during GeneratorExit. |

The guarantees above do not assert zeroization of every immutable `bytes`/`str`
copy, decrypted object or freed Rust input buffer. Those runtime limits remain
part of the [R15 inspection](../acceptance/R15.md).

## Automated evidence

The software evidence uses host tests and emulator/debug builds. It does not
exercise camera focus, physical USB host behavior or either physical device.

- [Device backup workflows](../../tests/functional/test_menus_backup.py):
  independent CBOR/PBKDF2/AES-GCM input encoded as PNG QR images and delivered
  over the real MSC/BOT emulator interface; reverse order, duplicates, wrong
  phrase then retry, refusal/cancellation, all displayed export frames
  independently reassembled/decrypted, navigation and the actual 60-second
  timeout. A two-identity full restore verifies same-volume continuation,
  one phrase, an early-finish warning and final application entries.
- [Native importer lifecycle](../../tests/upy/test_import_native.py):
  decoder-page release, retained-reservation cleanup at close,
  failed writes with exact SCSI sense/residue, resume, allocation failures at
  two heap pressures followed by successful retry, exclusive native ownership,
  the unchanged 4096-byte README limit and closure/reopening of the real import
  entry point with NORMAL recovery.
- [UI on MicroPython](../../tests/upy/test_backup_ui.py): passphrase policy,
  confirmation/refusal, mutable-buffer cleanup, sequence bounds, long-OTP
  fallback, 128-byte native text layout and progression that preserves the
  calling workflow.
- [Streaming core](../../tests/host/backup/test_streaming_restore.py) and
  [collector](../../tests/host/importer/test_session.py): missing fragments,
  conflicting IDs/sequence numbers, validation before writes, later corruption
  and exact cumulative receipt counters with bounded recent examples.
- [Maximum exports](../../tests/host/backup/test_native_export_bounds.py):
  real providers with maximal metadata/certificates, RSA private material and
  associated largeBlobs, through both frame profiles and the compact device
  collector. This is a transport/schema bound; actual MCU heap headroom has
  separate probe/build evidence.
- [Five-provider native bridge](../../tests/upy/test_backup_providers.py): the
  same script passes on T3B1 and T2B1 emulator builds. It exports all five real
  providers, reassembles their QR frames, wipes encrypted norcow, creates a
  different master secret, restores through lazy providers in IMPORT and
  returns through the real NORMAL mode reload. Subsequent operations verify
  HOTP continuation, all three OpenPGP 25519 roles and signature counter,
  PIV RSA-2048/certificate, old AES ciphertext plus new nonce allocation, and
  resident FIDO signatures, backup flags/counter, both hmac-secret UV domains
  and encrypted largeBlob content. This is a native runtime portability
  bridge, not a physical cross-device transfer or MCU RAM proof.
- [FIDO](../../tests/host/fido2/test_reset_local_provider.py),
  [OTP](../../tests/host/otp/test_provider.py),
  [OpenPGP](../../tests/host/card/openpgp/test_provider.py),
  [PIV](../../tests/host/card/piv/test_provider.py) and
  [AES](../../tests/host/card/aes/test_provider.py) exercise provider export and
  restore. Fresh-device tests use different master secrets and verify retained
  credential IDs, signatures/blob keys, OTP counters or old AES ciphertexts as
  applicable. These are software portability proofs, not physical R14 results.

Representative local checks:

```sh
uv run --no-sync pytest -q tests/host/backup tests/host/importer
uv run --no-sync pytest -q tests/functional/test_menus_backup.py
uv run --no-sync pytest -q tests/functional/test_upy.py -k 'backup_ui or import_native'
TREZOR_UDP_PORT=28000 uv run --no-sync pytest -q tests/functional/test_upy.py -k backup_providers
ctest --test-dir build/c -R 'fmsc_test_(scsi|bot)' --output-on-failure
```

## Remaining physical acceptance

1. Photograph and independently decode every frame on both physical displays,
   with multiple ordinary phones and both profiles. Test long OTP fallback and
   a large RSA/largeBlob identity, including a missing/corrupted frame.
2. Exercise refused-copy recovery in Finder, Windows Explorer and Linux, keeping
   the volume mounted between identities. A failed copy must be visibly failed
   and accepted after retry; no image can be silently discarded as successful.
3. Transfer every category T2B1→T3B1 and T3B1→T2B1, then verify actual signatures,
   OTP, hmac-secret/largeBlobs, certificates and AES ciphertexts. Record local
   settings that intentionally remain on the destination.
4. Record MCU memory headroom and controlled power interruptions while receiving,
   authenticating and committing each identity. An emulator with a 20 MiB heap
   does not provide that evidence.

Keep these results in the [acceptance register](../acceptance/README.md) with
artifact hashes. Stable publication remains gated by the complete R01–R16
matrix in the [release checklist](../release-checklist.md).
