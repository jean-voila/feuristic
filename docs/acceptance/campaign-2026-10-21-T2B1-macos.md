<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# First physical campaign — T2B1 / macOS, 21 October 2026 UTC

Partial campaign on a real Safe 3 **T2B1**, bootloader **2.1.16**, macOS 27.0.1
ARM64. The user performs physical confirmations; clients use native Mac HID,
PC/SC and CDC, without debuglink or a virtual reader. All identities are
disposable. Private commands, scripts and original evidence remain locally in
`build/hardware-20261021-T2B1/`; device identifiers and the GnuPG keyring are not
published.

The initial official firmware was 2.12.5, with initialised storage and locked
bootloader. After explicit backup/erase authorisation, unlocking succeeded;
`bootloader_locked=False` and `initialized=False` were read before the first flash.

## Images used

| Source | Origin | T2B1 file SHA-256 |
|---|---|---|
| `148390f5c364` | Nix candidate from CI 39560119956 | `d8a6e37e79ce7ab2e1e9c1a613be29f121dc814088a460f05c52ccca0450fe22` |
| `f56f02ef4018` | Local macOS build, TOTP fix | `a812c1a7224b6ce19d62ddc459f3d839aca7fab26c224b68ff6a489807b1ab01` |
| `b97aa7cb9ae2` | Local macOS build, visible locked welcome | `e4da82768739d41f89a14b5e8b95abe320c25d32e7950ea74779afee41fb1860` |

Each model/signature passed standard pinned trezorlib validation. Local builds
are not presented as reproducible Nix builds. The third-party warning and user
acknowledgement remain enabled.

## Physical observations

| Test actually performed | Result |
|---|---|
| First boot, French and PIN creation | PASS, confirmed by the user |
| Normal USB | PASS: HID class 3 + CCID class 11, no debuglink |
| HID/CTAP | PASS: INIT, 100-byte PING, FIDO 2.1 GetInfo; advertised extensions are not their complete acceptance |
| Resident ES256 passkey | PASS: creation, discoverable assertion and signature verified on Mac |
| Physical FIDO refusal | PASS: `OPERATION_DENIED` |
| Actual power cut, same passkey | PASS: valid signature, counter 2 → 33 |
| Native CCID | PASS: OpenPGP/PIV/AES SELECT and twelve public APDUs before/after import |
| GET CHALLENGE | PASS: 1 and 32 bytes; 33 and absent length rejected; no entropy-measurement claim |
| OpenPGP with GnuPG 2.5.22 | PASS: card 3.4, Ed25519/X25519 generation, public certificate export, verified signature, decrypted message identical to input |
| PIV | PASS: AES-192 management authentication, P-256 generation in 9A and independently verified signature |
| AES-GCM | PASS: 0, 1, 31, 127 and 3584-byte round trips, up to 256-byte AAD; corrupted tags/AAD reject without plaintext, 3585-byte input and host nonce reject; five distinct nonces |
| PNG and baseline JPEG import | PASS: native macOS FAT12 mount, MSC only, copy/fsync, local confirmation, ejection and HID/CCID return |
| RFC 4226 HOTP, initial counter 0 | PASS: on-device `755224` |
| Native CDC | PASS: classes 2/10 only, nine HELLO/framing/error cases, accepted time and return to normal |
| Clock retained during JPEG import | PASS: on-device TOTP `172068`, matching independent computation for UTC 21:38:00 window |
| TOTP countdown correction | PASS on `f56f02ef4018`, user confirmed |
| Visible welcome after `b97aa7cb9ae2` | PASS: FEURISTIC/French instruction, button opens PIN, original test PIN works |
| Identity persistence after updates | PASS: same passkey (counter 65), same PIV/OpenPGP signatures and AES key; HOTP counter 1 gives `287082` |
| AES nonces after cut/update | PASS: indices 0–4 before, 256–260 afterward; ten distinct observed nonces |
| Final state | PASS: clock resynchronised, HID + CCID only, functional FIDO GetInfo/PING and CCID APDUs |

An initial GnuPG signature returned “Conditions of use not satisfied” despite
reported confirmation. The 30-second timeout is a possible, unproven cause.
A retry explicitly confirmed on the final page produced a verified signature;
this discrepancy remains recorded.

## Fixes from testing

- `f56f02ef4018`: replace unformatted TOTP translations with
  `t("otp.remaining", remaining)`; English/French checks across two refreshes.
  Document Exit menu, Init connection and reconnection after unlocking.
- `b97aa7cb9ae2`: replace the blank locked screen with **FEURISTIC** and an
  English/French instruction. One button opens PIN entry without unlocking
  storage. The input wrapper remains local to its dialog to release its class.

Software validation of the last fix: **340 targeted host tests**, **9 T2B1
boot/lock tests** (FR/EN, left/right/both, reboot, incorrect then correct PIN),
lint and MicroPython compatibility. Local functional tests use normal emulator
mode; a frozen-only attempt was inapplicable to that local build because it
lacked a frozen `main` module.

## Scope

This report completes none of R01–R16 in full. Remaining work includes T3B1,
Windows/Linux, cameras and cross-revision restore, capacity/endurance, cuts
during writes, CTAP extensions, certificates/OpenSC interop, RNG fault injection,
PIN policies and complete consent tests. It is not a stable-release decision.

The image left on the device is **`b97aa7cb9ae2`**, SHA-256
`e4da82768739d41f89a14b5e8b95abe320c25d32e7950ea74779afee41fb1860`.
The two OTP accounts, passkey, OpenPGP identity, PIV 9A key and AES #1 remain
disposable test data. Both reported display defects were fixed and verified
physically.
