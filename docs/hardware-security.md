---
title: Hardware security on Trezor Safe 3
description: How feuristic uses the Optiga Trust M secure element of the Trezor Safe 3, which hardware protections remain after the bootloader unlock, what is deliberately not done and which residual risks remain.
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Hardware security on Trezor Safe 3

This page records what the Safe 3 hardware actually protects in feuristic. It
is based on the pinned upstream sources (`core/v2.12.5`). Every statement
marked **source** was checked in that code. **Hardware pending** marks what
still has to be observed on a physical device. The emulator has no secure
element: its Optiga driver is a stub, so no emulator test exercises the chip.

## Summary

| Protection | Status in feuristic | Evidence |
|---|---|---|
| Protected storage encrypted under a key that needs the PIN **and** secrets inside the Optiga | Active for every feuristic secret (master secret, passkeys, OTP, OpenPGP, PIV, AES keys, FIDO PIN state) | Source; T2B1 unlock/persistence campaign |
| PIN guess limits enforced by Optiga counters, wipe after 16 wrong PINs | Active (upstream storage) | Source; R15 hardware pending |
| Key generation from MCU TRNG XOR Optiga TRNG | Active for all long-term keys, the master secret, salts and backup IDs | Source; `tests/host/test_hardware_invariants.py` |
| Device halts if the Optiga fails during PIN checks or strong RNG | Active (upstream `ensure`) | Source |
| Manufacturer attestation keys (`0xE0F0`, `0xE0F2`) | **Lost** after the bootloader unlock; FIDO uses self attestation | Source |
| Identity keys generated and used inside the Optiga | **Not used**, by decision (see below) | — |
| Irreversible Optiga configuration by feuristic | **Never** (no `--production` build, no direct Optiga calls) | Guard tests |

## What the Optiga Trust M holds

Upstream configures these objects on a Safe 3 (one stretched-PIN slot,
`STRETCHED_PIN_COUNT = 1`, 16 PIN attempts):

| Object | Role | Access condition (source) | After bootloader unlock |
|---|---|---|---|
| `0xE0F0` device key, `0xE0E1` certificate | Trezor authenticity proof | key execute: shielded channel with pairing secret `0xE140` | unusable: the MCU copy of the pairing secret is erased |
| `0xE0F2` FIDO key, `0xE0E2` certificate | Trezor FIDO attestation | same | unusable |
| `0xF1D0` PIN secret | counter-protected secret mixed into the storage key | read: proof of the stretched PIN | in use by feuristic through upstream storage |
| `0xF1D4` stretched PIN, `0xF1D8` HMAC key | PIN verification and HMAC stretching | execute limited by counters `0xE120`, `0xE122` | in use |
| `0xE200` AES key, `0xE0F3` ECDH key | CMAC and ECDH PIN stretching | execute limited by lifetime counter `0xE121` | in use |
| `0xE121` lifetime counter | 600 000 stretching operations over the chip's life | change: never | in use, shared with past official firmware use |

The storage key is derived from the PIN, a random salt in flash and the
outputs of the Optiga stretching steps. A copy of the flash is not enough to
test PIN guesses offline: each guess needs the Optiga, and its counters cap the
number of guesses.

**Lifetime limit.** Each PIN verification uses four stretching operations, so
the Optiga allows about **150 000 PIN verifications** over the life of the
device. That includes unlocks after the 5-minute auto-lock and PIN
re-entries before exports and deletions. At 30 verifications a day, that is
more than 13 years. Past use under official firmware counts against the same
budget.

## Why identity keys are not stored in the Optiga

The chip can generate and use non-extractable ECC P-256 and RSA-2048 keys. Its
remaining free objects are one ECC key slot (`0xE0F1`), two RSA slots
(`0xE0FC`, `0xE0FD`), one counter and a few data objects. feuristic does not
put passkeys, OpenPGP, PIV or AES keys there:

1. **They would survive a wipe.** A storage wipe (16 wrong PINs, the device
   menu, the bootloader, a firmware change) erases MCU flash, not the Optiga.
   A key left in the chip would stay usable after the wipe that is supposed to
   destroy it.
2. **Their access rules could be rewritten.** Without locking an object's
   metadata to the operational state, which is irreversible, any code on the
   MCU could later rewrite who may use the key. Locking free objects would be
   an irreversible change that feuristic refuses to make.
3. **The capacity does not fit.** One ECC slot cannot hold 100 passkeys, and
   the Trust M cannot import or unwrap private keys without a manufacturer
   trust anchor that the unlock has made unusable.
4. **The attestation keys are gone.** The only keys with a manufacturer
   certificate need the shielded channel, whose pairing secret is erased
   by the unlock.

The Optiga still protects every key indirectly: all keys live in protected
storage, which cannot be decrypted without the PIN and the chip.

## What feuristic guarantees not to do

`tests/host/test_hardware_invariants.py` fails the build if any of these
change:

- feuristic code (Python, C, patches) calls no Optiga API, including the
  `set_sec_max` throttle;
- no patch touches upstream's secure element, secret sector, PIN storage,
  bootloader, boardloader, prodtest, model headers or firmware version files.
  The firmware header keeps upstream's version and monotonic counter, so
  official firmware can still be reinstalled and no OTP counter is burnt;
- no build entry point passes `--production`, which would lock Optiga
  metadata permanently;
- the release target never enables debuglink.

## Residual risks

**Firmware replacement keeps your data.** The bootloader keeps storage when
the new image has the same vendor header and a version at least equal to the
installed image's fix version (source:
`wf_firmware_update.c`, `detect_installation`). Every image under the
public `UNSAFE, DO NOT USE!` header shares that vendor header and its signing
keys are public. Someone with physical access can therefore install a
modified firmware without erasing feuristic's storage. That firmware still
needs your PIN, and the Optiga counters bound its guesses, but it can record
the PIN the next time you type it. Treat a device that left your control as
untrusted, and wipe it from the bootloader before using it again.

**The Optiga lock state depends on the device history.** Official production
firmware locks the PIN objects the first time it starts with empty storage
(source: `init_wiped_storage` → `optiga_pin_init`). feuristic is a
development-mode build and never locks them. On a Safe 3 that ran official
firmware before the unlock, which is the usual case, the objects are locked.
On a device unlocked before ever running official firmware they stay
unlocked; how far the Optiga's change access conditions then still protect
them against malicious firmware is **hardware pending**. To be sure, start
the official firmware once before unlocking.

**Cryptography runs on the MCU.** Signatures, decryption and HMAC run in the
STM32 with constant-time code. MicroPython does not guarantee that every copy
of a secret is erased from RAM after lock (see the
[threat model](threat-model.md)).

**No manufacturer attestation.** Services that only accept attested
authenticators will reject feuristic.

## Verification status

| Property | Emulator | Physical device |
|---|---|---|
| Storage unlock, persistence, power cut | Functional tests (both models) | T2B1 campaign 2026-10-21; T3B1 pending |
| Optiga PIN stretching active, halts on chip failure | Not observable (stub) | Pending (R15) |
| 16-attempt wipe on real Optiga counters | Not observable | Pending (R15) |
| Lock state (LcsO) of the Optiga PIN objects | Not observable | Pending: read with a read-only tool; never run prodtest write or lock commands |
| Strong RNG mixes the Optiga | Code guard only | Pending (R11 statistics) |
