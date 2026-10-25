---
title: Firmware architecture
description: "How feuristic is organized on Trezor Safe 3: repository layout, upstream integration, memory budget, USB modes, storage and key domain separation."
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# feuristic — Architecture

> Status: **design reference for v0.x (pre-release)**. This document is the
> contract between the components of the repository. When code and this
> document disagree, one of them is a bug.

feuristic is a third-party, GPL-3.0-only firmware for the Trezor Safe 3
(`T2B1` rev. A — STM32F427 + Optiga Trust M, and `T3B1` rev. B — STM32U585 +
Optiga Trust M). It turns the device into a standards-based USB security key:
FIDO2/CTAP 2.1, OpenPGP Card 3.4, PIV, TOTP/HOTP, AES-256-GCM and a hardware
RNG, all administered from the device screen and its two buttons.

feuristic is **not affiliated with SatoshiLabs / Trezor Company**. It reuses
the open-source Trezor firmware stack (kernel, drivers, storage, MicroPython,
Rust UI) and replaces every cryptocurrency feature.

---

## 1. Repository layout

```
feuristic/
├── upstream/trezor-firmware/   git submodule, pinned to an upstream release tag
├── patches/                    patch series applied on top of upstream (see §3)
│   ├── series                  ordered list of patch files
│   └── NNNN-*.patch
├── firmware/                   feuristic C code compiled *inside* the upstream build
│   ├── kernel/                 privileged code: USB classes (CCID, MSC), USB mode switch
│   └── upymod/                 unprivileged MicroPython C modules (image import, RSA, SHA-1)
├── lib/                        portable, host-testable C libraries (no upstream deps)
│   ├── fqr/                    QR code detector + decoder on a 1-bpp bitmap
│   ├── fimg/                   streaming PNG / baseline-JPEG decoders + binarizer
│   ├── fmsc/                   FAT12 virtual volume, SCSI/BOT engine, import stream tracker
│   └── third_party/            vendored code with its own licence (BearSSL subset, ...)
├── src/feuristic/              MicroPython application package (frozen into the firmware)
├── tests/
│   ├── host/                   CPython unit tests of src/feuristic (pytest, hypothesis)
│   ├── c/                      C unit tests of lib/ (CTest, ASan/UBSan)
│   ├── fuzz/                   libFuzzer targets for lib/ and parsers
│   ├── upy/                    unit tests executed inside the MicroPython emulator
│   └── functional/             end-to-end tests against the emulator (pytest)
├── tools/                      build helpers, host clients (time sync, vpcd bridge, ...)
├── docs/                       user, developer and protocol documentation, ADRs
└── .github/workflows/          CI pipelines
```

## 2. Layered design

```
┌───────────────────────────── unprivileged (coreapp) ─────────────────────────────┐
│  src/feuristic  (MicroPython)                                                     │
│   ui/  ── menus, screens, confirmations (Rust layout_caesar via trezorui_api)      │
│   apps/otp  apps/fido2  apps/card{openpgp,piv,aes}  apps/backup  apps/importer     │
│   core/  (pure logic: cbor, tlv, base45, kdf, store, counters, clock, i18n, policy)│
│   platform/ ── facade: crypto, kv-storage, rng, time, usb  (fw backend | host backend)
│  firmware/upymod  (C): feuristic_import (fimg+fqr+fmsc), feuristic_rsa (BearSSL)   │
├──────────────────────────────── syscalls (SVC) ──────────────────────────────────┤
│  upstream kernel (privileged): storage (norcow + PIN + Optiga), RNG, display, buttons
│  firmware/kernel: USB CCID class, USB MSC (BOT) class, usb_set_mode()             │
└────────────────────────────────────────────────────────────────────────────────────┘
```

Rules:

1. **Hostile input is parsed unprivileged.** Images, QR payloads, APDUs, CTAP
   CBOR and SCSI commands are parsed in the coreapp, never in the kernel. The
   kernel USB classes only move bounded packets.
2. **Pure logic is host-testable.** Everything in `src/feuristic/core` and the
   protocol handlers in `src/feuristic/apps/*` depend only on
   `feuristic.platform` and must run unchanged on CPython (tests) and on the
   device MicroPython (see `docs/developer/micropython-compat.md`).
3. **`lib/` is freestanding C99**, no allocation (caller-provided buffers), no
   upstream headers, `-Wall -Wextra -Werror`, fuzzed.

## 3. Upstream integration

* `upstream/trezor-firmware` is pinned to `core/v2.12.5`.
* `patches/series` is applied with `git am` onto a local branch
  `feuristic/patched` by `tools/upstream.py apply`. This helper resets and
  switches the submodule branch: run only when that preparation is explicitly
  intended, never automatically in a no-branch-change working checkout.
  Patches are regenerated with
  `tools/upstream.py export`. Every patch has a descriptive commit message and
  a `Feuristic-Rationale:` trailer.
* feuristic-owned sources are reached from the upstream tree through relative
  symlinks created by a patch (e.g. `core/src/feuristic -> ../../../../src/feuristic`),
  so there is no copying and no duplicated source of truth.
* Build entry point: the top-level `Makefile` (`make firmware MODEL=T2B1`,
  `make emu`, `make test`, ...). It wraps upstream's `xtask`.

## 4. Hardware and memory budget

| | T2B1 | T3B1 |
|---|---|---|
| MCU | STM32F427 (Cortex-M4F, 168 MHz) | STM32U585 (Cortex-M33, 160 MHz) |
| USB | OTG_HS core in FS mode, EP1–EP5 | OTG_FS, EP1–EP5 |
| Firmware flash | 768 KiB + 896 KiB | 1664 KiB |
| Storage (norcow) | 64 KiB live sector (+1 swap) | 64 KiB live sector (+1 swap) |
| coreapp RAM | ~191 KiB (heap ≈ 120–150 KiB) | ~728 KiB (heap ≈ 500 KiB) |
| Secure element | Optiga Trust M (PIN stretching) | Optiga Trust M (PIN stretching) |

Consequences that shape the design:

* **Storage is 64 KiB of live data.** Records have hard size caps (§6.3) and a
  quota check refuses writes that would endanger compaction. Contractual
  capacity: 100 discoverable credentials + 32 OTP accounts + 4 KiB serialized
  largeBlobs. Other card identities share the remaining sector space; this is
  not a promise that every application maximum also fits simultaneously.
  See [measured storage budget](developer/storage-budget.md).
* **T2B1 cannot hold a 256 KiB image file** in RAM or free flash (only 64 KiB
  of scattered spare flash exists and the bootloader requires the firmware
  area padding to stay erased). Image import therefore decodes the file *while
  it is being written* into a bounded 1-bpp bitmap and only interprets it after
  the transfer is complete and synchronised. See ADR-0003.
* **Optiga after bootloader unlock.** The unlock procedure wipes the Optiga
  pairing secret: the shielded channel and access to the original attestation keys are lost, but
  the PIN-stretching objects remain usable (upstream continues without the
  shielded channel). FIDO attestation is therefore *self attestation*.
  feuristic never drives the Optiga directly and never builds in production
  mode; the object map, the lock state and the reasons for keeping identity
  keys out of the chip are in [hardware security](hardware-security.md).
* **Boot screen.** A firmware not signed by SatoshiLabs runs under the
  "UNSAFE, DO NOT USE!" vendor header: a warning and a click are required
  at every boot. This is enforced by the official bootloader and cannot be
  removed by any third-party firmware.

## 5. USB

### 5.1 Identity

* VID/PID: `0x1209:0x0001` (pid.codes *test* PID) until a dedicated pid.codes
  PID is obtained — **release blocker** tracked in `docs/release-checklist.md`.
  Never the Trezor PIDs `0x53C0/0x53C1`.
* Manufacturer `feuristic project`, product `feuristic security key`.
* USB 2.0 descriptors (`bcdUSB 0x0200`), no BOS, no WebUSB, no WinUSB
  descriptors in any feuristic mode.

### 5.2 Exclusive modes (`usb_set_mode`)

| Mode | Interfaces | IN endpoints | Entered from |
|---|---|---|---|
| `NORMAL` | 0: HID FIDO (int IN/OUT 64 B) · 1: CCID (bulk IN/OUT 64 B, int IN 8 B) | 3 | default |
| `TIMESYNC` | 0–1: CDC-ACM (IAD; int IN 8 B, bulk IN/OUT 64 B) | 2 | Réglages → Heure TOTP |
| `IMPORT` | 0: MSC BOT (bulk IN/OUT 64 B), FAT12 label `FEURISTIC` (SCSI product `FEURISTIC-IMPORT`) | 1 | Ajouter QR / Restaurer |
| debug builds only | every mode + a vendor debuglink interface (EP3, int IN/OUT) | +1 | build flag |

The coreapp requests a mode with the new syscall `usb_set_mode(mode)`; the
kernel performs `usb_deinit → usb_init(dev_info(mode)) → class adds →
usb_start` with a ≥ 100 ms detach so hosts see a clean re-enumeration.

### 5.3 Kernel classes

The CCID and MSC kernel classes are deliberately dumb: they exchange **raw
64-byte packets** with the coreapp through syshandles (`SYSHANDLE_USB_CCID`,
`SYSHANDLE_USB_MSC`), exactly like the HID class. A zero-length write requests
a ZLP. CCID message assembly, SCSI/BOT state and FAT12 live in the coreapp.

### 5.4 Emulator

The unix emulator maps each interface to a UDP port relative to
`TREZOR_UDP_PORT` (default 21324): debug +1, FIDO HID +2, CDC +3, **CCID +7,
MSC +8**. One datagram carries one 64-byte packet (CCID/MSC may also use
larger datagrams carrying whole messages; see `docs/developer/emulator.md`).
`tools/vpcd_bridge.py` exposes the emulated CCID reader to a real `pcscd`
through vsmartcard's `vpcd`, so GnuPG / OpenSC can talk to the emulator.

## 6. Storage

### 6.1 Namespaces (norcow APP ids)

Upstream reserves APP 0x00 and uses 0x01–0x04; feuristic keeps upstream's
`APP_DEVICE (0x01)` for retained upstream internals (device id, U2F counter)
and allocates:

| APP | Flags | Content |
|---|---|---|
| `0x10` SYS | protected | master secret, protected settings, app PIN state |
| `0x90` SYS_PUBLIC | public | language, init flag, storage schema version, autolock |
| `0x11` OTP | protected | OTP account records (slots 0–32, record type 0x01) |
| `0x91` OTP_COUNTERS | public | HOTP redundant counters: stable index i (0–32) → keys 2i, 2i+1 |
| `0x12` FIDO_CREDS | protected | discoverable credential records (slots 0–100) |
| `0x13` FIDO_STATE | protected | clientPIN state, largeBlob array (A/B), misc |
| `0x14` CARD | protected | OpenPGP identity, PIV slot identities, PIV data objects, AES keys |
| `0x94` CARD_COUNTERS | public | AES-GCM nonce reservation (A/B), app PIN retry counters |

### 6.2 Record store (`feuristic.core.store`)

A namespace is an array of slots. A record value is
`magic(1)=0xFE | schema(1) | type(1) | flags(1) | generation(u32 BE) | uid(8) | payload`.
Updates are **copy-on-write**: write the new record into a free slot with
`generation+1`, then delete the old slot. At unlock the store scans each
namespace, keeps the highest generation per `uid` and deletes stale copies.
This gives atomic replacement on top of norcow, which itself deletes before
rewriting. Monotonic counters (HOTP, AES nonces, PIN retries) use two
redundant public counters A/B; the value is `max(A, B)` and increments write A
then B (see `feuristic.core.counters`).

### 6.3 Size caps (plaintext payload)

| Record | Cap |
|---|---|
| OTP account | 256 B (issuer ≤ 32 B, account ≤ 64 B, secret ≤ 64 B) |
| Discoverable credential | 384 B (rpId ≤ 128 B, user.id ≤ 64 B, name/displayName ≤ 64 B each) |
| largeBlob array | 4096 B (+ 16 B header) |
| PIV slot identity | 2400 B (key + X.509 certificate ≤ 2048 B) |
| OpenPGP identity | 1536 B main record, plus auxiliary record ≤ 3712 B |
| AES key | 96 B |

## 7. Keys and domain separation

* A 32-byte **master secret** `MS` is generated with the strong RNG (TRNG ⊕
  Optiga) at initialisation and stored protected in `SYS`.
* Derived keys: `HKDF-SHA256(IKM=MS, salt="feuristic/v1", info=<label>)`.
  Labels are listed in `feuristic.core.kdf.LABELS` and are unique per
  application and purpose (`fido2/cred-wrap`, `fido2/largeblob-key`,
  `card/aes-nonce-namespace`, ...). AES uses an 8-byte namespace derived with
  the key-record uid and counter epoch, followed by a 4-byte index; the global
  persisted counter and backup `nonce_floor` remain 64-bit. The legacy
  `card/aes-nonce-prefix` label remains available for migration vectors.
* Asymmetric identity keys (OpenPGP, PIV, discoverable passkeys) and AES keys
  are **random**, stored explicitly in their record and never shared across
  applications. Non-discoverable FIDO credentials are wrapped into the
  credential ID with `fido2/cred-wrap` (AES-256-GCM).

## 8. Application package (`src/feuristic`)

```
feuristic/
  platform/        facade + backends (fw: trezor.*, host: cryptography/dicts)
  core/            cbor, tlv, base32, base45, kdf, store, counters, clock, rsa,
                   errors, i18n, policy
  apps/otp/        hotp, totp, accounts, otpauth URI codec
  apps/fido2/      ctaphid framing, ctap1 (U2F), ctap2 (2.1), clientpin, credmgmt,
                   largeblobs, extensions, credentials
  apps/card/       ccid framing, apdu, dispatcher (AID select), openpgp, piv,
                   aes (ISO 7816-8 PSO profile), rng (GET CHALLENGE)
  apps/backup/     envelope (canonical CBOR, PBKDF2, AES-GCM), frames (Base45 QR),
                   export, restore — see docs/protocols/backup-format-v1.md, ADR-0004
  apps/importer/   MSC import session → QR payload → otp / backup
  apps/timesync/   CDC-ACM `TIME 1 <unix>` protocol
  ui/              menu tree, screens, text/number entry, QR display (fw only)
  main.py          boot, unlock, session loop, USB mode manager
```

User interaction is injected: protocol handlers receive a `ui` object with
async methods (`confirm`, `notify`, ...). Host tests pass a scripted fake;
the firmware passes `feuristic.ui`.

## 9. Testing strategy

| Level | Where | Runs on |
|---|---|---|
| C unit tests + sanitizers | `tests/c` | host (CI: Linux clang ASan/UBSan, macOS) |
| Fuzzing | `tests/fuzz` | CI smoke (60 s/target), nightly long runs |
| Python unit tests | `tests/host` | CPython + `cryptography`, coverage gate |
| MicroPython unit tests | `tests/upy` | emulator (`firmware-emu`) |
| Functional | `tests/functional` | emulator over UDP: FIDO2 (python-fido2), CCID APDUs, MSC import, CDC time sync, UI flows via debuglink |
| Interop | `tests/functional/interop` | CI Linux: GnuPG, OpenSC, libfido2 via vpcd/uhid bridges |
| Acceptance | `docs/acceptance/` | real T2B1 / T3B1 hardware (manual, R01–R16) |

## 10. Build variants

| Variant | Command | Notes |
|---|---|---|
| Hardware candidate T2B1/T3B1 | `make firmware MODEL=T2B1` | `pyopt`, frozen, no debuglink; upstream development signing keys |
| Debug hardware | `make firmware-debug MODEL=T3B1` | debuglink iface, debug logs, `__debug__` asserts |
| Emulator | `make emu MODEL=T3B1` | debug + debuglink + insecure storage testing mode |

Release artifacts are named `feuristic-<version>-<model>-<gitsha>.bin` with
SHA-256 sums, an SPDX SBOM and build provenance (see `docs/developer/release.md`).

The default hardware build is a test candidate signed with publicly known
upstream development keys, not a private vendor release. Stable distribution
requires the signing/vendor review in [release.md](developer/release.md), a
dedicated USB PID, and all physical [R01–R16 gates](acceptance/README.md).
An emulator's 20 MiB test heap does not establish a hardware memory fit.
