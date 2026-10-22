---
title: "ADR 0004: encrypted QR backup envelope"
description: "Design of the feuristic backup envelope: canonical CBOR, AES-256-GCM and QR framing for a full encrypted export of device identities."
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# ADR-0004: QR backup envelope and the "full export" design

* Status: accepted (v0.x)
* Context: spec §8.2, §8.3, §3.3, §10.6, R13, R14
* Normative format: `docs/protocols/backup-format-v1.md`

## 1. Context

The spec fixes the cryptography: canonical CBOR (RFC 8949), AES-256-GCM,
PBKDF2-HMAC-SHA-256 with 600 000 iterations, a 16-byte random salt, a
unique 12-byte nonce, a passphrase of at least 12 characters, and
authentication before import. Encrypted bytes are split into numbered QR
frames carrying a backup id, an index, a total and a transport checksum.
"Exporter une identité" exports one identity. "Export complet" chains
the same objects. Restoring is atomic per identity, and any missing frame
blocks the import without modifying storage.

Constraints that shaped the design:

* A 128 × 64 screen. At most about 156 payload bytes fit in a QR code
  that a camera can still hope to read (version 9, 1 px/module), or about
  22 bytes with large modules. A full export of 100 passkeys plus their
  largeBlob data takes hundreds of images.
* PBKDF2 with 600 000 iterations costs several seconds on the
  STM32F427/U585. Running it once per identity in a 150-identity export
  is not acceptable.
* RAM on T2B1: a heap of about 120 KiB. Not every frame of a full export
  can be held at once.
* Photographing hundreds of images is error-prone. Losing a single image
  should not lose everything.

## 2. Decision

1. **One envelope per identity.** Both export modes produce envelopes that
   each contain exactly one item. Each envelope has its own random backup
   id and its own random 96-bit nonce, and is split into its own frame
   sequence. An identity can therefore be restored alone, and a missing or
   damaged image only affects the identity it belongs to.
2. **One key per export session.** "Export complet" draws one random salt,
   derives the key once, and seals every envelope of the session with
   that key. The salt is repeated in every header. On restore, envelopes
   are grouped by salt, so a complete full export needs one passphrase
   entry and one PBKDF2 run.
3. **Header = authenticated public parameters.** The compact binary
   prefix (`"FEBK"`, version, length) is followed by a canonical CBOR map
   with integer keys (kind, backup id, KDF id, iterations, salt, AEAD id,
   nonce). The whole prefix and map form the GCM AAD. Algorithm
   identifiers and the iteration count are explicit, so every parameter is
   both self-describing and authenticated. Decoders accept exactly one
   value for each of them in v1.
4. **The plaintext says where an envelope belongs.** Envelopes of a full
   export carry `"seq"` and `"count"`. The restore can then tell the user
   that, for example, 11 of 12 identities are present and ask before
   restoring the rest.
5. **Lazy export.** A full export is an `ExportSession` that builds one
   identity (envelope and frames) on demand. Only the frames on screen
   are in RAM.
6. **Frames:** `"FB1:" ‖ Base45(id ‖ index ‖ total ‖ chunk ‖ CRC-32)` in
   QR alphanumeric mode, with two size profiles: dense (version ≤ 9) and
   large modules (version ≤ 3), both at ECC level M.

## 3. Security of sharing one key across a session

* **Nonce uniqueness.** AES-GCM is secure as long as a (key, nonce) pair
  is never reused. The nonces are independent uniform 96-bit values from
  the strong RNG. For `q` envelopes under one key, the probability of a
  collision is at most `q² / 2⁹⁷`. A maximal session (`q = 1024`, the
  format limit) gives about 2⁻⁷⁷, far below any practical concern.
  NIST SP 800-38D allows up to 2³² invocations with random 96-bit IVs.
  We use at most 2¹⁰.
* **Key uniqueness across sessions.** Every session draws a fresh 128-bit
  salt. Two sessions with the same passphrase therefore use independent
  keys (salt collision probability is about 2⁻¹²⁸ per pair). Nonce counting
  restarts per key, so there is no state to persist (unlike the AES
  service of spec §7, which needs a persistent counter because its keys
  are long-lived).
* **No cross-envelope malleability.** Each envelope's header, including
  its backup id and kind, is bound to its ciphertext by the tag. Swapping
  tags, headers or bodies between envelopes fails authentication (tested).
  Someone holding the images could present a subset of a session's
  envelopes. Each one is a complete, authentic identity, and the
  `seq`/`count` fields make the omission visible. Re-presenting envelopes
  of the same session is exactly what restoring a backup means.
* **Identical security for one identity.** A single-identity export is a
  session of size one, so nothing is weakened for the common case.
* **Brute force.** Sharing the key does not change the attacker's cost:
  one PBKDF2 evaluation per guess, whether they target one envelope or a
  whole session. They gain nothing beyond what the per-session salt
  already gives.
* **Device independence.** Neither the master secret nor any
  device-derived label enters the key or the backup id. The backup id is
  random rather than derived (`backup/id` in `core.kdf` is unused), so
  backups cannot be linked to a device, and they restore on the other
  hardware revision (spec §8.3, R14).

## 4. Alternatives considered

* **One envelope containing every item.** It is simpler, but a single lost
  or unreadable image among hundreds makes the whole backup unrecoverable,
  and the device would need the complete plaintext and all frames in RAM.
  Rejected.
* **One salt and derivation per identity.** It would run 600 000
  iterations per identity, which is minutes of computation for a full
  export and the same again for the restore, with no security benefit
  (§3). Rejected.
* **Deriving per-envelope subkeys with HKDF(key, backup id).** This would
  remove nonce-collision analysis entirely, at the cost of an extra
  primitive that the spec does not name and that third-party decoders
  would have to implement. With the bound in §3 the extra margin is
  irrelevant. Rejected for v1 simplicity. It remains a clean option for
  a v2.
* **Counter nonces.** They need persistent state or per-session
  bookkeeping. Random nonces are simpler and their collision bound is
  negligible here.
* **QR byte mode with raw binary frames.** It would be about 3 % denser
  than Base45 in alphanumeric mode (8 bits per payload byte, against
  1.5 × 5.5 = 8.25). Base45 was kept: the spec names it, frames stay
  printable ASCII (robust through the importer's text classification),
  and the QR decoders on both sides avoid the ECI and charset ambiguity of
  byte mode.
* **A textual header such as `FEURISTIC-BACKUP`.** It would waste
  frame space. The 4-byte magic plus the version byte is enough, and
  users see the version string "Backup format v1".

## 5. Consequences

* A full export needs as many sequences as identities, each starting with
  its own "QR 1 of n". The UI shows "Identity i of N" and the label. Short
  identities (OTP accounts) cost at least one image each. The format
  allows up to 16 items per full-export envelope, so a future exporter
  could group small items without breaking v1 decoders.
* The same MSC session accepts the independent identity sequences successively.
  The host/test batch API can collect them together; the constrained device
  processes one complete, authenticated envelope at a time, pausing decoder
  memory and host writes during confirmation/restore. A missing frame prevents
  that identity from changing. Earlier explicitly confirmed identities remain
  restored; full-set sequence counts and conflicts are tracked. The v1 bytes
  are unchanged. The device transport budget is 12 KiB per native identity,
  distinct from the generic format/parser's 64 KiB bound. See
  [the streaming procedure](../protocols/backup-format-v1.md#83-memory-bounded-device-restore-same-v1-bytes).
* Readability of the dense profile at 1 px/module, and of the large
  profile with its reduced quiet zone, is not demonstrated on hardware.
  Acceptance test R13 decides. If R13 fails for the dense profile, only
  the profile table changes. The envelope format stays the same.
