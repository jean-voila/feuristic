---
title: Encrypted QR backup format v1
description: "Normative feuristic QR backup format: CBOR container, AES-256-GCM encryption, key derivation and QR framing for identity export and restore."
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# feuristic QR backup format, version 1

Status: **normative** for feuristic v0.x. Product requirements: spec §3.3,
§8 (all of it), §10.3, §10.6, R13, R14. Design rationale:
`docs/adr/0004-backup-envelope.md`.

Implementation:

| Part | Module |
|---|---|
| Base45 (RFC 9285) | `src/feuristic/core/base45.py` |
| CRC-32 | `src/feuristic/apps/backup/crc32.py` |
| Envelope (§3–§5) | `src/feuristic/apps/backup/envelope.py` |
| QR frames (§6) | `src/feuristic/apps/backup/frames.py` |
| Provider interface (§7) | `src/feuristic/apps/backup/provider.py` |
| Export / restore (§8) | `src/feuristic/apps/backup/export.py`, `restore.py` |
| Import payloads (§9) | `src/feuristic/apps/importer/payload.py`, `session.py` |
| Test vector (§10) | `tests/host/backup/test_vector.py` |

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Overview

```
identity (provider dict) ──canonical CBOR──► plaintext
passphrase + salt ──PBKDF2-HMAC-SHA256 ×600 000──► 256-bit key
key + nonce + AAD(header) ──AES-256-GCM──► envelope = header ‖ ciphertext ‖ tag
envelope ──split, CRC-32, Base45──► "FB1:…" frames ──► one QR code each
```

* One envelope holds **one identity** (one OTP account, one passkey, one
  PIV slot, the OpenPGP key set, one AES key…). "Export complet" produces
  one envelope per identity, all encrypted with the same key (same salt)
  but each with its own random nonce and backup id, so every identity
  restores on its own and a lost image only loses that identity
  (ADR-0004).
* The format depends only on the passphrase and the data. Nothing is bound
  to the device, its master secret or its hardware revision, so a backup
  made on a T2B1 restores on a T3B1 and conversely (spec §8.3, R14).
* The format is distinct from, and not interchangeable with, Trezor wallet
  backups (spec §8.3).

## 2. Conventions

* Integers in binary layouts are unsigned big-endian.
* "Canonical CBOR" is the core deterministic encoding of RFC 8949 §4.2.1:
  shortest-form integers and lengths, definite lengths only, map keys
  sorted by the bytewise order of their encodings, no duplicate keys, no
  tags, no floats, no simple values other than `false`, `true`, `null`.
  Decoders MUST reject anything else, including trailing bytes.
* CDDL follows RFC 8610.

## 3. Key derivation

### 3.1 Passphrase policy

The backup passphrase is distinct from the device PIN, is typed on the
device with the two buttons, is never stored, and is never sent to the
computer (spec §8.2).

* Length: **12 to 128 bytes**.
* Alphabet: **printable ASCII `0x20`–`0x7E`** (space allowed). The
  on-device keyboard offers only ASCII. Restricting the alphabet also means
  the same passphrase gives the same bytes on every device and firmware,
  with no Unicode normalisation question.
* The passphrase bytes are used as-is: no trimming, no case folding, no
  normalisation.

An encoder MUST refuse a passphrase outside this policy. A v1 decoder MUST
apply the same policy (a backup can only have been made with a conforming
passphrase).

### 3.2 KDF

```
key = PBKDF2-HMAC-SHA256(P = passphrase, S = salt, c = 600 000, dkLen = 32)
```

* `salt`: 16 bytes from the strong RNG, drawn once per export session.
* `c` is fixed at **600 000** for format v1. A decoder MUST reject any
  other value (`UnsupportedParameters`), so a crafted backup cannot ask
  for an absurd iteration count. A future, stronger setting needs a new
  KDF identifier or a new format version.
* The 32-byte PBKDF2 output is the AES-256 key, with no further step.
* Implementations run the derivation incrementally. feuristic does 4096
  iterations per step and reports `progress(done, 600000)` between steps,
  so the screen and USB stay responsive. On the device this takes several
  seconds.

## 4. Envelope

### 4.1 Binary layout

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `46 45 42 4B` (`"FEBK"`) |
| 4 | 1 | format version = `0x01` |
| 5 | 2 | `H` = length of the header map, `1 ≤ H ≤ 96` |
| 7 | `H` | header: canonical CBOR map (§4.2) |
| 7+`H` | `n ≥ 1` | ciphertext |
| 7+`H`+`n` | 16 | AES-GCM tag |

Total envelope length MUST be ≤ 65 536 bytes.

### 4.2 Header (CDDL)

```cddl
header = {
  1 => kind,            ; 1 = identity export, 2 = part of a full export
  2 => bstr .size 8,    ; backup id (random, also carried by every frame)
  3 => 1,               ; KDF: 1 = PBKDF2-HMAC-SHA256
  4 => 600000,          ; PBKDF2 iteration count
  5 => bstr .size 16,   ; salt
  6 => 1,               ; AEAD: 1 = AES-256-GCM (96-bit nonce, 128-bit tag)
  7 => bstr .size 12,   ; nonce
}
kind = 1 / 2
```

All seven keys are required. Other keys are forbidden. In practice the
header is 55 bytes (`H = 0x0037`), so the fixed overhead of an envelope
is 7 + 55 + 16 = **78 bytes**.

### 4.3 Encryption

```
AAD        = envelope[0 : 7+H]           ; magic ‖ version ‖ H ‖ header
ciphertext ‖ tag = AES-256-GCM-Encrypt(key, nonce, plaintext, AAD)
```

* The **whole** header is authenticated: magic, version, length, kind,
  backup id, KDF and AEAD identifiers, iteration count, salt and nonce.
* The nonce is 12 random bytes, drawn for every envelope. Within one export
  session the key is shared, and the nonces are independent random values
  (ADR-0004 §3 gives the collision bound).
* RNG draw order in feuristic (needed to reproduce §10): salt (once per
  session), then for each envelope the backup id (8), then the nonce (12).

### 4.4 Decryption: authenticate before parsing

1. Check the length bound, the magic and the version (`UnsupportedVersion`
   if the version is not 1).
2. Decode the header with a canonical, depth-1 CBOR decoder and check it
   against §4.2. The header is the only data read before
   authentication. It is short, bounded and has a fixed schema.
3. Derive the key (§3.2). A key is cached per salt for the duration of
   one restore. A key is cached only after it has authenticated at least
   one envelope.
4. Verify the tag with AES-GCM. On failure, report "wrong passphrase or
   damaged backup" (`AuthenticationFailed`). The two cases cannot be told
   apart. No plaintext is released and nothing is written.
5. Only then decode the plaintext (canonical CBOR, maximum depth 8,
   bounded item count) and validate it strictly (§5). A plaintext that is
   authenticated but not canonical, or that breaks the schema, MUST be
   rejected (`PlaintextError`).

## 5. Plaintext

### 5.1 CDDL

```cddl
plaintext = identity-plaintext / full-plaintext

identity-plaintext = {          ; header kind = 1
  "v": 1,
  "kind": "identity",
  "items": [ item ],            ; exactly one item
  ? "created": uint .le 4294967295,
}

full-plaintext = {              ; header kind = 2
  "v": 1,
  "kind": "full",
  "items": [ 1*16 item ],       ; the v1 exporter writes exactly one
  "seq": uint,                  ; 1 ≤ seq ≤ count: position in the export session
  "count": uint,                ; 1 ≤ count ≤ 1024: identities in the session
  ? "created": uint .le 4294967295,
}

item = {
  "type": item-type,            ; selects the provider (§7)
  "v": 1..255,                  ; provider schema version
  * tstr => any,                ; provider fields (no floats, no tags)
}
item-type = tstr .regexp "[a-z][a-z0-9_-]{0,15}"
```

* `"kind"` MUST match the header kind.
* Unknown top-level keys are forbidden. Item keys MUST all be text
  strings.
* `"created"` is informational (Unix seconds from the session clock when
  it is set) and is never used for a security decision.
* Items nest at most 5 container levels below the item map, and one item
  holds at most 1024 CBOR data items. The exporter checks this, so every
  export can be restored.

### 5.2 Registered item types

| `type` | Application | Item schema |
|---|---|---|
| `otp` | TOTP/HOTP accounts | `docs/protocols/backup-otp.md` |
| `fido2` | discoverable passkeys (+ their largeBlob data) | FIDO2 agent (to be published) |
| `openpgp` | OpenPGP Card key set | OpenPGP agent (to be published) |
| `piv` | one PIV slot (key + certificate) | PIV agent (to be published) |
| `aes` | one AES-256-GCM key | AES agent (to be published) |

`example` is used only by the test vector and has no provider.

## 6. QR frames

### 6.1 Frame text

```
frame  = "FB1:" Base45(binary)
binary = backup_id (8) ‖ index (u16) ‖ total (u16) ‖ chunk (≥ 1 byte) ‖ crc32 (4)
```

* `backup_id` is the envelope header's backup id. Frames of different
  envelopes are never mixed.
* `index` is **1-based**, with `1 ≤ index ≤ total ≤ 999`.
* `chunk` is the next slice of the envelope. Concatenating the chunks in
  index order gives the envelope exactly. Encoders balance the chunk
  sizes (the sizes differ by at most one byte), so all QR codes of a
  sequence have the same version.
* `crc32` is CRC-32/ISO-HDLC (zlib: poly `0x04C11DB7` reflected, init and
  xorout `0xFFFFFFFF`, check value `CBF43926`) over all preceding bytes of
  `binary`, big-endian. It detects misreads only. Security comes from the
  GCM tag.
* `Base45` is RFC 9285 with strict decoding. Decoders reject characters
  outside the 45-character alphabet, a dangling single character, a
  triplet value above 65 535 and a final pair value above 255.
* The prefix `FB1:` and the Base45 alphabet both belong to the QR
  alphanumeric character set, so a frame is one alphanumeric-mode segment
  (5.5 bits per character).
* Frame texts MAY contain spaces (Base45 digit 36), including a trailing
  space. QR decoders MUST NOT trim the payload. A trimmed frame fails the
  CRC or the Base45 check and is never misread.
* Decoders accept frame texts up to 1024 characters. Encoders emit at most
  262.

### 6.2 Display profiles (128 × 64 OLED, ECC level M)

| Profile | Max QR version | Modules | Pixels/module | Max frame chars | Max binary | **Chunk bytes** |
|---|---|---|---|---|---|---|
| `dense` (default) | 9 | 53 × 53 | 1 | 262 (v9-M alnum) | 172 | **156** |
| `large` (large modules) | 3 | 29 × 29 | 2 | 61 (v3-M alnum) | 38 | **22** |

Frames needed for an envelope of `L` bytes: `ceil(L / 156)` (dense) or
`ceil(L / 22)` (large). Examples:

| Envelope | Dense | Large |
|---|---|---|
| 197 B (test vector, §10) | 2 | 9 |
| 300 B (typical passkey) | 2 | 14 |
| 2 500 B (PIV slot with certificate) | 17 | 114 |
| 65 536 B (maximum) | 421 | — (> 999) |

`tests/host/backup/test_qr_capacity.py` checks with an independent encoder
(segno) that every generated frame fits its profile, and that the profiles
are tight (one more character needs the next version). The quiet zone at 1
px/module is 5 modules (standard). At 2 px/module it is only about 1.5
modules: readability with ordinary phone cameras is acceptance test
**R13** on real hardware and has **not** been demonstrated by the host
tests. A full export of many identities needs many images. This is
specified behaviour, not presented as fast or convenient (spec §8.2).

### 6.3 Reassembly rules

* Frames may arrive in any order and over several files.
* An exact duplicate (same id, index and chunk) is ignored.
* For one backup id, a frame with the same index and a different chunk is
  rejected (`FrameConflict`), as is a frame with a different `total`
  (`FrameTotalMismatch`). A frame whose CRC fails is rejected
  (`FrameChecksumError`). A rejected frame never changes the state.
* Generic format/parser bounds: ≤ 999 frames and ≤ 65 536 envelope bytes per
  backup. The host-oriented collection API defaults to 96 KiB and 192 sequences.
  Device reception uses the separate, published 12 KiB per-identity budget and
  one active sequence; see §8.3. These device budgets do not change format v1.
* Reassembly is refused while any index is missing (`FrameIncomplete`,
  which lists the missing indices). **A missing frame blocks the restore
  of that identity and modifies none of its active data.**

## 7. Provider interface

Every backed-up application registers one provider at boot:
`feuristic.apps.backup.provider.register(p)`. Registration order is export
order. `get(type)` raises `UnsupportedItem` for an unknown type, and `all()`
returns the providers.

| Member | Contract |
|---|---|
| `TYPE: str` | item type (§5.2), `[a-z][a-z0-9_-]{0,15}`, unique |
| `LABEL_KEY: str` | i18n key of the category name shown in prompts (optional) |
| `list_identities() -> [(uid, label)]` | every exportable identity. `uid` is 1–32 bytes and stable. `label` is ≤ 128 UTF-8 bytes |
| `export_identity(uid) -> dict` | complete item (`"type"`, `"v"`, fields, secrets included), canonical-CBOR-able, with no device-bound material. `NotFound` if the uid is gone |
| `validate(obj)` | strict validation of an authenticated item. Raises `InvalidInput`. The default implementation checks `type`/`v`. Called for **every** item before any write |
| `exists(obj) -> bool` | restoring `obj` would replace an existing identity (same natural key) |
| `describe(obj) -> (label, fingerprint)` | shown in the restore preview and the overwrite confirmation. `fingerprint` is hex (≤ 64 chars) or `""` |
| `restore_identity(obj, overwrite) -> uid` | **atomic** write (all or nothing, power-loss safe). `PolicyDenied` if it exists and `overwrite` is false. `StorageFull` with nothing written. Restored FIDO2 credentials carry BE = BS = 1 |
| `on_exported(uid)` | called after the envelope is built and **before** its QR codes are returned for display (FIDO2 sets the WebAuthn backup-state flag BS). If it raises, no frame is returned |

Providers MAY subclass `BackupProvider` (recommended) or be duck-typed. A
provider without `validate` gets only the generic checks.

## 8. Procedures

### 8.1 Export ("Exporter une identité", "Export complet")

1. The user starts the export from the device menu (never from the host,
   spec §10.10).
2. **DANGER confirmation**. It shows the identity (or the number of
   identities) and the mandatory warning: *anyone holding the QR images
   and the passphrase can recover the keys; exported keys are no longer
   non-exportable* (spec §8.2). The device never claims that an exported
   key is non-exportable.
3. Re-authentication hook (device PIN, spec §9).
4. Passphrase entry, typed twice by the UI glue and compared in constant
   time, then checked against the policy (§3.1, up to 3 attempts).
5. A random salt and one key derivation for the whole session.
6. For each identity: `export_identity` → envelope (new backup id and
   nonce) → frames → `on_exported` → display "QR i of n".

The optional re-authentication hook is a core API extension point. The device
UI instead collects and confirms the passphrase first, then re-enters the
actual device PIN inside its passphrase callback, comparing the two locally.
It supplies no separate core hook, so there is one PIN check. All of this
happens after the recovery warning and before derivation or identity export.

### 8.2 Restore

1. The import session (§9) collects frames until every sequence is
   complete.
2. All headers are parsed. A malformed header fails before any passphrase
   prompt.
3. Envelopes are grouped by salt. Each group gets one passphrase entry and
   one key derivation. A wrong passphrase is reported and may be retried
   (3 attempts). When the attempts run out, the restore fails with
   **storage unchanged**.
4. Every envelope is authenticated and decrypted, and every item is
   validated by its provider, before anything is written. If any envelope
   or item fails, nothing is written.
5. If a full-export session is incomplete (`seq` values missing out of
   `count`), a NORMAL confirmation is shown.
6. A SENSITIVE summary confirmation previews the identities. For a single
   identity it shows the name and fingerprint.
7. For each item, if `exists`, a specific **DANGER overwrite confirmation**
   shows its name and fingerprint. A refusal skips that identity only.
   Then `restore_identity` runs, atomically per identity. On the first
   failure the remaining items are not attempted, and identities already
   restored stay restored (spec §8.2 "atomique par identité").
8. A report shows the identities restored, skipped, failed and not
   attempted.

### 8.3 Memory-bounded device restore (same v1 bytes)

The batch procedure above remains the host/test API `restore.restore`.
Firmware uses `restore.StreamingRestore`: it collects **one identity's complete
sequence**, releases the image decoder's workspace/bitmap/payload while keeping
MSC active, consumes that sequence's chunks, then authenticates and validates
**every item of the current envelope before any of them is written**. No
partial/unauthenticated identity is ever restored. Earlier confirmed identities
stay restored if a later independent identity is missing or damaged, as required
by per-identity atomicity. This is not a transaction over an entire full export.

The device receiver accepts one active sequence, ≤ 999 frames and ≤ 12 KiB
of encrypted envelope data. Tests cover maximal native exports: OpenPGP with
three RSA keys/auxiliary data (5127 B), FIDO with 64 associated largeBlob entries
(4847 B), PIV/RSA with certificate (2500 B), HOTP (379 B) and AES (241 B).
The native exporter emits one identity per envelope. A generic third-party
Full envelope may contain up to 16 items/64 KiB under format v1; the generic
parser supports that format, while device reception explicitly applies its
smaller transport budget. Oversized/interleaved input is refused, never
silently truncated or committed.

The user copies all frames of one identity, presses Continue and confirms it,
then waits for the next-identity invitation before copying more. During prompts
and derivation the MSC interface stays present but WRITE(10) returns NOT READY
(04/07), with the unaccepted residue; the host must retry a refused file after
resume. Done finishes the import and requests normal host eject. Do not copy a
whole full-export image directory during a paused confirmation.

`PackedReassembler` preserves arbitrary frame order and exact-duplicate checks
using a reserved byte arena plus four index bytes per frame. It does not keep a
Python bytes object for every tiny QR chunk. `StreamingRestore` caches at most
four wipeable salt/key pairs, records accepted backup-id/SHA-256 pairs and
full-set sequence bitmaps, rejects conflicting reused ids/sequence numbers, and
never calls a partial set complete. Missing sets are visibly reported. Exact
restored/skipped counters and the last four receipt examples are retained,
preventing hundreds of long labels from accumulating beside decoder buffers.
A later failure reports those prior successes. Keys are wiped on close.

See [memory evidence](../developer/import-memory.md). None of these software
checks replaces physical R04/R05/R13/R14 acceptance.

## 9. Import payloads and sessions

A QR found in an imported PNG/JPEG (spec §3.3) is classified as follows:

| Payload | Result |
|---|---|
| starts with `otpauth://` (scheme case-insensitive), ≤ 1024 bytes, all bytes in `0x20–0x7E` | OTP import |
| starts with `FB1:`, ≤ 1024 bytes, the rest in the Base45 alphabet | backup frame |
| `FB<1–3 digits>:` with another version | "unsupported backup version" |
| empty, > 2953 bytes, or anything else | "unsupported QR content" |

Session rules (`ImportSession`):

* It accepts any number of files without leaving the mode. Each file
  produces an event (accepted, duplicate or a specific rejection) with
  progress: received/total and the missing indices.
* The generic host collection API may collect several backup sequences and
  becomes batch-ready only when all are complete. Device streaming reception
  accepts one identity at a time (§8.3). Missing frames block that identity;
  `take_complete()` cannot return an incomplete envelope.
* At most one `otpauth://` URI per session. A different second URI is
  rejected. An identical one counts as a duplicate.
* **Mixing:** an `otpauth://` image while backup frames are being
  collected, or a backup frame while an OTP import is pending, is
  rejected and leaves the state unchanged. The user finishes or cancels
  the current import, then starts a new session.
* The session never writes storage. It returns an action (import an OTP
  URI, or restore these envelopes). After the action is done or declined,
  it is purged, which wipes the URI buffer. Then the glue asks for the
  SCSI eject. Cable removal or failure aborts and purges the session.

## 10. Test vector

Generated by `tests/host/backup/test_vector.py` with
`feuristic.platform.testing.deterministic_rng()` (SHA-256 counter mode,
seed `"feuristic-tests"`) and the real 600 000 iterations. The test also
decrypts the vector with `hashlib`, `cryptography` and `cbor2` only,
following this document.

Inputs:

```
passphrase = "correct horse battery staple"   (28 bytes)
item       = {"type": "example", "v": 1, "label": "Example identity",
              "secret": h'000102…1f' (32 bytes)}
kind       = identity (1), created = 1800000000
```

Values:

```
salt       778f41b9e5a960dacd70a61bbec357cd
key        147a98dfa786ba474adcba47ff2102b9dc3d15c819dbccee35995bf0098bdc8a
backup id  ac25714e21b1883d
nonce      015808a7e62817a47192c63c

AAD / prefix + header (62 bytes)
  4645424b 01 0037
  a7 01 01  02 48 ac25714e21b1883d  03 01  04 1a 000927c0
     05 50 778f41b9e5a960dacd70a61bbec357cd  06 01  07 4c 015808a7e62817a47192c63c

plaintext (119 bytes, canonical CBOR)
  a4617601646b696e64686964656e74697479656974656d7381a46176016474797065676578
  616d706c65656c6162656c704578616d706c65206964656e7469747966736563726574582000
  0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f67637265617465
  641a6b49d200

ciphertext (119 bytes)
  cdd51a18a6b3aa566c3164c387a68f146aeb03d33c59e3b6c409161690152a662c717bf449dc
  82ef56f59d7e6389452b0a1620e6de2744c6452f160b92bd3dcf857af29209cc8e7dbf36f02d
  b9ade254132790ce54c434a196d537f417dc24bc604b23779ce8870b91d0a181516a992cd305
  a8919f6ac2

tag        46127862388a5421a52aefc416b3b630
envelope   AAD ‖ ciphertext ‖ tag  (197 bytes)
```

Frames, `dense` profile (2 frames of 99 and 98 chunk bytes):

```
FB1:EYLQEEUB42AH100200Y*86H8V50R17W50:C0EYLQEEUB42AH4H0FN0900615AU075F+D8N1T:ACW/P/:KA5OM4B7Y0N-0T70A41F4TM:24GEX2P/0QKD3F3L1OLMUDAXCV6H/3IBNDYL0ES7JZSAZOTZ2U9I9G5$R57UF+D9ZJ0:0
FB1:EYLQEEUB42AH200200K*RPBUC2V0:F-FH%J5*Z2H8TH/4.2P*.5$K1P-NPAQJOFZKIV%PG+FO.65Z59:LDSA305Z3Q8 OBJK/.QR%UG$RT NKM9K5F$HT K1*GQUFGJLD0U58W0JIIFMDS%8%9FT67RSAR*K0EU6*2K1NUBDM8U
```

Frames, `large` profile (9 frames):

```
FB1:EYLQEEUB42AH100900Y*86H8V50R17W50:C0EYLQEEUB42AH4H0V$7V0E
FB1:EYLQEEUB42AH200900FN0900615AU075F+D8N1T:ACW/P/:KA5O1K5BE1
FB1:EYLQEEUB42AH300900M4B7Y0N-0T70A41F4TM:24GEX2P/0QKD3O%TYDK
FB1:EYLQEEUB42AH400900F3L1OLMUDAXCV6H/3IBNDYL0ES7JZSAZONP53H9
FB1:EYLQEEUB42AH500900TZ2U9I9G5$R57UF8F9*OGV:A/+JBQCMX8VAV80B
FB1:EYLQEEUB42AH600900HC1774 3SBV8QX8IZ2ZOIS 7F*G/TUXA1IMD5*L
FB1:EYLQEEUB42AH700900R0IZ7OFGUDLNPRS/I2ZDIAWAIT633JE3771B4HI
FB1:EYLQEEUB42AH800900X03:S4 7CYL4S$JB3HNJIZIK7DAHGJLUQ%Y4202
FB1:EYLQEEUB42AH900900/DL+6K9PO3F2YIC.LHIB4BJ5NZOGWMQ768Z683
```

## 11. Security considerations

* **Stolen images, no passphrase:** confidentiality rests on the
  passphrase and on 600 000 PBKDF2-SHA256 iterations per guess, with a
  128-bit salt that defeats precomputation. A short or guessable
  passphrase is the main risk. The policy enforces only a minimum length,
  and the UI SHOULD recommend several random words.
* **Images and passphrase both held:** keys are recoverable by design
  (spec §8.2). The device says so before every export and never calls
  such keys non-exportable. FIDO2 sets the BS flag.
* **Altered or forged backup:** every byte is authenticated (header as
  AAD, body by GCM). Without the passphrase an attacker cannot produce an
  envelope that restores. Someone who has the passphrase can only make
  backups the owner could also make. They are still strictly validated,
  and an overwrite always needs a specific confirmation.
* **Replay of an older backup** of the same identity is possible (inherent
  to backups). The overwrite confirmation shows the fingerprint.
  Restoring an older HOTP counter is handled by the OTP provider, which
  never moves a counter backwards for the same secret.
* **Hostile QR content:** classification and parsing are bounded and
  strict, run unprivileged, and never interpret data as commands. The
  plaintext parser runs only on authenticated data.
* **Secrets in RAM:** derived keys and the OTP URI are kept in `bytearray`
  and wiped. Decrypted plaintext objects are immutable on MicroPython and
  cannot be wiped deterministically (known limitation).

## 12. Versioning

* The magic `FEBK` and the version byte identify the envelope format. The
  frame prefix `FB1:` identifies the frame format. Both are shown to the
  user as "Backup format v1" (spec §8.3).
* A decoder MUST reject unknown versions, KDF/AEAD identifiers and
  iteration counts with a clear "unsupported version/parameters" message.
  It MUST NOT guess.
* Item schemas are versioned independently with the `"v"` field of each
  item.
