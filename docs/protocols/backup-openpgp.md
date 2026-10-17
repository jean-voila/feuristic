<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Backup item schema: OpenPGP card identity (`type = "openpgp"`, `v = 1`)

Status: **normative** for feuristic v0.x. Implementation:
`src/feuristic/apps/card/openpgp/provider.py` (`OpenPgpBackupProvider`).
Requirements: spec §8.2, §8.3. The container, encryption, KDF and QR
framing are defined in `docs/protocols/backup-format-v1.md`.

The card holds **one** OpenPGP identity: three key slots plus their data
objects. It is exported and restored as one item in canonical CBOR
(RFC 8949 §4.2.1).

## 1. CDDL (RFC 8610)

```cddl
openpgp-identity = {
  "type": "openpgp",
  "v": 1,
  "keys": [sig: key, dec: key, aut: key],
  "name": bstr .size (0..39),          ; ISO 8859-1, "Surname<<Given"
  "lang": bstr .size (0..8),
  "sex": bstr .size (0..1),            ; "", "0", "1", "2" or "9"
  "url": bstr .size (0..254),
  "login": bstr .size (0..254),
  "private": [4*4 bstr .size (0..254)], ; DOs 0101..0104
  "cert": bstr .size (0..2048),        ; DO 7F21
  "pw1": pin,
  "pw3": pin,
  "rc": pin / null,                    ; resetting code
  "pw1_status": 0 / 1,
  "dsc": uint .le 16777215,            ; digital signature counter
}

key = {
  "attr": bstr,                        ; canonical algorithm attributes (below)
  "secret": bstr / null,               ; null = empty slot
  "fpr": bstr .size 20,                ; DO C7..C9 (zeros = unset)
  "ca": bstr .size 20,                 ; DO CA..CC
  "date": uint .le 4294967295,         ; DO CE..D0
  "origin": 0 / 1 / 2,                 ; 0 iff secret is null; 1 generated, 2 imported
}

pin = {
  "kdf": 1..1000000,                   ; PBKDF2 iterations (1000 in v1)
  "salt": bstr .size 16,
  "hash": bstr .size 32,               ; PBKDF2-HMAC-SHA256(pin, "feuristic/openpgp/pin\0" || salt)
  "len": 1..127,                       ; ≥ 6 for pw1, ≥ 8 for pw3 and rc
}
```

Allowed `attr` values and their `secret` encoding:

| attr | Roles | secret |
|---|---|---|
| `16 2B 06 01 04 01 DA 47 0F 01` (Ed25519) | sig, aut | 32-byte seed |
| `12 2B 06 01 04 01 97 55 01 05 01` (X25519) | dec | 32-byte scalar (clamped at use) |
| `01 08 00 00 20 00` (RSA-2048) | any | `p ‖ q`, 128 + 128 bytes big-endian; e = 65537; n must have exactly 2048 bits |

## 2. Rules

* **Validation** (`validate`, run on every item before anything is
  written):
  * exact key sets;
  * types, lengths and ranges as above;
  * algorithm/role pairs;
  * canonical attributes;
  * RSA primes produce a 2048-bit modulus.

  Any violation raises `InvalidInput`.
* **PINs travel as salted PBKDF2 references**, never in clear. The
  restored card keeps the same PINs. Try counters are restored to 3.
* **`exists`** is true when the card already holds a non-empty identity,
  i.e. any key, aux data or name. Restoring then needs `overwrite=True`;
  the UI shows the existing label and fingerprint first (spec §8.2).
* **Atomicity**: the identity is written through `IdentityStore.replace`.
  First the new aux record is written under the free uid, then the
  identity record is atomically replaced, then the old aux record is
  deleted. A power cut leaves the old or the new identity, never a mix.
  Try counters are cleared only after the identity is written.
* The digital signature counter continues from `dsc`.
* The card **serial number (AID) is not part of the backup**: it is
  derived from the destination device's master secret. GnuPG therefore
  sees a new card serial and re-learns the keys (`gpg --card-status`).
* `describe` returns `("OpenPGP - <name>", <first non-zero fingerprint as
  40 upper-case hex>)`.
* `list_identities` returns `[(b"openpgp", label)]`, or `[]` for an empty
  or terminated card.

## 3. Security note

An exported identity contains the private keys. Anyone who holds all the
QR images and the backup passphrase can restore them (spec §8.2). The
device never presents these keys as non-exportable; the
`openpgp.backup.warning` string carries that message.
