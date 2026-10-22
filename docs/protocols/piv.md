---
title: PIV card application
description: "Normative feuristic PIV application: P-256 and RSA-2048 key slots, PIN, PUK, management key and examples with OpenSC and yubico-piv-tool."
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# PIV card application

Status: **normative** description of the feuristic PIV application (product
spec F04, F07, §6.2, §6.3; acceptance test R10). Implementation:
`src/feuristic/apps/card/piv/`. Tests: `tests/host/card/piv/`.

feuristic implements the commands and data objects of NIST SP 800-73-4
(Parts 1 and 2) needed by the common PIV middleware — OpenSC's `piv` driver
(`pkcs15-tool`, `pkcs11-tool`, `piv-tool`, hence TLS client authentication,
SSH via PKCS#11, S/MIME…) and the usual `yubico-piv-tool` / `ykman piv`
operations — with the algorithms of SP 800-78-4 listed below. It is **not** a
FIPS 201 / federal PIV credential: it carries no issuer-signed CHUID or
security object and makes no claim of conformance certification.

## 1. Application identifier and selection

* AID `A0 00 00 03 08 00 00 10 00 01 00`; partial selection by
  `A0 00 00 03 08` (or any prefix) is accepted.
* SELECT response: Application Property Template (SP 800-73-4 Part 1 Table 3):

```
61 37
   4F 06 000010000100                 PIX
   79 07 4F 05 A000000308             coexistent tag allocation authority
   50 0D "feuristic PIV"              application label
   AC 15 80 01 03  80 01 08  80 01 0A  80 01 0C  80 01 07  80 01 11  06 01 00
```

* Selecting another application (OpenPGP, AES), a card reset, a device lock
  or a USB re-enumeration clears the security status (PIN verified,
  administration key authenticated). Re-selecting PIV keeps it.

## 2. Key slots and algorithms

| Slot | Role (shown on the device) | Algorithms | PIN policy | Operations |
|---|---|---|---|---|
| `9A` | PIV Authentication | ECC P-256 (`11`), RSA 2048 (`07`) | once per session | ECDSA sign, RSA raw |
| `9C` | Digital Signature | ECC P-256, RSA 2048 | **before every use** | ECDSA sign, RSA raw |
| `9D` | Key Management | ECC P-256, RSA 2048 | once per session | **ECDH** (P-256), RSA raw (decryption) |
| `9E` | Card Authentication | ECC P-256, RSA 2048 | none | ECDSA sign, RSA raw (challenge-response) |
| `9B` | Card Application Administration Key | 3DES (`03`), AES-128 (`08`), AES-192 (`0A`, default), AES-256 (`0C`) | — | mutual / external authentication |

* Key-usage separation (spec §6.2): ECDH is only allowed with `9D`; ECDSA is
  refused with `9D`. RSA operations cannot be told apart (signing and
  decryption are the same raw private operation) and are allowed on every
  slot.
* Retired key slots (`82`–`95`), the secure-messaging key (`04`), P-384,
  RSA-1024/3072/4096, Ed25519/X25519 PIV extensions and pairing codes are not
  supported.
* GENERATE may make the PIN policy of a slot **stricter** (YubiKey tag `AA`:
  `01` never, `02` once, `03` always) but never weaker (`6A80`).

## 3. Commands

| Command | APDU | Access condition | Notes |
|---|---|---|---|
| SELECT | `00 A4 04 00` | always | §1 (handled with the dispatcher) |
| GET DATA | `00 CB 3F FF {5C tag}` | always (Printed Information: PIN) | §4 |
| PUT DATA | `00 DB 3F FF {5C tag}{53 …}` | administration key | §4 |
| VERIFY | `00 20 00 80 {PIN padded to 8}` | — | also `00 20 00 80` (no data: status) and `00 20 FF 80` (reset status) |
| CHANGE REFERENCE DATA | `00 24 00 80/81 {old ‖ new}` | old PIN/PUK | 16 bytes |
| RESET RETRY COUNTER | `00 2C 00 80 {PUK ‖ new PIN}` | PUK | 16 bytes |
| GENERAL AUTHENTICATE | `00 87 alg slot {7C …}` | per slot (§5) | §6 |
| GENERATE ASYMMETRIC KEY PAIR | `00 47 00 slot {AC {80 alg}[AA pin][AB touch]}` | administration key + device confirmation | response `7F49 {86 point}` or `7F49 {81 n, 82 e}` |
| GET VERSION (YubiKey) | `00 FD 00 00` | always | `05 07 00` |
| GET SERIAL (YubiKey) | `00 F8 00 00` | always | 4 bytes derived from the device |
| GET METADATA (YubiKey) | `00 F7 00 ref` | always | refs `80`, `81`, `9B`, `9A`/`9C`/`9D`/`9E` |
| SET MANAGEMENT KEY (YubiKey) | `00 FF FF FF/FE {alg 9B len key}` | administration key + device confirmation | |
| RESET (YubiKey) | `00 FB 00 00` | PIN **and** PUK blocked + device confirmation | erases PIV |
| IMPORT ASYMMETRIC KEY (YubiKey) | `00 FE …` | — | **`6D00`**: keys are generated on the device (spec §6.2) |
| ATTEST, SET PIN RETRIES, MOVE KEY | `F9`, `FA`, `F6` | — | `6D00` |

GET RESPONSE (`00 C0`) and command chaining are handled by the card
dispatcher: long certificates and RSA signatures work with short APDUs.

`GET VERSION` reports the PIV feature level of YubiKey firmware 5.7 so that
`yubico-piv-tool`/`ykman` use the AES-192 default administration key and the
metadata command; it does not claim the device is a YubiKey (the APT label is
"feuristic PIV").

## 4. Data objects

| Object | Tag | GET DATA | PUT DATA (cap) |
|---|---|---|---|
| Card Capability Container | `5FC107` | generated (YubiKey-style template, card id derived from the device) or stored | ≤ 128 B |
| CHUID | `5FC102` | generated (below) or stored | ≤ 960 B |
| Discovery Object | `7E` | `7E {4F AID, 5F2F 4000}` (PIV PIN only) | read-only (`6A80`) |
| Key History | `5FC10C` | generated `C1 00, C2 00` (no retired keys) or stored | ≤ 128 B |
| X.509 cert. 9A / 9C / 9D / 9E | `5FC105` / `5FC10A` / `5FC10B` / `5FC101` | `53 {70 cert, 71 info, FE}` | certificate ≤ 2048 B |
| Security Object | `5FC106` | stored only | ≤ 768 B |
| Printed Information | `5FC109` | stored only, **PIN required** | ≤ 256 B |
| anything else | | `6A82` | `6A80` |

* Generated CHUID: `30` FASC-N for non-federal issuers
  (`D4E739DA739CED39CE739D836858210842108421C84210C3EB`: agency code 9999,
  system 9999, credential 999999, as used by `yubico-piv-tool`), `34` GUID
  (16 bytes, `HKDF(master secret, "card/serial", "piv-guid")`, stable for
  the device), `35` expiration `20301231`, `3E` empty issuer signature, `FE`.
* PUT DATA content must be well-formed BER-TLV. An empty `53` deletes the
  object (a generated one then reappears). Certificate objects accept
  `70` (1..2048 bytes, mandatory), `71` (`00`, or `01` = gzip) and an empty
  `FE`; the certificate is stored next to the slot key (one record).
* Storage: one record per slot (key + certificate ≤ 2400 bytes), one record
  for the data objects, one for the credentials; all PIV records ≤ 10 KiB
  (`6A84` beyond).
* Generating a new key in a slot deletes its (now mismatched) certificate.

## 5. PIN, PUK and administration key

### 5.1 Default values — decision

The PIV application starts with the standard PIV defaults: PIN `123456`,
PUK `12345678`, administration key AES-192
`010203040506070801020304050607080102030405060708`. Rationale: the spec
requires all configuration to be possible on the device (§1.2, §9) but must
not make PIV unusable for a user who skips the PIV set-up step; standard
tools also expect these defaults. To keep this safe:

* the menu "Cryptographie → PIV" shows a warning for every default still in
  use (`piv.warn.default_pin`, `…_puk`, `…_mgmt`) until it is changed;
* the PIV set-up step (`localmgmt.init_identity`) asks for a new PIN and PUK
  on the device (digits only, 6–8); the administration key can be replaced
  by a random one shown on the device screen (`generate_mgmt_key`) so that
  it can be typed into host tools;
* the host can also change PIN/PUK with CHANGE REFERENCE DATA (any printable
  ASCII, 6–8 characters) and the administration key with SET MANAGEMENT KEY
  (requires the current key **and** an on-device confirmation);
* setting a value back to its default re-enables the warning.

### 5.2 Rules

* PIN and PUK: 6–8 printable ASCII bytes padded with `FF` to 8 bytes
  (SP 800-73-4 Part 2 §2.4.3). A malformed value answers `6A80` without
  consuming a try.
* Retry counters: 3 tries each. The failure counter is written to flash
  **before** the comparison and cleared after a success (a power cut can only
  cost a try, never give one). `63Cx` = wrong value, `x` tries left; `6983` =
  blocked. A failed VERIFY clears the PIN security status.
* Blocked PIN: RESET RETRY COUNTER with the PUK, or "Définir le PIN PIV" on
  the device (the device is already unlocked with the device PIN). Blocked
  PIN **and** PUK: YubiKey-style RESET (`00 FB`) with a device confirmation,
  or "Réinitialiser PIV" on the device.
* Changing PIN, PUK or the administration key (from the host or the device)
  voids the current security status; the host must verify / authenticate
  again.
* PIN and PUK are stored as `HMAC-SHA-256(salt, padded value)` with a random
  16-byte salt in the protected (storage-DEK encrypted) namespace; the
  administration key is stored in the same protected namespace.

### 5.3 Administration key authentication (GENERAL AUTHENTICATE, slot `9B`)

`P1` must be the configured algorithm (`6A86` otherwise); witness, challenge
and response have the cipher block size (8 bytes for 3DES, 16 for AES).

| Flow | Step 1 | Card | Step 2 | Card |
|---|---|---|---|---|
| mutual (yubico-piv-tool, `piv-tool -A M:9B:…`) | `7C 02 80 00` | `7C {80 E(W)}` | `7C {80 W, 81 C}` | `7C {82 E(C)}` |
| external (`piv-tool -A A:9B:…`) | `7C 02 81 00` | `7C {81 C}` | `7C {82 E(C)}` | `9000` |

* Step 2 must immediately follow step 1 (any other command discards the
  pending witness/challenge, `6985` afterwards). A wrong witness or response
  answers `6982` and revokes a previous authentication.
* Internal authentication with the administration key (`7C {81 C, 82 ∅}`)
  is refused (`6A80`): it would be an encryption oracle answering the
  external-authentication challenge.
* 3DES is TDEA keying option 1 (SP 800-67), implemented in pure Python.

## 6. Private-key operations (GENERAL AUTHENTICATE)

| Operation | Command data | Response |
|---|---|---|
| ECDSA P-256 | `7C {82 ∅, 81 hash}` (tags in any order) | `7C {82 DER ECDSA-Sig-Value}` |
| RSA 2048 raw (sign / decrypt / challenge) | `7C {82 ∅, 81 256-byte block}` | `7C {82 256-byte result}` |
| ECDH P-256 (`9D` only) | `7C {82 ∅, 85 04‖X‖Y}` | `7C {82 X coordinate (32 B)}` |

* ECDSA input: the host-computed hash. Longer than 32 bytes → leftmost 32
  bytes (FIPS 186-4 §6.4); shorter → left-padded with zeros; 1..64 bytes
  accepted (`6A80` otherwise).
* RSA input: exactly 256 bytes, numerically below the modulus (the host does
  the PKCS #1 v1.5 / PSS padding or the OAEP/v1.5 decoding).
* ECDH: the peer point must be an uncompressed point on P-256; it is checked
  before the confirmation (`6A80`).
* Challenge-response (spec F07, R10): signing a host challenge with `9E`
  (no PIN; "Card Authentication" prompt) or `9A` is the PIV
  challenge-response; the device shows "Challenge-response" for `9E`.

### 6.1 On-device confirmation (spec §6.3)

**Every** private-key operation shows a confirmation screen; PIN
verification never replaces it. The prompt (`Prompt.kind` `piv.sign`,
`piv.rsa`, `piv.ecdh`, `piv.card_auth`) contains:

* the operation (Signature / RSA private operation / ECDH key agreement /
  Challenge-response);
* the slot role and number, e.g. "Digital Signature (9C)";
* the algorithm ("ECC P-256", "RSA 2048");
* the public-key fingerprint: the first 8 bytes of SHA-256 over the
  SubjectPublicKeyInfo DER, in hex — comparable on the host with
  `openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum`;
* for signatures and RSA operations, the label **"Signature d'empreinte non
  interprétée"** / "Uninterpreted digest signature": PIV only receives a hash
  or a padded block, which the device cannot interpret, so no semantic
  description is invented.

Refusal or timeout answers `6982`. For `9C` the PIN is consumed by the
attempt, even if refused. The PIN is checked before the prompt is shown.
GENERATE and SET MANAGEMENT KEY also require a confirmation (DANGER-level
when an existing key is replaced).

## 7. Status words

| SW | Meaning |
|---|---|
| `9000` | success |
| `61xx` | more data: GET RESPONSE |
| `63Cx` | wrong PIN/PUK, `x` tries left |
| `6581` | stored PIV data corrupted |
| `6700` | wrong length (dispatcher: de-chained data > 4096 bytes) |
| `6881` / `6882` | logical channels / secure messaging not supported |
| `6982` | security status not satisfied (PIN, administration key) or operation refused on the device; wrong witness/response |
| `6983` | PIN/PUK blocked |
| `6985` | 9B step 2 without step 1; RESET while PIN or PUK is still usable |
| `6A80` | malformed data, unsupported algorithm/policy, key-usage violation, invalid point/input, unknown or read-only object in PUT DATA |
| `6A81` | RSA key generation unavailable in this build |
| `6A82` | data object not found |
| `6A84` | not enough memory (certificate > 2048 B, object cap, 10 KiB PIV budget) |
| `6A86` | wrong P1/P2 (algorithm mismatch, invalid key reference) |
| `6A88` | key reference not found (empty slot, unsupported PIN reference) |
| `6D00` | instruction not supported (including key import) |
| `6E00` | class not supported |

## 8. Usage examples

The device must be unlocked; confirm each private-key operation on its
screen. Reader names below are examples.

### 8.1 OpenSC

```sh
opensc-tool --list-readers
opensc-tool -s 00A4040005A00000030800 -s 00CB3FFF035C017E00   # raw SELECT + discovery
pkcs15-tool --list-certificates --list-public-keys
pkcs11-tool --module opensc-pkcs11.so --list-objects
# generate a key in 9A with the default AES-192 administration key
piv-tool -A M:9B:0A -G 9A:11 -o 9a.pub
#   (piv-tool reads the administration key from the file named by
#    $PIV_EXT_AUTH_KEY; algorithm 0A = AES-192, 03 = 3DES)
# load a certificate obtained for that key
piv-tool -A M:9B:0A -O 9A -i cert.der
# sign with 9C (PIN asked by pkcs11-tool, prompt on the device)
pkcs11-tool --module opensc-pkcs11.so --login --sign --mechanism ECDSA \
            --id 02 -i digest.bin -o sig.bin
# TLS client authentication / SSH via PKCS#11
ssh -I /usr/lib/opensc-pkcs11.so user@host
```

### 8.2 yubico-piv-tool

`yubico-piv-tool` only lists readers whose name contains "Yubikey" unless
`-r` is given: pass the reader name explicitly (`-r ''` matches any).

```sh
yubico-piv-tool -r '' -a status
yubico-piv-tool -r '' -a change-pin -P 123456 -N 24681357
yubico-piv-tool -r '' -a change-puk -P 12345678 -N 87654321
yubico-piv-tool -r '' -k 010203040506070801020304050607080102030405060708 \
                -a generate -s 9c -A ECCP256 -o 9c.pub
yubico-piv-tool -r '' -a verify-pin -P 24681357 -a selfsign-certificate -s 9c \
                -S '/CN=alice/' -i 9c.pub -o 9c.crt
yubico-piv-tool -r '' -k … -a import-certificate -s 9c -i 9c.crt
yubico-piv-tool -r '' -a verify-pin -P 24681357 -a test-signature -s 9c -i 9c.crt
yubico-piv-tool -r '' -k … -a set-mgm-key -m AES256 -n <64 hex digits>
```

`-a import-key` fails with `6D00` by design; `--pin-policy=never` on `9A`/`9C`
fails with `6A80` (only stricter policies are honoured); `--touch-policy=never`
fails because every operation is confirmed on the device.

## 9. Device menus (local management)

"Cryptographie → PIV" (`apps/card/piv/localmgmt.py`): list the four slots
with status, algorithm, fingerprint and PIN policy; generate a key (P-256 or
RSA 2048) in a slot; delete a slot (key + certificate); show a certificate
summary (subject CN, issuer CN, validity, serial — display-only parser);
set PIN / PUK; generate or reset the administration key; make a slot's PIN
policy stricter; reset PIV; export a slot identity as an encrypted QR backup
(`docs/protocols/backup-piv.md`).

## 10. Limitations

* No retired key slots, no secure messaging / VCI, no pairing code, no
  biometric objects, no attestation (`F9`).
* No issuer-signed CHUID / security object: relying parties that require
  FIPS 201 card authentication of the CHUID signature will reject it.
* RSA 2048 key generation takes seconds on the device (keep-alive time
  extensions are sent); it requires `feuristic.core.rsa`.
* Private keys are **exportable through the device's encrypted QR backup**
  (spec §8.2); the device never claims them non-exportable. They are never
  readable over USB.
* `GET CHALLENGE` is not part of PIV; use the AES/RNG profile
  (`docs/protocols/aes-gcm-iso7816-v1.md` §9).
