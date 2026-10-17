<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# OpenPGP Card application (v3.4)

Status: **normative** for feuristic v0.x. Implementation:
`src/feuristic/apps/card/openpgp/`. Requirements: product spec F03, §6.1,
§6.3, §8.2, §10; acceptance test R09 (GnuPG without trezor-agent).
Reference: *Functional Specification of the OpenPGP application on ISO
Smart Card Operating Systems*, version 3.4.1.

## 1. Identity of the card

AID (16 bytes):

```
D2 76 00 01 24 | 01 | 03 04 | FF 7E | s s s s | 00 00
RID            | app| v3.4  | manuf.| serial  | RFU
```

* **Manufacturer `FF7E`** is in the range `FF00–FFFE` that the
  specification reserves for randomly assigned serial numbers. GnuPG shows
  it as *unmanaged S/N range*. feuristic never uses a real vendor ID.
* **Serial number**: `HKDF(MS, "card/serial", context "openpgp")[:4]`
  (`core.kdf`). It is stable per device, unlinkable across devices and
  never `00000000`/`FFFFFFFF`. A restored backup does not change the
  serial.

Historical bytes, ATR and reader behaviour: see `docs/protocols/ccid.md`.
Extended Lc/Le and command chaining are advertised.

## 2. Algorithms and attributes

| Role | Default | Attribute bytes (C1/C2/C3) |
|---|---|---|
| Signature (C1) | EdDSA Ed25519 | `16 2B 06 01 04 01 DA 47 0F 01` |
| Decryption (C2) | ECDH Curve25519 | `12 2B 06 01 04 01 97 55 01 05 01` |
| Authentication (C3) | EdDSA Ed25519 | `16 2B 06 01 04 01 DA 47 0F 01` |
| any (compatibility, optional) | RSA-2048, e = 65537 | `01 08 00 00 20 00` (stored canonically; on write, any e-length 17–32 and format 0–3 is accepted) |

* RSA is accepted only when `feuristic.core.rsa` is present
  (`keys.rsa_available()`). RSA key generation is incremental and
  asynchronous; the glue keeps the host alive with CCID time extensions.
* `FA` (algorithm information) lists the supported attributes.
* An attribute with a trailing `FF` (import format) is accepted and stored
  canonically.

Public keys in `7F49`, as GnuPG's scdaemon expects from 3.x cards
(`app-openpgp.c`, `ecc_read_pubkey`):

* **ECC**: `86` carries the raw 32-byte key, **without the `0x40`
  prefix**. For Ed25519 that is the point; for X25519 the u-coordinate in
  native little-endian order. GnuPG adds the prefix itself for curves
  flagged with the DJB tweak.
* **RSA**: `81` = n (256 bytes), `82` = e (`01 00 01`).

## 3. Command support

| INS | Command | Support |
|---|---|---|
| A4 | SELECT | Through the dispatcher. `6285` when terminated. |
| A5 | SELECT DATA | `P2=04`, data `60 04 5C 02 7F 21`. Only occurrence 0 exists (`6A88` otherwise). |
| CA | GET DATA | See §4. |
| CC | GET NEXT DATA | `6D00` (one certificate only). |
| DA | PUT DATA | See §4. |
| DB | PUT DATA (odd, key import `4D`) | **`6A81` always**. Keys are generated and managed on the device (spec §6.1/§6.2); they move only through the encrypted QR backup. |
| 20 | VERIFY | P2 `81`/`82`/`83`. `Lc` absent: status (`9000` or `63Cx`). `P1=FF`: reset access status. |
| 24 | CHANGE REFERENCE DATA | P2 `81`/`83`; data = old ‖ new. The split uses the stored length of the old PIN. |
| 2C | RESET RETRY COUNTER | `P1=00`: resetting code ‖ new PW1. `P1=02`: PW3 verified, new PW1. |
| 47 | GENERATE ASYMMETRIC KEY PAIR | `P1=80` (PW3 + device confirmation) / `81` (read). CRT `B6 00`/`B8 00`/`A4 00`, optionally `84 01 xx`. |
| 2A 9E9A | PSO: COMPUTE DIGITAL SIGNATURE | PW1(81). EdDSA over the data received; RSA PKCS#1 v1.5 over a DigestInfo (≤ 102 bytes). |
| 2A 8086 | PSO: DECIPHER | PW1(82). X25519: `A6{7F49{86 point}}` (32 bytes, or 33 with `40`) → 32-byte shared secret. RSA: `00` ‖ 256-byte cryptogram → PKCS#1 v1.5 unpadded. |
| 2A 8680 | PSO: ENCIPHER (AES) | `6A81` |
| 88 | INTERNAL AUTHENTICATE | PW1(82), authentication key (EdDSA / RSA PKCS#1 v1.5). |
| 84 | GET CHALLENGE | 1–32 bytes (spec §7). `Le` absent or > 32 → `6700`. |
| E6 | TERMINATE DF | PW3 verified **or PW3 blocked**, plus a DANGER confirmation on the device. |
| 44 | ACTIVATE FILE | Terminated → fresh identity (default PINs, counters 3); otherwise a no-op. |
| 22 | MSE | `6D00` |

In the terminated state only SELECT (`6285`) and ACTIVATE FILE are
accepted; everything else returns `6985`. CLA must be `00` (`6E00`
otherwise). Unknown INS → `6D00`.

## 4. Data objects

| Tag | GET | PUT (access) | Notes |
|---|---|---|---|
| 4F | ✓ | – | AID |
| 5E | ✓ | PW3 | login data ≤ 254 |
| 5F50 | ✓ | PW3 | URL ≤ 254 |
| 5F52 | ✓ | – | historical bytes |
| 65 | ✓ (wrapped in `65`) | – | `5B` name ≤ 39, `5F2D` language ≤ 8, `5F35` sex `0`/`1`/`2`/`9` (each PUT with PW3, also readable directly) |
| 6E | ✓ (wrapped in `6E`) | – | `4F`, `5F52`, `7F74`, `7F66`, `73{C0 C1 C2 C3 C4 C5 C6 CD DE D6 D7 D8}` |
| 7A | ✓ (wrapped) | – | `93`: 3-byte digital signature counter |
| 7F21 | ✓ (raw) | PW3 | cardholder certificate ≤ 2048 |
| 7F66 | ✓ (content) | – | `02 02 10 00 02 02 10 00`: 4096 / 4096 |
| 7F74 | ✓ | – | `81 01 A0`: display + button |
| C0 | ✓ | – | `5C 00 00 20 08 00 00 FE 00 00` |
| C1–C3 | ✓ | PW3 | algorithm attributes (§2). Changing the algorithm of a slot holding a key destroys the key after a DANGER confirmation. |
| C4 | ✓ | PW3 (1 byte) | `pw1_status 7F 7F 7F tries(PW1) tries(RC) tries(PW3)` |
| C5 / C7–C9 | ✓ | PW3 (20 bytes each) | fingerprints |
| C6 / CA–CC | ✓ | PW3 | CA fingerprints |
| CD / CE–D0 | ✓ | PW3 (4 bytes each) | generation dates |
| D3 | – | PW3 | resetting code: empty = remove, else 8–127 bytes |
| D6–D8 | ✓ `02 20` | PW3 | UIF *permanently enabled* (every operation is confirmed on the device). Writing `01`/`02` → no-op; `00` → `6985`. |
| DE | ✓ | – | key information: `01 o 02 o 03 o` (0 none, 1 generated, 2 imported) |
| FA | ✓ (wrapped) | – | algorithm information |
| 0101 / 0102 | ✓ | PW1(82) / PW3 | private DOs ≤ 254 |
| 0103 / 0104 | PW1(82) / PW3 | PW1(82) / PW3 | private DOs ≤ 254 |
| F9 (KDF-DO), D5 (AES) | `6A88` | `6A81` | not supported |

Unknown or read-only tag in PUT DATA → `6A88`. Length violation → `6700`;
invalid value → `6A80`; storage exhausted → `6A84` (nothing changed).

Extended capabilities (`C0` byte 1 = `5C`): GET CHALLENGE, PW status
changeable, private DOs, algorithm attributes changeable. No SM, **no key
import**, no AES, no KDF-DO, no MSE.

## 5. PINs

| PIN | Default | Length | Tries |
|---|---|---|---|
| PW1 (user) | `123456` | 6–127 | 3 |
| PW3 (admin) | `12345678` | 8–127 | 3 |
| Resetting code | not set | 8–127 | 3 (0 when not set) |

* **Stored as references**:
  `PBKDF2-HMAC-SHA256(pin, "feuristic/openpgp/pin\0" ‖ salt16, 1000)`, plus
  the PIN length. The length is needed to split CHANGE REFERENCE DATA and
  RESET RETRY COUNTER data. Comparison is constant time (`ct_equal`). The
  record itself is encrypted by the protected storage.
* **Tries are consumed before the comparison** and persisted
  power-loss-safely; a success restores them. A PIN whose length is
  outside the public bounds is rejected with `6A80` **without** consuming
  a try, which leaks nothing because the bounds are public.
* Wrong PIN → `63Cx` (x = tries left). Blocked → `6983`. A failed VERIFY
  also clears that PIN's access status.
* PW1 status byte default is **`01`** (several signatures per
  verification), because each signature is confirmed on the device anyway.
  With `00`, PW1(81) is valid for one PSO:CDS.
* Access status is volatile: card reset, power-off and selecting another
  application clear it. Re-SELECT of OpenPGP keeps it, because GnuPG
  re-selects frequently.
* The device menu can set or unblock any PIN locally (§8).

## 6. Physical confirmation (spec §6.3, §10.10)

Prompts are `core.interaction.Prompt` objects. Labels are i18n keys from
`openpgp/strings.py` (EN/FR).

| Operation | kind | severity | fields |
|---|---|---|---|
| PSO:CDS | `openpgp.sign` | SENSITIVE | type (EdDSA / RSA PKCS#1 v1.5), key role, algorithm, *Signature d'empreinte non interprétée* = hex of the data (SHA-256 if > 64 bytes); `fingerprint` = 40-hex v4 fingerprint from C5 (if unset: SHA-256 of the public key as a field) |
| PSO:DECIPHER | `openpgp.decrypt` | SENSITIVE | type, role *Déchiffrement*, algorithm, SHA-256 of the input |
| INTERNAL AUTHENTICATE | `openpgp.auth` | SENSITIVE | type, role *Authentification*, algorithm, data hex |
| GENERATE (host) | `openpgp.generate` | SENSITIVE (DANGER when replacing a key) | role, algorithm, warning |
| PUT C1–C3 destroying a key | `openpgp.attr_change` | DANGER | role, old > new algorithm, warning |
| TERMINATE DF | `openpgp.terminate` | DANGER | warning |

**Refusal or timeout → `6985`** (conditions of use not satisfied). GnuPG
maps it to `GPG_ERR_USE_CONDITIONS` and keeps its cached PIN. `6982`
would be reported as a bad PIN and make gpg-agent forget or re-ask the
PIN. (`6600`, GnuPG's "ack timeout", was considered but is
YubiKey/Gnuk-specific.)

The digital signature counter is incremented after the confirmation and
before the signature is released. A refused signature is not counted.

## 7. Storage

* Namespace `CARD` (protected) uses keys `0x00–0x03` of OpenPGP's range
  `0x00–0x0F`: one `RecordStore` of capacity 3.
  * Identity record (≤ 1536 B canonical CBOR): keys, attributes,
    fingerprints, CA fingerprints, dates, origins, name, language, sex,
    PIN references, PW1 status byte, signature counter base, life cycle.
  * Two alternating aux records (≤ 3712 B): URL, login, private DOs,
    certificate.

  Updates write the new aux record under the free uid, then atomically
  replace the identity record that references it, then delete the old aux
  record. Every power cut leaves either the old pair or the new pair
  visible; an orphan aux record is collected at load.
* Namespace `CARD_COUNTERS` (public), keys `0x10–0x1F` (PIV uses
  `0x20–0x2F`, AES `0x00–0x01`). All are `RedundantCounter` pairs and
  monotonic:

  | Keys | Content |
  |---|---|
  | `10/11` | PW1 failures |
  | `12/13` | PW1 OK-mark |
  | `14–17` | PW3 failures / OK-mark |
  | `18–1B` | resetting code failures / OK-mark |
  | `1C/1D` | digital signature counter |
  | `1E/1F` | reserved |

  Tries left = 3 − (fail − OK-mark). The counter shown =
  counter − base, where the base is stored in the identity record; it is
  reset when a new signature key is generated.
* On first use (no identity record) the defaults are used in memory and
  persisted at the first change. Try counters are never cleared by a
  reboot.

## 8. Device menu (`openpgp/localmgmt.py`)

| Function | Menu (spec §9) |
|---|---|
| `generate_keys(store, profile, created)` | OpenPGP → générer. Profiles `ed25519` (Ed25519/Cv25519/Ed25519) or `rsa2048`. `created` = synchronised session time, otherwise show `openpgp.time_required`. Computes OpenPGP v4 fingerprints exactly as GnuPG does (cv25519 KDF params `03 01 08 07`), so `gpg --full-generate-key` → *Existing key from card* gives matching fingerprints. |
| `status(store)` | OpenPGP → voir (algorithms, fingerprints, dates, tries, signature count) |
| `delete_keys(store, roles)` | OpenPGP → supprimer |
| `set_pin(store, which, pin)`, `unblock(store, which)` | PIN management on the device |
| `factory_reset(store)` | reset to factory state |
| backup provider (§9) | OpenPGP → exporter QR |

The UI shows its own confirmation screens before calling these functions.
Local changes bump `store.epoch`, so the applet drops the host's PIN
verification.

## 9. Backup

`openpgp/provider.py`, `TYPE = "openpgp"`. Schema:
`docs/protocols/backup-openpgp.md`.

## 10. Using it with GnuPG

* `gpg --card-status`: shows *Version 3.4*, *unmanaged S/N range*, key
  attributes `ed25519 cv25519 ed25519` and *UIF … permanent*.
* `gpg --card-edit` → `admin` → `generate`: GnuPG's normal flow. PW3, then
  GENERATE ×3, each confirmed on the device; GnuPG writes fingerprints and
  dates with PUT DATA. Keys generated in the device menu can be used with
  `gpg --full-generate-key` → *Existing key from card*.
* `passwd` (PW1/PW3/resetting code), `name`, `url`, `login`, `forcesig`,
  `key-attr` and `factory-reset` work as on other 3.4 cards.
  `keytocard` is refused (no key import).
* `scdaemon.conf`:

  ```
  pcsc-shared        # share the reader with OpenSC (PIV) and other PC/SC clients
  disable-ccid       # recommended on macOS; use pcscd/CryptoTokenKit, not the internal CCID driver
  ```

  With `pcsc-shared`, a PIV client selecting its application resets the
  OpenPGP PIN state; GnuPG asks for the PIN again when needed.
* Linux: the reader's VID/PID may need to be added to libccid's
  `Info.plist` (see `docs/protocols/ccid.md` §8).

## 11. Limitations

* One certificate (occurrence 0 of 7F21); no SELECT DATA for others.
* No key import, SM, KDF-DO, AES, attestation or MSE (key role swapping).
* RSA-2048 only, and only with `feuristic.core.rsa`.
* Interoperability with GnuPG is **not yet validated** on hardware or the
  emulator (R09 pending; `tests/host/card/openpgp/test_interop_gnupg.py`
  is a skeleton).
