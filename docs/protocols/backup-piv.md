<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Backup item schema: PIV slot identities (`type = "piv"`, `v = 1`)

Status: **normative** for feuristic v0.x. Implementation:
`src/feuristic/apps/card/piv/provider.py` (`PivBackupProvider`). Product
requirements: spec §8.2, §8.3. Tests: `tests/host/card/piv/test_provider.py`.

This document defines the identity item that the PIV application gives to
the backup envelope; encryption, KDF, framing and the item container are
defined by `docs/protocols/backup-format-v1.md`. **One item describes one
PIV key slot** (`9A`, `9C`, `9D` or `9E`) that holds a private key, together
with its certificate. Items are encoded in canonical CBOR (RFC 8949 §4.2.1)
by the backup core.

## 1. CDDL (RFC 8610)

```cddl
piv-identity = piv-p256 / piv-rsa2048

piv-common = (
  "v": 1,
  "type": "piv",
  "slot": 0x9A / 0x9C / 0x9D / 0x9E,
  "pin_policy": 1 / 2 / 3,            ; 1 never, 2 once per session, 3 every use
  ? (
    "cert": bstr .size (1..2048),      ; content of PIV tag 70 (DER X.509, or gzip)
    "certinfo": 0 / 1,                 ; PIV CertInfo (tag 71): 1 = gzip-compressed
  ),
)

piv-p256 = {
  piv-common,
  "alg": 0x11,                         ; SP 800-78-4: ECC P-256
  "sk": bstr .size 32,                 ; secret scalar d, big-endian, 1 <= d < n
}

piv-rsa2048 = {
  piv-common,
  "alg": 0x07,                         ; SP 800-78-4: RSA 2048
  "p": bstr .size 128,                 ; prime factors, big-endian, top bit set
  "q": bstr .size 128,
  "e": 65537,
}
```

Field order in this listing is irrelevant: canonical CBOR orders map keys.

## 2. Semantics

* `uid` used by the backup core: `"PIVslot" ‖ slot` (8 bytes); label
  `PIV <slot> <role>` (e.g. `PIV 9C Digital Signature`, in the device
  language).
* `describe()` fingerprint: the first 8 bytes of SHA-256 over the
  SubjectPublicKeyInfo DER of the public key, upper-case hex — the same value
  as in the PIV signature prompt (`docs/protocols/piv.md` §6.1).
* Slots holding only a certificate (no private key) are **not** exported
  (nothing secret; the certificate can be re-imported with PUT DATA).
* **Not exported**: PIN, PUK, administration key, CHUID, CCC, Printed
  Information, Security Object. The restoring device keeps its own
  credentials and generated objects (spec §8.3: a backup is independent of
  the device; note that the CHUID GUID — used by some middleware as the card
  identity — therefore changes after a restore on another device).

## 3. Validation (before anything is written)

A restored item is rejected (`InvalidInput`) unless all of the following
hold, even though the envelope is authenticated:

* exactly the keys of one variant above (no unknown or missing key);
  `cert` and `certinfo` both present or both absent;
* integers are CBOR integers (not booleans) and in range;
* `pin_policy` is not weaker than the product default of the slot
  (`9A`: once, `9C`: every use, `9D`: once, `9E`: never);
* P-256: `sk` is a valid scalar (`1 ≤ d < n`);
* RSA: `p ≠ q`, both odd with their top bit set, `n = p·q` is 2048 bits,
  `e = 65537` (primality is not re-tested: the item is authenticated);
* the encoded slot record fits the 2400-byte record cap.

## 4. Restore

* `exists(item)`: the slot currently holds a key **or** a certificate. The
  backup UI then shows the current identity (`describe`) and asks for the
  specific overwrite confirmation; without it `restore_identity` raises
  `PolicyDenied` and writes nothing.
* The slot record (key + certificate + policy) is written in **one**
  copy-on-write record update: after a power cut either the previous slot
  content or the complete restored identity is present (spec §3.3, §10.6).
* Restored keys carry origin "imported" (GET METADATA tag `03` = `02`).

## 5. Example (diagnostic notation, RFC 8949 §8)

```
{"v": 1, "alg": 17, "slot": 156, "type": "piv", "pin_policy": 3,
 "sk": h'1111…11', "cert": h'3082…', "certinfo": 0}
```
