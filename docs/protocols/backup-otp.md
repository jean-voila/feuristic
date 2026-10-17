<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Backup item schema: OTP accounts (`type = "otp"`, `v = 1`)

Status: **normative** for feuristic v0.x. Implementation:
`src/feuristic/apps/otp/provider.py` (`OtpBackupProvider`). Product
requirements: spec §8.2, §8.3.

This document defines the identity item that the OTP application gives to
the backup envelope. Encryption, KDF, framing and the item container are
defined by the backup format (`docs/protocols/backup-format-v1.md`). One
item describes one TOTP or HOTP account. Items are encoded in **canonical
CBOR** (RFC 8949 §4.2.1) by the backup core.

## 1. CDDL (RFC 8610)

```cddl
otp-identity = otp-totp / otp-hotp

otp-common = (
  "v": 1,
  "type": "otp",
  "issuer": tstr .size (0..32),        ; UTF-8 bytes; may be empty
  "account": tstr .size (1..64),       ; UTF-8 bytes
  "secret": bstr .size (1..64),        ; raw HMAC key (not base32)
  "algorithm": "SHA1" / "SHA256" / "SHA512",
  "digits": 6 / 7 / 8,
)

otp-totp = {
  otp-common,
  "kind": "totp",
  "period": 15..300,                   ; seconds, RFC 6238 time step X (T0 = 0)
}

otp-hotp = {
  otp-common,
  "kind": "hotp",
  "counter": 0..18446744073709551615,  ; next unused RFC 4226 moving factor
}
```

Extra constraints, which CDDL cannot express and which the device checks:

* No other key may be present. A TOTP item MUST NOT carry `counter` and an
  HOTP item MUST NOT carry `period`.
* `issuer` and `account` follow the text rules of `docs/protocols/otpauth.md`
  §3: valid UTF-8, no control, bidirectional-override or zero-width
  characters, no `:`, no leading or trailing space.
* Integers are not booleans (CBOR `true`/`false` are refused).

## 2. Example (diagnostic notation)

```
{"v": 1, "kind": "hotp", "type": "otp", "digits": 6, "issuer": "Corp",
 "secret": h'3132333435363738393031323334353637383930', "account": "bob",
 "counter": 42, "algorithm": "SHA1"}
```

In canonical CBOR, map keys are sorted by their encoded bytes: shorter keys
come first, then bytewise order. The order is therefore
`"v"`, `"kind"`, `"type"`, `"digits"`, `"issuer"`, `"secret"`, `"account"`,
`"counter"`, `"algorithm"` for HOTP, and `"v"`, `"kind"`, `"type"`,
`"digits"`, `"issuer"`, `"period"`, `"secret"`, `"account"`, `"algorithm"`
for TOTP.

## 3. Provider behaviour

| Method | Behaviour |
|---|---|
| `list_identities()` | `[(uid, label)]` where `uid` is the 8-byte record uid and `label` is `"Issuer: account"`, or just `account` when there is no issuer. Sorted by issuer, then account |
| `export_identity(uid)` | The item above. HOTP `counter` = `counter_base + persisted increments`, the next value the device would use |
| `validate(obj)` | Common item checks, then the rules of §1. Raises `InvalidInput` |
| `exists(obj)` | True if an account with the same `issuer` **and** `account` exists |
| `describe(obj)` | `(label, fingerprint)`. `fingerprint` = first 8 bytes of `SHA-256(secret)` as 16 lower-case hex characters, shown before overwriting (spec §8.2) |
| `restore_identity(obj, overwrite)` | New account, or atomic copy-on-write replacement of the account with the same issuer + account. If such an account exists and `overwrite` is false, raises `PolicyDenied` (`AlreadyExists`) and writes nothing. Raises `StorageFull` at 32 accounts unless replacing |
| `on_exported(uid)` | No-op |

### 3.1 HOTP counter safety

When an item overwrites an HOTP account that holds the **same secret**,
the stored moving factor becomes `max(item.counter, current)`. Restoring an
old backup can therefore never make the device show an HOTP value it
already showed. With a different secret, the item's counter is used as is.

### 3.2 Fingerprint note

The fingerprint is a truncated hash of the secret. It is displayed only on
the device screen. For very weak secrets (a few bytes) it could help an
observer brute-force the secret, which is why the import screen warns
about secrets under 80 bits.
