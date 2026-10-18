<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Backup item schema: AES-256-GCM keys (`type = "aes"`, `v = 1`)

Status: **normative** for feuristic v0.x. Implementation:
`src/feuristic/apps/card/aes/provider.py` (`AesBackupProvider`). Product
requirements: spec §7, §8.2, §8.3; R12. Tests:
`tests/host/card/aes/test_provider.py`.

One item describes one AES key of the ISO/IEC 7816-8 profile
(`docs/protocols/aes-gcm-iso7816-v1.md`). Encryption, KDF, framing and the
item container are defined by `docs/protocols/backup-format-v1.md`; the item
is encoded in canonical CBOR by the backup core.

## 1. CDDL (RFC 8610)

```cddl
aes-identity = {
  "v": 1,
  "type": "aes",
  "id": 1..16,                          ; key identifier used in MSE (tag 83/84)
  "name": tstr .size (1..16),           ; printable ASCII (0x20..0x7E)
  "key": bstr .size 32,                 ; AES-256 key
  "enabled": bool,
  "policy": 0 / 1,                      ; 0 confirm every operation, 1 once per session
  "nonce_floor": 0..18446744073709551615,
}
```

## 2. Semantics

* `uid` used by the backup core: `"AESkey" ‖ 00 ‖ id` (8 bytes); label
  `AES #<id> <name>`.
* `describe()` fingerprint: the key check value
  `SHA-256("feuristic/aes-kcv" ‖ 00 ‖ key)[0..8]`, upper-case hex (the value
  shown in the AES menus and prompts); it does not reveal the key.
* `nonce_floor`: the source device's global AES nonce counter at export
  time, i.e. an upper bound (exclusive) of every counter value that device
  had reserved. On restore the destination device advances its own counter
  to at least this value **before** storing the key, and restarts its
  allocation from the persisted counter, so the restored key never encrypts
  with a counter value used before the backup on the source device. Nonces
  also contain a 4-byte prefix derived from the destination device's master
  secret and key record, which separates devices; the residual collision
  probability when one key is used on two devices is that of two 32-bit
  prefixes (2⁻³²), see the annex §7.
* The record uid (which feeds the nonce prefix) is *not* exported: a new
  key gets a fresh random uid, an overwritten key keeps the uid of the
  record it replaces.

## 3. Validation

Rejected (`InvalidInput`, nothing written) unless: exactly the eight keys
above; `v` = 1 (integer, not boolean); `id` 1..16; `name` 1..16 printable
ASCII characters; `key` 32 bytes; `enabled` a boolean; `policy` 0 or 1;
`nonce_floor` an unsigned 64-bit integer (not boolean).

## 4. Restore

* `exists(item)`: a key with the same `id` exists. Overwriting requires the
  specific confirmation of the backup UI; otherwise `PolicyDenied`.
* Order: (1) raise the nonce counter to `nonce_floor` (power-loss safe,
  monotonic); (2) write the key record in one copy-on-write update (same
  record uid when replacing). A power cut after (1) leaves the counter
  higher and the key absent or unchanged; never a partial key.
* Restoring an older backup never lowers the counter.

## 5. Example (diagnostic notation)

```
{"v": 1, "id": 3, "key": h'4242…42', "name": "vault", "type": "aes",
 "policy": 0, "enabled": true, "nonce_floor": 1792}
```
