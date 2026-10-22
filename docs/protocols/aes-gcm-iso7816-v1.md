---
title: AES-256-GCM and RNG over ISO 7816 APDUs
description: "Normative feuristic profile for AES-256-GCM encryption and hardware random bytes over ISO/IEC 7816 APDUs: key selection and session parameters."
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# feuristic AES-256-GCM / RNG cryptographic profile, version 1 (ISO/IEC 7816-8)

Status: **normative public annex** required by the product specification
§2.1 and §7 ("l'encodage complet de sélection des clés et des paramètres de
session doit être publié et versionné"). Implementation:
`src/feuristic/apps/card/aes/` (`applet.py`, `keys.py`, `rng.py`). Tests:
`tests/host/card/aes/` (the worked example of §11 is checked byte for byte).

This profile lets any PC/SC application encrypt and decrypt with AES-256-GCM
keys held by the device and read random bytes, using only standard
ISO/IEC 7816-4 / 7816-8 commands over USB CCID. No feuristic driver is
needed. As stated in spec §2.1, OpenSC/PKCS#11 does **not** expose this
profile; an application talks to it with raw APDUs (§12 gives a client).

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.
Hexadecimal bytes are written without prefix (`2A`), TLV lengths follow
ISO/IEC 7816-4 BER-TLV rules (`L < 80`: one byte; `81 LL`; `82 LL LL`).

## 1. Summary

| Item | Value |
|---|---|
| Transport | USB CCID (PC/SC), T=1-style APDU exchange, short or extended APDUs |
| AID | `F0 66 65 75 72 69 73 74 69 63 01` |
| Algorithm | AES-256-GCM only (NIST SP 800-38D), 96-bit nonce, 128-bit tag |
| Algorithm reference | `47` |
| Keys | 1..16, 256-bit, generated on the device only |
| Commands | SELECT, MANAGE SECURITY ENVIRONMENT (SET), PERFORM SECURITY OPERATION (ENCIPHER / DECIPHER), GET CHALLENGE |
| Max data per operation | plaintext/ciphertext ≤ 3584 bytes, AAD ≤ 256 bytes |
| Nonces | chosen by the device only, never repeated (§7) |
| User presence | on-device confirmation, per key policy (§4) |
| Random bytes | GET CHALLENGE, 1..32 bytes, no PIN, rate limited (§9) |

## 2. Transport

* The profile is one application of the feuristic virtual card (USB CCID
  interface of the "normal" USB mode, architecture §5). It coexists with
  OpenPGP Card and PIV; applications are selected by AID and never share keys.
* CLA MUST be `00` (`10` on non-final parts of a command chain). Secure
  messaging and logical channels are not supported (`6882`, `6881`).
* **Command chaining** (ISO/IEC 7816-4 §5.1.1.1): a host MAY split any
  command data field into parts with CLA `10` on all parts but the last. The
  card answers `9000` to intermediate parts. The de-chained data field is
  limited to 4096 bytes (`6700` beyond, on the offending part).
* **Response chaining**: when the response exceeds `Ne`, the card returns
  `61 xx` and the host fetches the rest with GET RESPONSE `00 C0 00 00 Le`.
  Extended-length APDUs (`Lc`/`Le` on 2 bytes) MAY be used instead.
* Operations are not "streams" in the cryptographic sense: one PSO is one
  complete GCM operation (spec §7: no claim of fast bulk encryption). Larger
  data MUST be split by the application into independent messages (each with
  its own nonce and tag), e.g. with a record sequence number in the AAD.

## 3. Application identifier and SELECT

`F0 66 65 75 72 69 73 74 69 63 01` = category `F` (proprietary AID, not
registered, ISO/IEC 7816-4 AID categories) ‖ ASCII `feuristic` ‖ profile
version `01`. A later incompatible profile gets a new last byte (§13).
Partial selection by any non-empty prefix is accepted.

Command: `00 A4 04 00 0B F066657572697374696301 00`

Response (`P2 = 00`), FCI:

```
6F 23
   84 0B F066657572697374696301     DF name (AID)
   A5 14                             proprietary information
      80 01 01                       profile version
      81 01 47                       algorithm reference (AES-256-GCM)
      82 02 0E00                     max plaintext/ciphertext bytes (3584)
      83 02 0100                     max AAD bytes (256)
      84 01 10                       number of key identifiers (16)
      85 01 20                       max GET CHALLENGE length (32)
9000
```

`P2 = 0C` returns no data. Clients SHOULD check `80 = 01` and the limits.

## 4. Key model and security policy

* Keys are identified by a **key identifier** `kid` in `1..16`. Each key has
  a name (1–16 printable ASCII characters), an *enabled* flag and a
  confirmation policy. Keys are created, named, disabled and deleted **on the
  device only** (menu "Cryptographie → AES"); there is no APDU to create,
  import or read a key. The key bytes leave the device only inside an
  encrypted QR backup armed from the device menu (spec §8.2,
  `docs/protocols/backup-aes.md`).
* Confirmation policy (per key, chosen on the device):
  * `0` — **every operation**: each ENCIPHER/DECIPHER shows a confirmation
    screen (operation, key id and name, data length, key check value) and
    waits for the two-button validation;
  * `1` — **once per session**: the first operation with that key after a
    card reset is confirmed; later operations with the same key are not. A
    card reset happens on device lock (5-minute inactivity, spec §9), USB
    re-enumeration and power loss. Any change to any AES key also ends the
    session.
  Refusal or timeout answers `6982` and has no other effect.
* **No AES-specific PIN.** Decision and reasoning: the AES keys are stored in
  the protected storage, which is only readable after the user unlocked the
  device with the device PIN on the device itself (spec §10.1), and the
  firmware resets the card (ending every session) when the device locks. A second PIN
  sent by the host (ISO VERIFY) would be typed on the host, i.e. exposed to
  exactly the malware it is supposed to stop, and would add no protection
  once that malware runs in the user's session. The protection against a
  compromised host is the **physical confirmation on the device screen**,
  which the host cannot forge. The "PIN selon politique" of spec F05 is
  therefore the device PIN gating the storage, combined with the
  per-key confirmation policy.
* A **disabled** key behaves like an absent key (`6A88`).
* The key check value shown on the device and in backups is
  `SHA-256("feuristic/aes-kcv" ‖ 00 ‖ key)[0..8]`, upper-case hex; it does not
  reveal the key.

## 5. MANAGE SECURITY ENVIRONMENT (SET)

`00 22 P1 B8 Lc <CRT> `, ISO/IEC 7816-4 §11.5.11:

| P1 | Meaning (ISO/IEC 7816-4 coding) | Environment set |
|---|---|---|
| `81` | SET for verification, **encipherment**, external authentication | encipher |
| `41` | SET for computation, **decipherment**, internal authentication | decipher |
| `F1` | SET for all of the above | encipher and decipher |

`P2 = B8`: control reference template for confidentiality (CT). Data field
(BER-TLV, any order, each tag at most once):

| Tag | Length | Value | Presence |
|---|---|---|---|
| `80` | 1 | algorithm reference `47` (AES-256-GCM) | optional (implicit `47`) |
| `83` | 1 | key identifier `01..10` | exactly one of `83` / `84` |
| `84` | 1 | key identifier `01..10` (accepted as a synonym of `83`) | |

Example (key 1, both directions): `00 22 F1 B8 06 800147 830101`.

The environment is volatile: it is cleared when another application is
selected, on card reset and whenever an AES key is modified on the device.
Errors: `6A86` (P1/P2), `6A80` (unknown/duplicate tag, bad length, other
algorithm reference, zero or two key references), `6A88` (key absent or
disabled).

## 6. PERFORM SECURITY OPERATION

### 6.1 ENCIPHER — `00 2A 84 80`

Command data (BER-TLV, any order, each at most once):

| Tag | Value | Presence |
|---|---|---|
| `81` | additional authenticated data (AAD), 0..256 bytes | optional (absent = empty) |
| `80` | plaintext, 0..3584 bytes | **mandatory** (may be empty: authentication only) |

Any other tag, in particular `82` (nonce) or `83` (tag), is rejected with
`6A80`: **the host never chooses an encryption nonce** (spec §7).

Response data, exactly in this order:

```
82 0C <nonce, 12 bytes>
80 L  <ciphertext, same length as the plaintext>
83 10 <GCM tag, 16 bytes>
```

`ciphertext ‖ tag` is the standard AES-256-GCM output (SP 800-38D) for
`key[kid]`, `nonce`, `AAD` and `plaintext`; any GCM implementation holding
the key (e.g. after a restore) decrypts it.

### 6.2 DECIPHER — `00 2A 80 84`

Command data (BER-TLV, any order, each at most once):

| Tag | Value | Presence |
|---|---|---|
| `81` | AAD, 0..256 bytes | optional |
| `82` | nonce, exactly 12 bytes | mandatory |
| `80` | ciphertext, 0..3584 bytes | mandatory |
| `83` | tag, exactly 16 bytes | mandatory |

Hence the DECIPHER data field is simply `[81 AAD] ‖ <ENCIPHER response>`.

Response data: the plaintext (raw bytes, no TLV), **only if the tag
verifies**. On tag mismatch the card answers `6988` with no data; no part of
the plaintext is ever released before (or without) successful tag
verification (spec §7). The confirmation (per policy) happens before the
decryption.

### 6.3 Preconditions and errors

* The corresponding environment MUST have been set by MSE (`6985` otherwise),
  and the key must still exist and be enabled (`6A88`).
* Length checks happen before the confirmation is shown: `6700` when the
  plaintext/ciphertext exceeds 3584 bytes or the AAD exceeds 256 bytes;
  `6A80` for malformed TLV, missing/duplicate/unknown tags or a nonce/tag of
  the wrong size.

## 7. Nonce construction

For every ENCIPHER the device builds the 96-bit nonce as

```
counter   = next value of the device-global 64-bit AES nonce counter
epoch     = uint32(counter >> 32), big-endian
index     = uint32(counter & 0xffffffff), big-endian
namespace = HKDF-SHA-256(IKM = device master secret, salt = "feuristic/v1",
                info = "card/aes-nonce-namespace" ‖ 00 ‖ key-record-uid ‖ epoch)[0..8]
nonce     = namespace (8 bytes) ‖ index (4 bytes)
```

* The counter is **global to all AES keys** of the device, strictly
  increasing, and **persisted before use**: values are reserved in flash in
  blocks of 256 in a power-loss-safe redundant counter (two copies; the
  value is the maximum; the stale copy is overwritten first). After a power
  cut allocation restarts at the end of the last reserved block, so a value
  is never handed out twice (at most 255 values are skipped). The counter is
  never reset, not even when all AES keys are deleted.
* The namespace separates devices, key records and counter epochs. The
  32-bit index never wraps within a namespace: crossing `2^32` selects the
  next epoch. Exhausting the 64-bit allocator refuses encryption; there is
  no silent reset. Restores also advance the counter past
  the source device's counter value recorded in the backup
  (`docs/protocols/backup-aes.md`).
* Within one key/device/epoch, index uniqueness follows from the persistent
  counter, including across power loss. HKDF namespaces have a residual
  collision probability of 2⁻⁶⁴ per pair of distinct device/key/epoch
  contexts. Across many contexts, account for the corresponding birthday
  bound. This is not an absolute uniqueness guarantee across clones;
  applications requiring that property SHOULD use the key on one device only.
* A refused or failed operation consumes no nonce value beyond the
  reservation granularity.

**Development hardening, 19 October 2026:** earlier development builds used
`legacy-prefix(4) || uint64(counter)`, with the separate KDF label
`card/aes-nonce-prefix`. New encryption uses the 64-bit namespace above.
DECIPHER accepts either construction as an opaque 12-byte nonce, so existing
ciphertexts remain usable. Key records, the 64-bit `nonce_floor`, backup item
v1 and every APDU field retain their encoding. The store's namespace cache
retains only the latest epoch per key and belongs to one device power session;
lock/master-secret replacement discards the store.

## 8. Limits

| Limit | Value | Reason |
|---|---|---|
| plaintext / ciphertext per PSO | 3584 bytes | one operation ≤ 3840 data bytes; every command fits the 4096-byte de-chained data limit |
| AAD per PSO | 256 bytes | |
| keys | 16 (`kid` 1..16) | storage budget (≤ 96 bytes per key record) |
| GET CHALLENGE | 1..32 bytes | spec §7 |
| GET CHALLENGE rate | ≤ 20 requests/s and ≤ 4096 bytes/s (burst: one second) | anti-abuse (spec §7) |

## 9. GET CHALLENGE (random bytes)

`00 84 00 00 Le`, ISO/IEC 7816-4 §11.6.3. Public function: no PIN, no
confirmation (spec §7). Answered when the AES profile is selected **and when
no application is selected** (card-level fallback); not answered while PIV
or OpenPGP is selected: OpenPGP Card implements its own GET CHALLENGE
(OpenPGP Card 3.4 §7.2.15), PIV does not (`6D00`).

* `Le` = `01`..`20`: returns exactly `Le` bytes.
* `Le` > `20`, including short `Le = 00` (= 256): `6C20` (retry with
  `Le = 20`).
* No `Le`, or a data field present: `6700`. `P1 P2` ≠ `00 00`: `6A86`.
* Rate limit exceeded: `6985` (nothing consumed; retry later). The limiter
  never affects AES, PIV or OpenPGP operations.
* RNG health failure: `6400`.

**Source and health tests.** Bytes come from the firmware DRBG fed by the
MCU TRNG and the secure element RNG (spec F06). Continuous health tests
adapted from NIST SP 800-90B §4.4 run on every delivered byte, treating each
output byte as an 8-bit sample with assessed entropy H = 8 and false-alarm
probability α = 2⁻⁴⁰:

* Repetition Count Test (§4.4.1): failure at **6** identical consecutive
  bytes (`C = 1 + ⌈40/8⌉`);
* Adaptive Proportion Test (§4.4.2): window **512** bytes, failure when the
  window's first byte occurs **19** times (`C = 1 + CRITBINOM(512, 2⁻⁸, 1 − 2⁻⁴⁰)`);
* start-up test (§4.3): 1024 bytes drawn, tested and discarded before the
  first output of each power session.

These tests detect catastrophic failures (stuck or looping source); they do
not replace the entropy-source assessment of the hardware. A failure is
latched: every request answers `6400` until the user runs the self-test again
from "Cryptographie → Aléa → État" and it passes. The same health-checked
RNG generates AES keys (key creation is refused while the RNG has failed).
The menu shows the state, bytes tested/delivered, request count, failure
counts per test, the last failure and the number of rate-limited requests.

## 10. Status words

| SW | Meaning in this profile |
|---|---|
| `9000` | success |
| `61xx` | more response data: send GET RESPONSE |
| `6400` | RNG health tests failed (GET CHALLENGE, key creation) |
| `6581` | stored key record corrupted |
| `6700` | wrong length: data over the limits, de-chained data > 4096 bytes, GET CHALLENGE without `Le` or with data |
| `6881` / `6882` | logical channel / secure messaging not supported |
| `6982` | operation refused (or timed out) on the device |
| `6985` | no security environment for this direction; GET CHALLENGE rate limit exceeded |
| `6988` | **GCM tag verification failed** — no plaintext released |
| `6A80` | malformed data field (TLV, tags, sizes, host-supplied nonce on ENCIPHER, wrong algorithm reference) |
| `6A84` | storage full |
| `6A86` | wrong P1/P2 |
| `6A88` | key identifier absent or disabled |
| `6C20` | GET CHALLENGE `Le` > 32 |
| `6D00` | instruction not supported |
| `6E00` | class not supported |
| `6F00` | internal error |

`6988` was chosen for tag failures because it is the ISO/IEC 7816-4 class-69
code for an integrity check failure of protected data, distinct from a
malformed command (`6A80`).

## 11. Worked example

Assumptions (illustration only): key 1 = `000102…1F`, the device's nonce
namespace for that key is `A1B2C3D400000000`, the global counter is at 0 (fresh device),
AAD = `"hdr"`, plaintext = `"hello"`, policy "every operation".

```
→ 00 A4 04 00 0B F066657572697374696301 00
← 6F23840BF066657572697374696301A51480010181014782020E0083020100840110850120 9000

→ 00 22 81 B8 06 800147 830101                     MSE SET encipher, key 1
← 9000

→ 00 2A 84 80 0C 8103686472 800568656C6C6F 00      ENCIPHER {81 "hdr", 80 "hello"}
   (device shows "Encrypt with AES key? #1 example, 5 bytes"; user confirms)
← 820CA1B2C3D40000000000000000                     nonce
  8005EA665984F3                                   ciphertext
  8310D8CB40C46592B03474A27763BA1BED2A             tag
  9000

→ 00 22 41 B8 06 800147 830101                     MSE SET decipher, key 1
← 9000

→ 00 2A 80 84 2C 8103686472 820CA1B2C3D40000000000000000 8005EA665984F3
                 8310D8CB40C46592B03474A27763BA1BED2A 00
← 68656C6C6F 9000                                  "hello"

→ same with the last tag byte changed to 2B
← 6988                                             no data

→ 00 84 00 00 20                                   GET CHALLENGE 32
← <32 random bytes> 9000
→ 00 84 00 00 00                                   Le = 256
← 6C20
```

## 12. Python client (pyscard)

```python
# SPDX-License-Identifier: GPL-3.0-only
"""Minimal client for the feuristic AES-256-GCM profile v1 (pyscard)."""
from smartcard.System import readers

AID = bytes.fromhex("F066657572697374696301")


def tlv(tag: int, value: bytes) -> bytes:
    n = len(value)
    head = bytes([n]) if n < 0x80 else bytes([0x81, n]) if n < 0x100 else bytes([0x82]) + n.to_bytes(2, "big")
    return bytes([tag]) + head + value


def parse_tlv(data: bytes) -> dict:
    out, i = {}, 0
    while i < len(data):
        tag, n = data[i], data[i + 1]
        i += 2
        if n == 0x81:
            n, i = data[i], i + 1
        elif n == 0x82:
            n, i = int.from_bytes(data[i:i + 2], "big"), i + 2
        out[tag] = data[i:i + n]
        i += n
    return out


class FeuristicAes:
    def __init__(self, reader_index: int = 0):
        self.conn = readers()[reader_index].createConnection()
        self.conn.connect()

    def transmit(self, ins: int, p1: int, p2: int, data: bytes = b"", le: bool = True) -> bytes:
        parts = [data[i:i + 255] for i in range(0, len(data), 255)] or [b""]
        for k, part in enumerate(parts):
            last = k == len(parts) - 1
            apdu = [0x00 if last else 0x10, ins, p1, p2]
            if part:
                apdu += [len(part)] + list(part)
            if last and le:
                apdu += [0x00]
            resp, sw1, sw2 = self.conn.transmit(apdu)
            if not last and (sw1, sw2) != (0x90, 0x00):
                raise IOError(f"chaining failed: {sw1:02X}{sw2:02X}")
        out = bytes(resp)
        while sw1 == 0x61:  # response chaining
            resp, sw1, sw2 = self.conn.transmit([0x00, 0xC0, 0x00, 0x00, sw2])
            out += bytes(resp)
        if (sw1, sw2) != (0x90, 0x00):
            raise IOError(f"card error {sw1:02X}{sw2:02X}")
        return out

    def select(self) -> dict:
        fci = parse_tlv(parse_tlv(self.transmit(0xA4, 0x04, 0x00, AID))[0x6F])
        info = parse_tlv(fci[0xA5])
        assert info[0x80] == b"\x01", "unsupported profile version"
        return info

    def encrypt(self, kid: int, plaintext: bytes, aad: bytes = b"") -> tuple:
        self.transmit(0x22, 0x81, 0xB8, tlv(0x80, b"\x47") + tlv(0x83, bytes([kid])), le=False)
        data = (tlv(0x81, aad) if aad else b"") + tlv(0x80, plaintext)
        r = parse_tlv(self.transmit(0x2A, 0x84, 0x80, data))
        return r[0x82], r[0x80], r[0x83]  # nonce, ciphertext, tag

    def decrypt(self, kid: int, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
        self.transmit(0x22, 0x41, 0xB8, tlv(0x80, b"\x47") + tlv(0x83, bytes([kid])), le=False)
        data = (tlv(0x81, aad) if aad else b"") + tlv(0x82, nonce) + tlv(0x80, ciphertext) + tlv(0x83, tag)
        return self.transmit(0x2A, 0x80, 0x84, data)  # raises on 6988 (bad tag)

    def random(self, n: int = 32) -> bytes:
        resp, sw1, sw2 = self.conn.transmit([0x00, 0x84, 0x00, 0x00, n])
        if (sw1, sw2) != (0x90, 0x00):
            raise IOError(f"GET CHALLENGE {sw1:02X}{sw2:02X}")
        return bytes(resp)


if __name__ == "__main__":
    card = FeuristicAes()
    print("limits:", card.select())
    nonce, ct, tag = card.encrypt(1, b"hello", b"hdr")   # confirm on the device
    print(card.decrypt(1, nonce, ct, tag, b"hdr"))
    print(card.random(32).hex())
```

`opensc-tool -s 00A404000BF066657572697374696301 -s 0084000020` reads random
bytes with stock tools.

## 13. Versioning policy

* This document describes **profile version 1** (AID last byte `01`, FCI tag
  `80` = `01`). Within version 1 the card MAY add FCI proprietary tags and
  MAY raise the limits advertised in the FCI; clients MUST ignore unknown FCI
  tags and MUST respect the advertised limits.
* Any change that alters the meaning of an existing command, tag or status
  word, adds a mandatory field, or changes the 96-bit nonce wire encoding creates
  **version 2** with a new AID (`…63 02`); the firmware MAY then offer both
  versions side by side.
* Internal nonce-allocation hardening MAY retain version 1 when the nonce
  remains an opaque 12-byte value and every existing ciphertext and backup
  remains usable. Such changes MUST be documented with their security bounds
  and migration evidence, as for the pre-release hardening in §7.
* New algorithms would get new algorithm references (tag `80` in MSE);
  reference `47` always means AES-256-GCM with 96-bit nonces and 128-bit tags.

## 14. Security considerations

* A compromised host can use a key only with the user's on-device
  confirmation (or, with the "once per session" policy, during a session the
  user opened). Choose "every operation" for high-value keys.
* The device never reveals key bytes over USB; GCM tag failures release
  nothing. Decryption oracles are limited by the confirmation policy.
* GET CHALLENGE output is public randomness; it is rate limited so a host
  cannot monopolise the RNG, and it is refused when the health tests fail.
* Ciphertexts produced under this profile are standard AES-256-GCM: their
  security depends on nonce uniqueness, guaranteed by §7 for device-side
  encryption. Ciphertexts produced elsewhere with a restored key are outside
  the device's control.
