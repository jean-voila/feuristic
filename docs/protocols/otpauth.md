---
title: "otpauth:// URIs for TOTP and HOTP"
description: "The subset of Google Authenticator otpauth:// URIs that feuristic imports from QR images and exports for TOTP and HOTP accounts, with limits."
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# `otpauth://` URIs accepted and produced by feuristic

Status: **normative** for feuristic v0.x. Implementation:
`src/feuristic/apps/otp/uri.py` (codec), `src/feuristic/core/base32.py`,
`src/feuristic/apps/otp/hotp.py`, `totp.py` and `accounts.py`. Product
requirements: spec F01, §3.3, §8.1.

feuristic imports OTP accounts from QR codes that contain an `otpauth://`
URI in the Google Authenticator *Key Uri Format*. It also shows such a QR to
export a single account. This document lists exactly which subset is
accepted, with its limits.

## 1. Syntax

```
otpauth://TYPE/LABEL?PARAMETERS
```

| Part | Rule |
|---|---|
| scheme | `otpauth`, case-insensitive |
| `TYPE` | `totp` or `hotp`, case-insensitive. Anything else (`steam`, `motp`, …) is refused |
| `LABEL` | `account` or `issuer:account`. The colon may be literal or `%3A`; spaces after it are ignored |
| `PARAMETERS` | `name=value` pairs separated by `&`; parameter names are case-insensitive |

### 1.1 Parameters

| Name | Required | Accepted values | Default |
|---|---|---|---|
| `secret` | yes | base32 (RFC 4648), see §2 | — |
| `issuer` | no | text, see §3 | label issuer |
| `algorithm` | no | `SHA1`, `SHA256`, `SHA512`, case-insensitive | `SHA1` |
| `digits` | no | `6`, `7`, `8` | `6` |
| `period` | no (TOTP) | integer 15 … 300 (seconds) | `30` |
| `counter` | **yes for HOTP** | integer 0 … 2⁶⁴−1 | — |

* Unknown parameters (`image`, `color`, `lock`, …) are **ignored**.
* `period` is ignored for HOTP and `counter` is ignored for TOTP.
* A known parameter that appears twice (in any letter case) makes the URI
  invalid. So does a known parameter without `=`.
* Empty parts (`&&`, a trailing `&`) are ignored. An empty `issuer=` counts
  as absent; any other empty known parameter is an error.
* Numbers are ASCII decimal digits only: no sign, no spaces, no
  hexadecimal, at most 20 digits.

## 2. Secret

* Decoded with the RFC 4648 §6 base32 alphabet, case-insensitive. Spaces
  and hyphens are ignored, so `JBSW Y3DP` and `jbsw-y3dp` both work.
* Padding `=` (or `%3D`) is optional. If present, it must be at the end and
  complete.
* As in the reference Google Authenticator decoder, characters are consumed
  5 bits at a time and incomplete trailing bits are dropped. This accepts
  the "random base32 characters" secrets of any length that many services
  generate. The key bytes are the same ones other authenticators use, so
  the codes match.
* Decoded length: **1 to 64 bytes**. A secret shorter than **10 bytes (80
  bits)** is accepted but flagged as weak: the add-account screen shows a
  warning. RFC 4226 §4 R6 requires 128 bits and recommends 160.

## 3. Issuer and account

* Percent-decoding follows RFC 3986 §2.1. Malformed escapes (`%`, `%4`,
  `%G1`) are errors.
* In **query values** `+` decodes to a space, as in HTML form encoding
  (`issuer=ACME+Co`). In the **label** `+` is a literal character
  (`a+b@example.com`).
* Decoded text must be valid UTF-8 (RFC 3629: no overlong forms, no
  surrogates, nothing above U+10FFFF).
* Refused characters, to prevent display spoofing: C0 and C1 controls,
  DEL, U+061C, U+200B–U+200F, U+2028–U+202E, U+2060–U+206F and U+FEFF.
  This covers zero-width characters and bidirectional overrides.
* Leading and trailing spaces are removed. Neither name may contain `:`.
* Limits, in UTF-8 bytes after decoding (docs/architecture.md §6.3):
  **issuer ≤ 32 B**, **account 1 … 64 B**.
* If the label has an issuer prefix **and** the `issuer` parameter is set,
  the two must be identical (case-sensitive). Otherwise the URI is refused.
  If only one is present, it is used.

## 4. Whole-URI limits

* At most **512 bytes**, checked before any other parsing.
* Raw (not percent-encoded) UTF-8 and raw spaces are tolerated, because some
  generators produce them. Raw control characters are not.
* A fragment (`#…`) is refused instead of being silently dropped.

## 5. Examples

Accepted:

```
otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example
otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30
otpauth://hotp/Corp:bob?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=42&digits=8&algorithm=sha256
otpauth://totp/Soci%C3%A9t%C3%A9:j%C3%BCrgen?secret=jbsw-y3dp-ehpk-3pxp&image=https%3A%2F%2Fexample.com%2Flogo.png
```

Refused (reason):

```
otpauth://totp/A:me?secret=JBSWY3DPEHPK3PXP&issuer=B          issuer mismatch
otpauth://hotp/me?secret=JBSWY3DPEHPK3PXP                     HOTP without counter
otpauth://totp/me?secret=JBSWY3DPEHPK3PXP&digits=10           digits not in 6..8
otpauth://totp/me?secret=JBSWY3DPEHPK3PX1                     '1' is not base32
otpauth://totp/me?secret=JBSWY3DPEHPK3PXP&period=0            period not in 15..300
otpauth://totp/Bank%E2%80%AE:me?secret=JBSWY3DPEHPK3PXP       bidirectional override
otpauth://totp/me?secret=A&secret=B                           duplicate parameter
```

## 6. Import behaviour (device)

| Situation | Device behaviour |
|---|---|
| New issuer + account | confirmation screen (service, account, type, algorithm, digits, period or counter; weak-secret warning if needed) |
| Same issuer + account **and same secret** | "This account already exists", nothing is written |
| Same issuer + account, **different secret** | DANGER confirmation "Replace the account?". The old secret is erased if confirmed |
| 32 accounts already stored | "Storage full", nothing is written |

Replacing an HOTP account with the **same** secret (only possible through a
backup restore) never moves its counter backwards.

## 7. Export format (spec §8.1)

The device shows one account as a QR code containing a canonical URI:

```
otpauth://TYPE/[ISSUER:]ACCOUNT?secret=SECRET[&issuer=ISSUER]&algorithm=ALG&digits=D&(period=P|counter=C)
```

* `SECRET`: upper-case base32, **without padding**.
* `ISSUER` / `ACCOUNT`: UTF-8, every byte other than `A–Z a–z 0–9 - . _ ~ @`
  percent-encoded as `%XX` (upper-case hex). The label colon is literal.
* `algorithm`, `digits` and `period`/`counter` are always present.
  Parameter order is fixed: `secret`, `issuer`, `algorithm`, `digits`,
  `period` | `counter`.
* HOTP `counter` is the **next unused** moving factor. An authenticator that
  imports the QR continues without reusing a value the device already
  showed. The device keeps its own counter, so codes from both may collide
  if both are used afterwards. Exporting is meant for migration.
* If the URI would exceed 512 bytes (only possible with long non-ASCII
  names), the issuer prefix of the label is left out. The `issuer`
  parameter, which every reader prefers, stays.

Exporting reveals the secret. The firmware requires the device PIN again,
a hold-to-confirm DANGER screen warning that *anyone who photographs this
QR code can reproduce your codes*, shows the QR only on the device screen
(never over USB), and hides it automatically after **60 seconds**.
