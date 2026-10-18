<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# FIDO2 / CTAP 2.1 and U2F — protocol notes

Status: implemented in `src/feuristic/apps/fido2/` (shared MicroPython/CPython
code), tested on the host with python-fido2 as an independent client
(`tests/host/fido2/`). **Not yet validated on hardware** (acceptance tests
R02–R04 of the product specification remain to be run).

References: CTAP 2.1 PS (2021-06-15), WebAuthn Level 3, FIDO U2F Raw Message
Formats v1.2, FIDO U2F HID Protocol v1.2.

## 1. Feature matrix

| Feature | Status | Notes |
|---|---|---|
| CTAPHID INIT / PING / MSG / CBOR / CANCEL / KEEPALIVE / ERROR | yes | §11.2; 64-byte reports, max message 7609 bytes |
| CTAPHID WINK | yes, when the glue enables it | capability bit set only then; the glue flashes the screen |
| CTAPHID LOCK | no | not advertised, `ERR_INVALID_CMD` |
| CTAPHID NMSG capability | not set | U2F (MSG) is supported |
| U2F REGISTER / AUTHENTICATE (0x03, 0x07, 0x08) / VERSION | yes | `"U2F_V2"`, presence by polling (6985) |
| authenticatorMakeCredential / GetAssertion / GetNextAssertion | yes | ES256 (-7), EdDSA (-8) |
| authenticatorGetInfo | yes | see §2 |
| authenticatorClientPIN, protocols 2 and 1 | yes | getPINRetries, getKeyAgreement, setPIN, changePIN, getPinToken, getPinUvAuthTokenUsingPinWithPermissions |
| Built-in UV (`uv`, getPinUvAuthTokenUsingUvWithPermissions, getUVRetries) | no | not advertised; `CTAP2_ERR_INVALID_SUBCOMMAND` / `INVALID_OPTION` |
| authenticatorReset | yes | only ≤ 10 s after power-up, plus a DANGER confirmation |
| authenticatorSelection | yes | |
| authenticatorCredentialManagement 0x0A | yes | 0x41 (FIDO_2_1_PRE) accepted as an alias, not advertised |
| authenticatorLargeBlobs | yes | 4096-byte serialized array |
| authenticatorConfig, bio enrollment, enterprise attestation | no | not advertised |
| Extensions credProtect, hmac-secret, largeBlobKey | yes | |
| Extensions credBlob, minPinLength, thirdPartyPayment | no | not advertised |

## 2. authenticatorGetInfo

| Key | Value |
|---|---|
| 0x01 versions | `["U2F_V2", "FIDO_2_0", "FIDO_2_1"]` |
| 0x02 extensions | `["credProtect", "hmac-secret", "largeBlobKey"]` |
| 0x03 aaguid | `e90e59a4-2c04-4252-ae49-d69eff27585f` |
| 0x04 options | `rk: true, up: true, plat: false, clientPin: <PIN set?>, credMgmt: true, largeBlobs: true, pinUvAuthToken: true, makeCredUvNotRqd: true` (no `uv`, no `alwaysUv`) |
| 0x05 maxMsgSize | 7609 |
| 0x06 pinUvAuthProtocols | `[2, 1]` |
| 0x07 maxCredentialCountInList | 16 (lists up to 64 entries are accepted; more → `CTAP2_ERR_LIMIT_EXCEEDED`) |
| 0x08 maxCredentialIdLength | 64 |
| 0x09 transports | `["usb"]` |
| 0x0A algorithms | ES256, EdDSA |
| 0x0B maxSerializedLargeBlobArray | 4096 |
| 0x0D minPINLength | 4 |
| 0x0E firmwareVersion | `Context.firmware_version` (default 0x000100) |
| 0x14 remainingDiscoverableCredentials | 100 − stored |
| 0x16 attestationFormats | `["packed", "none"]` (CTAP 2.2 key, harmless for 2.1 platforms) |

**AAGUID.** `e90e59a4-2c04-4252-ae49-d69eff27585f` is a random UUIDv4
generated once for the project. It identifies the feuristic *model*, is the
same on every device, and is not registered in the FIDO MDS.

**makeCredUvNotRqd = true** (CTAP 2.1 §6.4, §6.1.2 step 7): when a PIN is
set, *discoverable* credentials require a pinUvAuthToken
(`CTAP2_ERR_PUAT_REQUIRED`), non-discoverable ones only need user presence.
This keeps second-factor logins and OpenSSH `ecdsa-sk`/`ed25519-sk` keys
usable on a PIN-protected key while passkeys stay PIN-protected.

**No built-in UV.** The device has its own (storage) PIN, but WebAuthn user
verification is obtained through clientPIN, the standard path for roaming
authenticators. Requests with `uv: true` get `CTAP2_ERR_INVALID_OPTION`.

## 3. Attestation

feuristic has no vendor attestation key: unlocking the bootloader destroys
the Optiga attestation objects (docs/architecture.md §4) and feuristic never
reuses Trezor/SatoshiLabs certificates.

* CTAP2: `packed` **self attestation** (`{alg, sig}` signed with the new
  credential key, no `x5c`), or `none` when the platform puts `"none"` before
  `"packed"` in `attestationFormatsPreference` (0x0B). `enterpriseAttestation`
  → `CTAP1_ERR_INVALID_PARAMETER`.
* U2F: the registration is signed with the credential key and carries a
  **per-credential self-signed X.509 certificate** for that key
  (`apps/fido2/x509.py`: v3, ecdsa-with-SHA256, subject = issuer =
  `O=feuristic project, OU=Authenticator Attestation, CN=feuristic self
  attestation`, serial = 16 bytes derived from the public key, validity
  2026-01-01 → 9999-12-31, basicConstraints CA:FALSE critical). Rationale: a
  per-device certificate would be a cross-RP tracking identifier; the
  per-credential certificate is unlinkable and mirrors CTAP2 self
  attestation.

## 4. Credentials

### 4.1 Credential ID formats

| First byte | Length | Kind | Content |
|---|---|---|---|
| `0x01` | 13 | discoverable | `0x01 ‖ uid(8) ‖ seq(4)`; lookup by record uid, then exact ID and rpIdHash match |
| `0x02` | 62 | non-discoverable | `0x02 ‖ nonce(12) ‖ AES-256-GCM(info(1) ‖ key(32)) ‖ tag(16)`, key = `kdf(ms, "fido2/cred-wrap", ctx=seed)`, AAD = `0x02 ‖ rpIdHash` |
| `0x03` | 61 | U2F key handle | `0x03 ‖ nonce(12) ‖ AES-256-GCM(key(32)) ‖ tag(16)`, key = `kdf(ms, "fido2/u2f-wrap", ctx=seed)`, AAD = `0x03 ‖ appParam` |

`info` = credProtect level (bits 0–1), hmac-secret (bit 2), largeBlobKey (bit
3), EdDSA (bit 4). `seed` is the 32-byte reset epoch stored in the FIDO state
blob; authenticatorReset regenerates it, which invalidates every
non-discoverable credential and U2F key handle (the device master secret is
shared with other applications and cannot be rotated).

U2F key handles are accepted by CTAP2 getAssertion (rpIdHash = appParam), and
CTAP2 ES256 credentials with credProtect level 1 are accepted by U2F
AUTHENTICATE (CTAP 2.1 §10.2).

### 4.2 Keys and per-credential secrets

Private keys are random (P-256 scalars from `p256_generate`, Ed25519 32-byte
seeds). `CredRandomWithUV`, `CredRandomWithoutUV` and the `largeBlobKey` are
`HKDF-SHA256(IKM = credential private key, salt = "feuristic/v1",
info = label ‖ 0x00 ‖ ctx)` with the labels `fido2/cred-random`
(ctx `"uv"` / `"no-uv"`) and `fido2/largeblob-key`. Deriving them from the
private key (instead of the device master secret) makes hmac-secret outputs
and encrypted largeBlob entries survive a QR backup restored on another
device.

### 4.3 Signature counter

One global 32-bit counter (CTAP2 and U2F), strictly increasing across power
cuts (redundant counter, reserved in blocks of 32 values). Trade-off: a
global counter lets colluding RPs estimate activity elsewhere; per-credential
counters would rewrite a ~400-byte record on every assertion (flash wear on a
64 KiB sector) and cannot exist for stateless non-discoverable credentials.

### 4.4 WebAuthn backup flags

Discoverable credentials: BE = 1 (they can be exported by the QR backup,
product spec §5/§8.2); BS = 1 once exported (`provider.on_exported`) or
restored. Non-discoverable credentials and U2F key handles: BE = 0, BS = 0.

## 5. Storage layout and sizes

| Namespace / key | Content | Size |
|---|---|---|
| `FIDO_CREDS` (0x12) slots 0–100 | `RecordStore`, capacity **100**, record type 0x46, header flag bit 0 = BS | payload ≤ 384 B (worst case 376 B) |
| `FIDO_STATE` (0x13) keys 0x00/0x01 | state `Blob`: `version ‖ seed(32) ‖ pinRetries ‖ flags ‖ pinHash(16) ‖ minPinLen` | 52 B |
| `FIDO_STATE` keys 0x02/0x03 | largeBlob `Blob` (serialized array incl. 16-byte hash) | ≤ 4096 B |
| `FIDO_STATE` keys 0x04/0x05 | signature counter (`RedundantCounter`, protected) | 8 B each |

Discoverable record payload (canonical CBOR):
`{1: seq, 2: rpId (≤ 128 B), 3: user.id (≤ 64 B), ?4: user.name (≤ 64 B),
?5: user.displayName (≤ 64 B), 6: info, 7: privateKey(32)}`.
`rp.name` is not stored (shown in the creation prompt only; credMgmt returns
`rp: {id}`). user.name / displayName / rp.name are truncated to 64 bytes on
a UTF-8 boundary. Re-registering the same (rpId, user.id) atomically replaces
the record (same uid, new seq). Duplicates left by an interrupted restore are
resolved at the next load (newest generation wins). Corrupt records are
skipped, never fatal.

Worst-case flash use (FakeKV model): 100 records ≈ 44.8 KiB + two largeBlob
copies ≈ 8.1 KiB + state/counters < 0.5 KiB.

## 6. PIN

* Protocols 1 and 2, separate key agreement keys generated at power-up
  (lazily) and regenerated after each mismatch.
* `pinRetries` (8) persisted, decremented **before** comparing the PIN hash;
  3 consecutive mismatches → `CTAP2_ERR_PIN_AUTH_BLOCKED` until power cycle
  (`powerCycleState` reported by getPINRetries); 0 → `CTAP2_ERR_PIN_BLOCKED`
  (only a reset helps).
* PIN rules: padded to 64 bytes, ≤ 63 bytes, valid UTF-8, ≥ 4 code points.
  Stored as `LEFT(SHA-256(PIN), 16)`.
* pinUvAuthToken: 32 random bytes, bound to the protocol that issued it;
  permissions mc, ga, cm, lbw (be/acfg → `CTAP2_ERR_UNAUTHORIZED_PERMISSION`);
  permissions RP ID (bound on first use when absent); usage limits 30 s
  initial / 10 min maximum; after a makeCredential or a getAssertion with
  `up = true` the UP/UV flags and every permission except lbw are cleared.
* Device menu (`localmgmt.set_pin` / `change_pin`): set when none, change with
  the current PIN (same retry accounting). No removal except the confirmed
  global wipe, mirroring CTAP.

## 7. largeBlobs

`get`/`set` with offsets, `length` on the first fragment, fragment limit
`maxMsgSize − 64` = 7545, array cap 4096 (`CTAP2_ERR_LARGE_BLOB_STORAGE_FULL`),
`CTAP1_ERR_INVALID_SEQ` for out-of-order offsets, `CTAP2_ERR_INTEGRITY_FAILURE`
when `LEFT(SHA-256(array), 16)` does not match (previous array kept). Writes
need a token with `lbw` when a PIN is set; the MAC covers
`0xff×32 ‖ 0x0c 0x00 ‖ uint32LE(offset) ‖ SHA-256(fragment)`. The array is
committed atomically (A/B blob).

## 8. User interaction

Every user-presence step awaits `ctx.ui.confirm(Prompt(kind, title, fields,
severity))`:

| kind | When | Severity |
|---|---|---|
| `fido2.make_credential` | makeCredential | SENSITIVE |
| `fido2.get_assertion` | getAssertion (then `ui.select` among accounts if several discoverable credentials) | SENSITIVE |
| `fido2.excluded` | excludeList hit | NORMAL |
| `fido2.selection` | authenticatorSelection, zero-length pinUvAuthParam, Chrome's `.dummy` RP | NORMAL |
| `fido2.reset` | authenticatorReset | DANGER |
| `fido2.u2f_register`, `fido2.u2f_authenticate`, `fido2.u2f_bogus` | U2F | SENSITIVE / NORMAL |
| `fido2.local.delete`, `fido2.local.wipe` | device menus | DANGER |

Refusal → `CTAP2_ERR_OPERATION_DENIED`; timeout (`UserTimeout`, or `False`
after the prompt timeout of 30 s) → `CTAP2_ERR_USER_ACTION_TIMEOUT`;
CTAPHID_CANCEL → `CTAP2_ERR_KEEPALIVE_CANCEL`. Silent requests (`up = false`)
with several discoverable credentials return `numberOfCredentials` and serve
authenticatorGetNextAssertion (state dropped after 30 s or any other command).

U2F uses the polling model: the first request answers 6985 and arms a
presence latch; the glue runs the dialog concurrently; the next identical
request consumes the approval. A refusal answers the next identical request
with CTAPHID `ERR_CHANNEL_BUSY` (stops Chrome's polling, as upstream Trezor).
Dummy registrations (app parameter `"A"×32`, zeros, `SHA-256("make.me.blink")`)
show "already registered / not registered" and then complete with a
throw-away stateless key handle.

## 9. Firmware glue contract

```python
ctx = Context(ms, DeviceInteraction(...), power_up_ms=boot_ticks)
server = HidServer(CtapHid(wink=True), Fido2App(ctx))
while True:
    pkt = await read_hid_report(timeout_ms=20)   # USB HID iface or emulator UDP (+2)
    now = ticks_ms()
    if pkt is not None:
        server.feed(pkt, now)
    server.poll(now)                             # continuation timeouts, keepalives (100 ms)
    for out in server.packets():
        write_hid_report(out)
    job = server.next_job()                      # CTAP request or U2F dialog coroutine
    if job is not None:
        spawn(job)
    if server.take_wink():
        flash_screen()
```

* The interaction must abort a pending dialog (return `False` or raise
  `UserCancelled`) when `server.cancel_requested()` becomes true, and should
  raise `UserTimeout` on timeout.
* `app.u2f.dialog_stale()` tells the glue that the host stopped polling for
  the U2F dialog being shown (the task may be closed).
* The storage must be unlocked (device PIN entered) before FIDO requests are
  served.

## 10. Backup (provider)

`Fido2BackupProvider` (`TYPE = "fido2"`), one identity per discoverable
credential; schema in `provider.py`. The item contains the private key, IDs,
names, algorithm, credProtect, flags, the global signature counter and the
largeBlob array items that decrypt under the credential's largeBlobKey ("données
largeBlobs associées"). Restore keeps the credential ID, sets BE = BS = 1,
raises the signature counter and merges the largeBlob items (duplicates
skipped, 4096-byte cap checked before writing). Array items that belong to no
stored credential are not exported.

## 11. Limits and known deviations

* rpId > 128 bytes: discoverable credentials refused with
  `CTAP1_ERR_INVALID_LENGTH` (non-discoverable ones work).
* clientDataHash must be 32 bytes (`CTAP1_ERR_INVALID_LENGTH`).
* `rp.name` not stored; credMgmt returns only `rp.id`.
* `KEY_STORE_FULL` is reported *before* asking for user presence.
* hmac-secret is computed for silent (`up = false`) assertions as the spec
  allows (upstream Trezor deliberately does not).
* python-fido2 / platforms that send `uv: true` without a pinUvAuthParam get
  `CTAP2_ERR_INVALID_OPTION` (no built-in UV).
* Secrets in `bytes` (tokens, shared secrets, derived keys) cannot be wiped
  from RAM by MicroPython; they are short-lived.
* 16 CTAPHID channels are remembered (LRU); older ones get
  `ERR_INVALID_CHANNEL` and must re-INIT.
