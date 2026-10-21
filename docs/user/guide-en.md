<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# User guide — English

**Development candidate for hardware testing, not hardware qualified.** Use test
identities. Read [installation](install.md) before the irreversible bootloader
unlock, which erases storage and removes original manufacturer attestation.
[R01–R16](../acceptance/README.md) must pass on **both** T2B1 and T3B1 before a
stable release. Feuristic has no cryptocurrency or wallet-seed migration.

## First boot and two-button controls

Acknowledge the `UNSAFE, DO NOT USE!` boot warning, select English, read the
third-party notice, then enter a new **4–50 digit device PIN twice**.

On later boots and after locking, the screen shows **FEURISTIC** and
“Press any button...”. Either button opens PIN entry; the device remains
locked until the PIN is verified.

- Left: previous; right: next; both together: select/confirm.
- Hold left for approximately one second: back/cancel.
- Read every page of sensitive prompts; follow the hold indication for
  destructive confirmations. Back/cancel must never approve an operation.
- Enter digits/text on the device's character carousel and select its finish
  action. Long lists include More... and Back entries.

Home contains Authentication, Cryptography, Backup, Settings and Lock. Storage
locks after **five minutes of inactivity**, or immediately through Lock. Enter
the device PIN again to resume. Wrong device PINs consume persistent attempts
and incur delays; exhausting the upstream storage retry limit wipes the device.
Never exercise this limit on your only useful identities.

| Secret | Purpose |
|---|---|
| Device PIN | unlock storage and reauthenticate local export/management |
| FIDO PIN | standard clientPIN/WebAuthn user verification |
| OpenPGP PW1/PW3/resetting code | user/admin smart-card operations |
| PIV PIN/PUK/administration key | PIV operations and administration |
| Backup passphrase | encrypt QR backups; 12–128 printable ASCII characters, distinct from the device PIN |

## Passkeys and security-key use

Unlock and leave normal USB mode active. In a test account's security settings,
add a USB security key or passkey. The browser may ask for a **FIDO PIN**, which
is separate from the device PIN. Check the service/account on the Safe 3 and
approve. Sign out and verify a fresh login; also refuse a request and check it
fails.

Open **Authentication → Passkeys → Services → service → account** for
information/protections, encrypted identity export or targeted deletion. The
Passkeys menu also provides FIDO PIN management and FIDO data erasure. Deleting
locally does not remove the corresponding registration from the website.
Non-discoverable credentials do not appear in the discoverable list and are
not included in discoverable-identity backups.

CTAP 2.1 supports clientPIN, credentialManagement, credProtect, largeBlobs and
hmac-secret, alongside U2F. There is no biometric verification or manufacturer
attestation. Discoverable private keys are exportable in encrypted backups;
WebAuthn backup flags reflect this. See [FIDO2](../protocols/fido2.md).

With a FIDO-enabled OpenSSH installation, create a disposable test key:

```sh
ssh-keygen -t ed25519-sk -O resident -f ./feuristic-test-sk
```

Use a fresh output filename, provide the FIDO PIN if requested and approve on
the device. The local file references a hardware key. Use normal OpenSSH and
Git SSH-signing configuration for subsequent operations.

**Authentication → Challenge-response** explains the standard client paths:
WebAuthn hmac-secret or PIV GENERAL AUTHENTICATE. The host client initiates the
actual operation. This menu does not accept a challenge for a proprietary SSH
protocol.

## Add and use OTP accounts

1. Obtain an `otpauth://` QR from a test service. Prepare a **PNG or baseline
   JPEG**, ≤ **256 KiB**, ≤ **1024 × 1024 pixels**, with one relevant QR. HEIC
   and progressive JPEG are not supported formats.
2. Select **Authentication → OTP → Add QR via USB**. The temporary FAT12
   import volume appears; FIDO and CCID are unavailable during import.
3. Copy one image at a time and wait for analysis. The volume is a temporary
   input surface, not a backup disk: rereading copied image clusters may
   return zeros and image files are not retained.
4. Inspect service, account, type and parameters on the device and confirm
   locally. Copying alone never commits a secret.
5. When requested, **eject using Finder, Explorer or the Linux device-eject
   action**. Wait for normal HID+CCID mode before reconnecting other clients.

Select an account, then View code. TOTP needs synchronized session time. HOTP
requires confirmation and advances its persistent counter before showing the
code. Avoid generating extra HOTP codes, as the server has a finite resync
window. The supported OTP profile is SHA1/SHA256/SHA512, 6/7/8 digits and TOTP
periods 15–300 seconds; the service must use the same parameters.

Invalid formats and capacity excess are refused without damaging existing
accounts. Cancel and eject to leave. If filesystem ordering/fragmentation
causes a stream error, retry in a new import session; do not reformat the
volume. See [otpauth profile](../protocols/otpauth.md).

## Set TOTP time

Open **Settings → TOTP time → Sync over USB**. The device temporarily exposes
only CDC-ACM serial. A standard terminal can send `TIME 1 ` followed by Unix
seconds and a newline; `OK` means success, `ERR` gives a failure code. The
computer's clock must be correct. Optional repository helper:

```sh
uv run python tools/feuristic_time.py
```

It detects the current test VID/PID; pass an explicit serial-device path if
several ports exist. Linux, macOS and Windows PowerShell examples are in the
[time protocol](../protocols/time-sync-v1.md). Going back more than 60 seconds
or forward more than 300 seconds requires local confirmation. Success,
cancellation or the five-minute mode timeout restores normal USB. Time
survives logical USB re-enumeration, **not power loss**. After power removal,
TOTP shows Time not synchronised rather than an incorrect code.

## OpenPGP and GnuPG

**Cryptography → OpenPGP** offers Generate keys, View keys, Delete keys, Export
QR backup, Card PINs and application reset. Synchronize time before local key
generation because OpenPGP fingerprints depend on key timestamps. Choose
Ed25519/X25519 or RSA-2048 for compatibility. Generation replaces the three
roles: signing, decryption and authentication. Back up before replacing keys.

Change initial PW1 **123456** and PW3 **12345678** through Card PINs. A resetting
code is optional. Local management authenticated with the device PIN can also
restore blocked application retry counters.

Use standard GnuPG, scdaemon and PC/SC; no trezor-agent:

```sh
gpg --card-status
gpg --card-edit
```

GnuPG's `admin`, then `generate` flow can generate keys on the card, with local
approval for sensitive operations. Retain the public OpenPGP certificate,
subkeys and revocation material using GnuPG's normal procedures; the card
backup is not a complete backup of the GnuPG public keyring. Add `disable-ccid`
to `scdaemon.conf` when using PC/SC. After restoring on a different device the
card serial changes; run `gpg --card-status` to learn it again. See
[OpenPGP protocol](../protocols/openpgp.md).

## PIV, certificates and signatures

**Cryptography → PIV → Identities → slot** offers information, P-256/RSA-2048
generation, certificate view, PIN policy, encrypted export and deletion. Slots
are 9A authentication, 9C digital signature, 9D key agreement and 9E card
authentication. Regenerating a slot destroys its previous key and certificate.
Import the matching public X.509 certificate (≤ 2048 bytes) with a standard
PIV client.

In PIV Settings change initial PIN **123456**, PUK **12345678** and the public
AES-192 administration key
`010203040506070801020304050607080102030405060708`. Locally entered PIN/PUK
values have 6–8 digits. Generating an administration key displays it locally
as Hex or QR for a limited time: save it privately for your host PIV tools.
That QR contains an administration secret, not a public certificate.

```sh
opensc-tool --list-readers
pkcs15-tool --dump
yubico-piv-tool -r '' -a status
```

The empty reader filter includes non-Yubikey reader names. Use OpenSC/PKCS#11
or a PIV client for certificates, TLS and SSH; detailed commands and PIN
policies are in [PIV](../protocols/piv.md). Every private-key operation requires
local confirmation with role, algorithm and fingerprint. Uninterpreted digest
signature means the device sees only a digest/block and cannot establish the
host document's meaning.

## AES-256-GCM and randomness

**Cryptography → AES** lets you create a key with ID 1–16, a 1–16 printable
ASCII name and approval policy Every operation or Once per session. A key's
menu offers information/fingerprint, rename, policy, enable/disable, encrypted
export and deletion. Once per session authorizes subsequent operations until
card reset, lock or USB mode change. Disabling refuses use without destroying
the key.

A PC/SC client uses SELECT/MSE/PSO from the published
[AES-GCM v1 profile](../protocols/aes-gcm-iso7816-v1.md), which includes a client
example. The PIV PKCS#11 module does not automatically expose this AES service.
Limits per operation: 3584 bytes of plaintext/ciphertext and 256 bytes of AAD.
The device supplies the nonce and authenticates the tag before plaintext output.

**Cryptography → Randomness** shows status, information and self-test. Retesting
requires reauthentication. Standard 32-byte random challenge example:

```sh
opensc-tool -s 0084000020
```

GET CHALLENGE returns 1–32 bytes without an application PIN, subject to health
checks and rate limiting. Health failure must refuse output.

## QR backup and restore

Anyone photographing an unencrypted OTP QR can reproduce its codes. Encrypted
identity backups contain private keys: images plus passphrase suffice to
restore them. Photograph privately and control camera cloud synchronization.
Feuristic cannot recover a lost passphrase.

An OTP account's QR export shows a standard `otpauth://` after PIN and warning.
If its URI does not fit, the UI offers encrypted multi-frame backup instead.

Encrypted QR export temporarily disconnects USB and suspends FIDO/CCID.
Keep power connected. USB reconnects when export finishes or is cancelled;
reopen any interrupted smart-card session afterwards.

1. Choose **Backup → Export an identity**, then category/identity, or **Full
   export** to chain the exportable identities.
2. Choose **Large modules** (more images) or **Dense QR**. Neither physical
   readability profile is qualified until R13 passes.
3. Read the recovery warning, enter a 12–128 printable ASCII passphrase twice,
   then reenter the device PIN. The passphrase must differ from the PIN.
   Wait for derivation without removing power.
4. Photograph **every frame of every identity**. The frame number appears
   before the full-screen QR. Left goes back, right advances and finishes at
   the last frame; both finish after every frame was viewed. Holding left or
   waiting 60 seconds stops/hides the export.
5. Store images and phrase separately. Test restoration before erasing the
   original. Export finished proves display, not camera readability or storage.

To restore, select **Backup → Restore**. Prepare PNG/baseline JPEG photos within
the input limits, preserving contrast/modules. Copy one file at a time,
**all frames of one identity**, then press Continue. Frame order is arbitrary
and exact duplicates are ignored; a missing frame blocks that identity without
changing it. Enter the phrase on the device, inspect the identity and approve
any specific overwrite. New-file writes are paused during confirmation and
calculation. If the computer reports the device is not ready, **retry that file
once the device invites you to copy the next identity**; a failed copy is not a
successful import.

For an identity with many images, the FAT12 root has only 64 directory entries.
Use short names such as `QR000001.PNG` and batches of at most 32 images. Wait
until the device counts those frames as received, then delete **only the copies
on the import volume**, keeping the original backup images elsewhere. Continue
with the next batch on the same mounted volume; do not eject or restart before
all frames of that identity have arrived.

Repeat for the remaining identities with the volume still mounted. The same
export set reuses its cached derived key without another phrase entry. Choose
Done to finish, inspect the result and any incomplete-set warning, then eject
when requested. Previously approved identities stay restored if a later one
fails or is missing. Wrong phrase/tag never modifies the current identity. The
device displays the number restored; inspect restored identities in their
application menus.

Restoration is atomic **per identity**, not for an entire export. Device/FIDO
PINs and PIV administration state are not globally cloned: the destination
keeps its PIV credentials, while OpenPGP retains its saved PIN references.
HOTP never rolls the same secret's counter back. Using a restored AES key in
parallel on several devices does not provide an absolute worldwide nonce
uniqueness guarantee; see [AES backup limits](../protocols/backup-aes.md).

## Capacity, settings and troubleshooting

**100 discoverable passkeys + 32 OTP accounts + 4096 serialized largeBlob bytes**
share one 64 KiB live sector with other applications. This does not promise
all maximum OpenPGP/PIV/AES sizes in addition. Storage-full errors must preserve
existing data. Large backups can require hundreds of photos; they are not a
single QR or a fast recovery mechanism. T2B1 is especially RAM constrained;
see [storage budget](../developer/storage-budget.md).

Settings changes the device PIN, FR/EN language and time, and shows USB and
hardware/version information. USB interfaces is informational and does not
enable every interface simultaneously. Wipe device requires strengthened
confirmations and PIN, then restarts with empty storage.

Current USB **1209:0001 is a test PID**, not a project assignment. Linux libccid
may require reader registration; see [CCID host notes](../protocols/ccid.md).
Reconnect clients holding old USB handles after temporary modes. If a serial
port or disk is missing, check the active mode and data cable. Never reformat
the import drive. Record version, model, OS, action and error without secrets;
follow [SECURITY.md](../../SECURITY.md) for security-sensitive defects.

The FAT12 label is `FEURISTIC`; the SCSI product name is `FEURISTIC-IMPORT`,
which exceeds FAT's 11-character label field. Import mode expires after ten
minutes. The hardware receiver handles **one identity at a time, up to 12 KiB
per encrypted envelope**, covering the tested native OpenPGP/RSA, PIV and
passkey-with-largeBlob exports. Public format v1 allows 64 KiB envelopes and
16 items in a Full envelope; those generic parser bounds do not promise that
arbitrary third-party packages fit on the device. A native full export chains
independent one-identity envelopes while the same volume stays mounted.
