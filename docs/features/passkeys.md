---
title: FIDO2 passkeys and security keys on Trezor Safe 3
description: Use Feuristic as a FIDO2 and WebAuthn security key on Trezor Safe 3, with CTAP 2.1, discoverable passkeys, U2F and OpenSSH security-key clients.
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# FIDO2 passkeys and security keys

Unlock the device and use a standard WebAuthn client to register a USB security
key on a test account. Read the service and account on the OLED before confirming.
Sign out, sign in with the key, then repeat while refusing the request.

CTAP 2.1 implements clientPIN, credentialManagement, credProtect, largeBlobs
and hmac-secret. U2F is also implemented. Client support varies; the
[protocol reference](../protocols/fido2.md) defines the exact profile.

Manage identities under **Authentication → Passkeys → Services**. The device
PIN and FIDO PIN are distinct. Discoverable passkeys participate in encrypted
backups and must not be described as non-exportable.

For OpenSSH with a FIDO-enabled client:

```sh
ssh-keygen -t ed25519-sk -O resident -f ./feuristic-test-sk
```

Use a fresh filename. Registration with a remote service or SSH server is a
separate host operation. Read the [English guide](../user/guide-en.md) or
[French guide](../user/guide-fr.md) for management and deletion.
