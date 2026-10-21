---
title: "Passkeys FIDO2 et clé de sécurité sur Trezor Safe 3"
description: "Utiliser Feuristic pour FIDO2, WebAuthn, CTAP 2.1, U2F et les clés de sécurité OpenSSH sur un Trezor Safe 3."
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# FIDO2 et passkeys

Feuristic expose une clé de sécurité FIDO HID : **WebAuthn / CTAP 2.1 et U2F**,
avec identifiants découvrables, clientPIN, credProtect, largeBlobs et hmac-secret.
Le profil prévoit jusqu’à 100 identifiants découvrables.

1. Déverrouillez Feuristic et restez en mode USB normal.
2. Dans votre navigateur ou client, choisissez une clé de sécurité USB pour
   créer une passkey sur un compte de test.
3. Vérifiez le service et le compte sur l’écran, parcourez les pages et
   confirmez avec les deux boutons. Maintenir gauche permet de refuser.

Le PIN FIDO est distinct du PIN de déverrouillage de l’appareil. Configurez-le
avec votre client FIDO standard lorsque celui-ci le demande.

## Clients et sauvegarde

Les navigateurs WebAuthn, libfido2 et les clés de sécurité OpenSSH utilisent
cette interface. La prise en charge du protocole ne garantit pas une validation
de chaque combinaison navigateur/OS. Utilisez des identités jetables.

La gestion locale est sous **Authentification → Passkeys → Services**.
Pour un client OpenSSH compatible FIDO, utilisez un nom de fichier neuf :

```sh
ssh-keygen -t ed25519-sk -O resident -f ./feuristic-test-sk
```

L’enregistrement auprès d’un serveur reste une opération distincte du client.
Les passkeys découvrables sont **exportables** dans les sauvegardes chiffrées.
Ce choix doit être pris en compte dans votre modèle de sécurité.

La campagne physique T2B1/macOS a vérifié création, signature, refus et
persistance d’une passkey après coupure et mises à jour. Consultez le
[rapport](../acceptance/campaign-2026-10-21-T2B1-macos.md), le
[protocole FIDO2](../protocols/fido2.md) et la [sauvegarde](backup.md).
