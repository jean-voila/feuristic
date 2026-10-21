---
title: "OpenPGP et GnuPG sur Trezor Safe 3"
description: "Signatures Ed25519, déchiffrement X25519 et RSA-2048 avec le profil OpenPGP Card 3.4 de Feuristic et GnuPG sur Trezor Safe 3."
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# OpenPGP et SSH

Feuristic implémente **OpenPGP Card 3.4** sur CCID/PC/SC, avec **Ed25519,
X25519 et RSA-2048**. Les identités se gèrent sous
**Cryptographie → OpenPGP → Identités**.

En mode USB normal, un client standard tel que GnuPG peut interroger la carte :

```sh
gpg --card-status
```

Configurez des identifiants de test, puis générez les clés avec le client ou les
menus de l’appareil. Les PIN applicatifs OpenPGP sont distincts du PIN de
l’appareil ; lisez les valeurs initiales et les règles dans le
[protocole](../protocols/openpgp.md) avant l’utilisation.

## Confirmation physique

Pour une opération sensible, vérifiez le rôle, l’algorithme et les autres
informations affichées. Parcourez les pages jusqu’à **Confirmer**, puis validez
avec les deux boutons avant l’expiration de la demande. Maintenir gauche refuse.

Les valeurs initiales sont `123456` pour PW1 et `12345678` pour PW3 :
changez-les avant d’ajouter des identités utiles. Synchronisez l’horloge avant
une génération locale, car la date de création fait partie des empreintes.

Le rôle d’authentification peut servir avec l’agent SSH de GnuPG selon la
configuration du client. Ne supposez pas que tous les usages SSH ont déjà été
validés sur chaque OS.

La campagne T2B1/macOS a vérifié une identité GnuPG jetable, des signatures
Ed25519, un déchiffrement X25519 et la persistance après mises à jour.
Consultez le [rapport](../acceptance/campaign-2026-10-21-T2B1-macos.md), le
[protocole](../protocols/openpgp.md) et la [sauvegarde](backup.md).
