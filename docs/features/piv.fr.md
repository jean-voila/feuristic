---
title: "Carte PIV et certificats sur Trezor Safe 3"
description: "Emplacements PIV 9A, 9C, 9D, 9E, clés P-256/RSA-2048 et interface CCID/PC/SC dans le firmware feuristic."
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# PIV et certificats

feuristic propose PIV sur CCID/PC/SC, avec des clés **P-256 et RSA-2048**.
Les emplacements sont **9A** (authentification), **9C** (signature),
**9D** (accord de clé) et **9E** (authentification de la carte).

Gérez les identités sous **Cryptographie → PIV → Identités**. Les clients PIV,
OpenSC et PKCS#11 utilisent cette interface lorsque leurs profils sont compatibles.
La compatibilité protocolaire ne vaut pas validation de tous les clients.

## Avant un essai

Utilisez un PIN applicatif et des identités de test. Le PIN PIV et la clé de
gestion PIV sont distincts du PIN de l’appareil. Consultez les valeurs initiales,
les commandes et les politiques dans le [protocole PIV](../protocols/piv.md).

Les valeurs initiales sont PIN `123456`, PUK `12345678` et clé de gestion
AES-192 `010203040506070801020304050607080102030405060708`. Changez-les avant
de stocker des identités utiles.

Vérifiez chaque demande sur l’écran et allez jusqu’à **Confirmer** avec les deux
boutons avant son expiration. Un certificat doit correspondre à la clé publique
réellement générée dans l’emplacement choisi.

Une clé P-256 en 9A et sa signature ont été vérifiées sur le T2B1 physique,
y compris après mise à jour avec la même clé publique. RSA et l’ensemble des
usages de certificats restent soumis à leur recette spécifique.

Voir le [rapport matériel](../acceptance/campaign-2026-10-21-T2B1-macos.md), le
[protocole PIV](../protocols/piv.md) et la [sauvegarde PIV](../protocols/backup-piv.md).
