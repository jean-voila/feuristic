---
title: "Sauvegarde et restauration par QR chiffrés"
description: "Sauvegarder les identités Feuristic en séquences QR chiffrées et les restaurer depuis des images PNG/JPEG sur Trezor Safe 3."
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Sauvegarde et restauration

Feuristic exporte les identités sous forme de **séquences QR chiffrées**.
L’enveloppe utilise CBOR canonique, PBKDF2-HMAC-SHA256 et AES-256-GCM ; les
trames sont encodées en Base45. Le [format public](../protocols/backup-format-v1.md)
décrit les paramètres et les règles de validation.

Une photo QR accompagnée de sa phrase peut restituer les clés privées.
Un export OTP en clair expose directement sa seed.

## Créer une sauvegarde

Utilisez le menu de sauvegarde et choisissez un mot de passe distinct des PIN.
La phrase doit comporter **12 à 128 caractères ASCII imprimables** et être
différente du PIN de l’appareil. Capturez toutes les trames avec une caméra. Vérifiez leur lisibilité et gardez
le mot de passe séparément. Une sauvegarde chiffrée contient des secrets et ne
doit pas être ajoutée à une issue, un dépôt ou un journal de test public.

## Restaurer

Le mode d’import USB accepte des images PNG et JPEG de base. Suivez les menus,
vérifiez les identités proposées et confirmez explicitement le remplacement
lorsque l’appareil le demande. Terminez par une éjection propre du volume.

Un test réel de restauration sur un autre appareil de test est nécessaire avant
de compter sur une sauvegarde. Les tests d’enveloppe sur hôte ou émulateur ne
remplacent pas la validation caméra, les coupures et les échanges entre révisions.

Les passkeys découvrables sont exportables dans ces sauvegardes. Les formats
propres à [OTP](../protocols/backup-otp.md), [OpenPGP](../protocols/backup-openpgp.md),
[PIV](../protocols/backup-piv.md) et [AES](../protocols/backup-aes.md) précisent le contenu.
Consultez aussi la [validation des sauvegardes](../developer/backup-readiness.md)
et la [recette matérielle](../acceptance/README.md).
