---
title: "Questions fréquentes sur feuristic"
description: "Réponses sur la compatibilité Trezor Safe 3, le déverrouillage, les mises à jour, les avertissements et les clients compatibles avec feuristic."
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Questions fréquentes

## Est-ce un firmware officiel Trezor ?

Non. feuristic est un projet indépendant, sans approbation ni signature de
Trezor Company ou SatoshiLabs. Le bootloader affiche toujours son avertissement
tiers obligatoire.

## Puis-je conserver mon portefeuille Bitcoin ?

feuristic remplace l’application de portefeuille. Il ne migre ni les seeds ni
les comptes et ne signe pas de transactions en cryptomonnaies. Sauvegardez le
portefeuille avant le déverrouillage et utilisez un appareil de test dédié.

## Fonctionne-t-il sur Safe 5, Safe 7 ou Model T ?

Non. Seuls les Safe 3 **T2B1 et T3B1** sont ciblés, avec un binaire distinct pour
chaque modèle. Consultez le [matériel compatible](hardware.md).

## Pourquoi le déverrouillage est-il irréversible ?

Le bootloader efface le stockage et les secrets servant à l’attestation
constructeur. Réinstaller le firmware officiel ne recrée pas ces secrets.
Consultez les conséquences dans l’[installation](user/install.md).

## Le firmware est-il prêt pour des identités de production ?

La version 0.1.0 est la première version publique : images optimisées, sans
debuglink. Elle n’est pas encore qualifiée sur matériel. Une première campagne physique
T2B1/macOS a validé les opérations principales, mais la recette complète des
deux révisions et des OS prévus reste à effectuer avant la 1.0. Les clés de signature de
développement et l’identité USB provisoire sont aussi des limites de distribution.

## Faut-il un compte ou une application compagnon ?

feuristic ne demande ni compte ni service cloud. Il emploie FIDO HID, CCID/PC/SC,
un port série temporaire et un volume temporaire pour les images QR. Les fonctions
utilisent des clients standard, avec les limites d’interopérabilité documentées.

## Les passkeys sont-elles exportables ?

Oui. Les identifiants découvrables sont inclus dans les sauvegardes chiffrées.
Ne les présentez pas comme des clés matériellement non exportables.

## Peut-on installer en copiant le binaire sur le volume USB ?

Non. Le volume feuristic sert aux images QR. Le firmware s’installe via le
bootloader avec Suite ou `trezorctl`. Consultez l’[installation](user/install.md).

## Pourquoi l’heure TOTP doit-elle être remise après un démarrage ?

L’horloge doit être synchronisée dans le mode USB prévu avant d’utiliser les
codes TOTP. Consultez le [guide OTP](features/otp.md).

## Où poser une question ou signaler un problème ?

Utilisez les [discussions](https://github.com/jean-voila/feuristic/discussions)
pour l’aide et les issues pour les défauts reproductibles. Pour une vulnérabilité,
lisez la [politique de sécurité](security.md) avant de communiquer des détails.
