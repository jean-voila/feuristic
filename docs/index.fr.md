---
title: "Firmware personnalisé pour Trezor Safe 3"
description: "feuristic transforme un Trezor Safe 3 en clé FIDO2, carte OpenPGP/PIV et générateur TOTP/HOTP. Téléchargements, installation, protocoles et essais."
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# feuristic — firmware personnalisé pour Trezor Safe 3

![feuristic pour Trezor Safe 3 : FIDO2, OpenPGP, PIV, OTP et AES-GCM](assets/overview.svg){ .project-overview width="1600" height="800" }

feuristic remplace l’application de portefeuille d’un **Trezor Safe 3** par une
clé de sécurité USB, une carte à puce et un générateur de codes à usage unique.
Il prend en charge les révisions **T2B1 et T3B1**. La configuration et les
confirmations utilisent les deux boutons ; les opérations passent par des
clients standard sur l’ordinateur.

[Installer feuristic](user/install.md){ .md-button .md-button--primary }
[Télécharger le firmware](downloads.md){ .md-button }

!!! warning "Avant d’installer"
    L’installation efface le portefeuille et supprime définitivement
    l’attestation constructeur d’origine. feuristic est indépendant de Trezor
    Company et de SatoshiLabs. Une campagne physique a validé les opérations
    principales sur T2B1/macOS ; les essais matériels T3B1 et la recette
    complète sont en cours. Gardez un second moyen de connexion pour vos comptes
    importants.

![Cinq écrans feuristic : verrouillage, validation d’une passkey, passkeys enregistrées, code TOTP et QR de sauvegarde chiffrée](assets/screens.svg){ loading=lazy width="1600" height="840" }

## Fonctions disponibles

| Fonction | Interface | Guide |
|---|---|---|
| Passkeys et clé de sécurité | FIDO2 / WebAuthn, CTAP 2.1, U2F | [FIDO2](features/passkeys.md) |
| Signature et déchiffrement OpenPGP | OpenPGP Card 3.4, GnuPG | [OpenPGP](features/openpgp.md) |
| Certificats et authentification | PIV, PC/SC, clients PKCS#11 | [PIV](features/piv.md) |
| Codes à usage unique | TOTP / HOTP, import d’images QR | [OTP](features/otp.md) |
| Chiffrement et nombres aléatoires | AES-256-GCM / APDU ISO 7816 | [AES et RNG](features/aes.md) |
| Sauvegarde chiffrée des identités | Séquences QR, restauration PNG/JPEG | [Sauvegarde](features/backup.md) |

## Installer en trois étapes

1. **Identifier le modèle et télécharger.** Choisissez le `.bin` T2B1 ou T3B1
   dans les [téléchargements](downloads.md), puis vérifiez son SHA-256.
2. **Ouvrir le bootloader et installer.** Sur un appareil de test déjà sauvegardé,
   déverrouillez une seule fois le bootloader, puis sélectionnez le fichier dans
   Trezor Suite ou envoyez-le avec `trezorctl`. Confirmez les demandes sur
   l’appareil. Le binaire ne se copie pas sur le volume d’import OTP.
3. **Créer le PIN de l’appareil.** Acceptez l’avertissement tiers, choisissez
   anglais ou français, puis suivez le [guide d’utilisation](user/guide.md).

Lisez la [procédure complète](user/install.md) avant l’étape 2. Elle précise les
effets irréversibles, la séquence des boutons et le chemin de récupération.

## Interfaces et commandes

![Modes USB feuristic : FIDO et carte à puce, synchronisation série, import QR](assets/usb-modes.svg){ loading=lazy width="1440" height="600" }

Le mode normal expose FIDO HID et un lecteur de carte CCID. La synchronisation
utilise temporairement un port série ; l’import QR utilise un volume FAT12.
Ces modes sont exclusifs et reviennent au mode normal à la fin.

- Gauche : précédent. Droite : suivant. Les deux : confirmer.
- Maintenir gauche : revenir ou refuser. Les actions destructives demandent un maintien de confirmation.
- Le PIN de l’appareil protège le stockage. Les identifiants FIDO, OpenPGP et PIV sont distincts.

## Validation et travaux restants

Le [rapport T2B1 physique](acceptance/campaign-2026-10-21-T2B1-macos.md) consigne
les signatures vérifiées, AES-GCM, les imports OTP, l’horloge et la persistance
après mise à jour. Le [registre de recette](acceptance/README.md) distingue ces
résultats des tests sur émulateur et liste les essais restants.

Consultez aussi l’[architecture](architecture.md), le [modèle de menace](threat-model.md)
et les [références des protocoles](protocols/fido2.md).
