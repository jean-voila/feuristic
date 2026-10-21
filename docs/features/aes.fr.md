---
title: "Chiffrement AES-GCM et nombres aléatoires matériels"
description: "Profil AES-256-GCM et GET CHALLENGE ISO 7816 de Feuristic, avec nonces générés sur l’appareil et consentement physique."
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# AES-GCM et nombres aléatoires

Feuristic propose **AES-256-GCM** par APDU ISO 7816, avec des nonces générés
par l’appareil. Le profil accepte jusqu’à **3 584 octets** de message et
**256 octets** de données associées (AAD).

Créez une clé sous **Cryptographie → AES → Créer une clé**. Choisissez sa
politique de confirmation et lisez la demande sur l’écran. Une politique
« Une fois par session » autorise les opérations de cette session après une
confirmation ; elle demande une nouvelle autorisation après redémarrage.

Les 16 identifiants ont un nom, un état actif et une politique. Le verrouillage,
la réinitialisation et les changements de mode USB terminent les autorisations
de session. Ce profil versionné de carte à puce n’est pas une interface de
chiffrement en masse.

Les données, étiquettes d’authentification et erreurs doivent respecter la
[référence AES-GCM](../protocols/aes-gcm-iso7816-v1.md). Un échec de vérification
de l’étiquette ne doit pas être traité comme un texte déchiffré valide.

Le service ISO 7816 **GET CHALLENGE** fournit de 1 à 32 octets aléatoires avec contrôles
de santé et limites de débit. Ses règles figurent dans la
[référence CCID](../protocols/ccid.md).

**Cryptographie → Aléa** affiche la santé et un autotest local. Des sorties
différentes ne constituent pas une certification d’entropie.

La campagne physique a vérifié les échanges AES-GCM, les limites du profil et
l’absence de réemploi des nonces observés après redémarrage et mise à jour.
Consultez le [rapport](../acceptance/campaign-2026-10-21-T2B1-macos.md) et le
[format de sauvegarde AES](../protocols/backup-aes.md).
