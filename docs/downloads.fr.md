---
title: "Télécharger le firmware Trezor Safe 3"
description: "Télécharger les binaires Feuristic T2B1 et T3B1, vérifier leurs empreintes SHA-256 et installer le firmware personnalisé sur un Trezor Safe 3."
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Télécharger Feuristic

[Ouvrir les versions GitHub](https://github.com/jean-voila/feuristic/releases){ .md-button .md-button--primary }

Utilisez une **préversion de développement étiquetée** tant que la recette
matérielle reste incomplète. Les préversions ne figurent pas forcément derrière
le lien `/releases/latest` de GitHub : ouvrez la liste des versions et choisissez
la version explicitement. Tant que le dépôt est privé, un compte autorisé est
nécessaire pour télécharger ses fichiers.

| Modèle interne | Fichier |
|---|---|
| **T2B1** | `feuristic-<version>-T2B1-<commit>.bin` |
| **T3B1** | `feuristic-<version>-T3B1-<commit>.bin` |

Une version comprend les deux binaires, leurs fichiers SHA-256, `SHA256SUMS`,
un SBOM SPDX, un manifeste de provenance, les sources correspondantes et les
licences. Les builds de débogage ne sont pas des candidats à l’installation.
L’archive ZIP automatique de GitHub ne contient pas les sous-modules ; utilisez
l’archive de sources fournie avec la version.

## Vérifier avant d’installer

Placez `SHA256SUMS` et votre `.bin` dans le même dossier.

=== "macOS"

    ```sh
    shasum -a 256 -c SHA256SUMS --ignore-missing
    ```

=== "Linux"

    ```sh
    sha256sum --ignore-missing -c SHA256SUMS
    ```

=== "Windows PowerShell"

    ```powershell
    Get-FileHash .\feuristic-*-T2B1-*.bin -Algorithm SHA256
    ```

    Comparez le résultat à la ligne correspondante de `SHA256SUMS`. Remplacez
    T2B1 par T3B1 si c’est le modèle interne de votre appareil.

Ces empreintes vérifient l’intégrité par rapport au manifeste reçu. Les images
emploient les clés publiques de développement amont et conservent l’avertissement
obligatoire ; ce ne sont pas des firmwares signés par le constructeur.

## Installer et récupérer

Suivez l’[installation](user/install.md). Suite permet de sélectionner un fichier
local ; `trezorctl firmware update --filename <file.bin>` l’envoie depuis un
terminal. Ne copiez pas le binaire sur le volume temporaire d’import QR.

Si l’application ne démarre plus, ouvrez le bootloader officiel et installez
un binaire connu du bon modèle. Ne remplacez ni boardloader ni bootloader.
Réinstaller le firmware officiel ne restaure pas l’attestation d’usine.
