---
title: Installer un firmware personnalisé sur Trezor Safe 3
description: Installer feuristic sur T2B1 ou T3B1 avec le bootloader officiel, Suite ou trezorctl. Vérification, déverrouillage irréversible, mises à jour et récupération.
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Installation pour essais matériels / Hardware test installation

**Version 0.x pour T2B1 et T3B1.** Les opérations principales ont été
vérifiées lors d’une première campagne physique T2B1/macOS. La recette
matérielle complète est en cours. Consultez le [rapport](../acceptance/campaign-2026-10-21-T2B1-macos.md).

## Installer en trois étapes

1. **Télécharger et vérifier.** Identifiez le modèle interne avec
   `trezorctl get-features`, puis téléchargez son `.bin` dans les
   [versions GitHub](https://github.com/jean-voila/feuristic/releases).
   Vérifiez son [SHA-256](../downloads.md) et sauvegardez le portefeuille existant.
2. **Déverrouiller et installer.** Reconnectez en maintenant gauche, activez
   **Init connection**, puis déverrouillez une seule fois avec
   `trezorctl device unlock-bootloader`. Confirmez l’effacement irréversible.
   Reconnectez en bootloader et ouvrez **Trezor Suite → Settings → Device →
   Danger Area → Install custom firmware**. Sélectionnez ou glissez le `.bin`
   dans la zone de téléchargement et confirmez sur l’appareil. La procédure
   CLI détaillée ci-dessous a été testée sur T2B1 avec le bootloader 2.1.16.
3. **Démarrer feuristic.** Acceptez l’avertissement tiers, choisissez la langue
   et créez un PIN de test. Continuez avec le [guide d’utilisation](guide.md).

L’installation efface le portefeuille et supprime définitivement l’attestation
constructeur. Le retour au firmware officiel ne la restaure pas. Le volume
d’import OTP ne sert pas à installer un firmware.

## Conséquences à accepter avant toute manipulation

Utiliser un appareil dédié aux essais, sans fonds ni identités de production.
Conserver les sauvegardes existantes hors de cet appareil. feuristic ne restaure
aucune phrase Trezor et ne migre aucun portefeuille.

Le déverrouillage du bootloader est **irréversible**. Il efface le stockage et
les secrets d'appairage Optiga ; la preuve d'authenticité constructeur et
l'attestation FIDO d'origine ne sont plus utilisables. Le firmware continue
avec les protections restantes du stockage, mais ne revendique pas la même
configuration d'attestation qu'un appareil d'origine. feuristic emploie une
attestation FIDO propre à son profil, sans certification constructeur.

Preuves dans la base épinglée :

- [workflow de déverrouillage](https://github.com/trezor/trezor-firmware/blob/66ac7295aaa0aa9fb427a0cc035b34dd61b6d472/core/embed/projects/bootloader/workflow/wf_unlock_bootloader.c) : confirmation locale, `erase_storage`, puis `secret_unlock_bootloader` ;
- [secret STM32F4](https://github.com/trezor/trezor-firmware/blob/66ac7295aaa0aa9fb427a0cc035b34dd61b6d472/core/embed/sec/secret/stm32f4/secret.c) et [secret STM32U5](https://github.com/trezor/trezor-firmware/blob/66ac7295aaa0aa9fb427a0cc035b34dd61b6d472/core/embed/sec/secret/stm32u5/secret.c) : effacement du secret ou des emplacements privés ;
- [initialisation Optiga](https://github.com/trezor/trezor-firmware/blob/66ac7295aaa0aa9fb427a0cc035b34dd61b6d472/core/embed/sec/optiga/optiga_init.c) : perte du canal protégé et des attestations lorsque le secret n'est plus disponible ;
- [en-tête tiers T2B1](https://github.com/trezor/trezor-firmware/blob/66ac7295aaa0aa9fb427a0cc035b34dd61b6d472/core/embed/models/T2B1/vendorheader/vendor_unsafe.json) et [T3B1](https://github.com/trezor/trezor-firmware/blob/66ac7295aaa0aa9fb427a0cc035b34dd61b6d472/core/embed/models/T3B1/vendorheader/vendor_unsafe.json) : avertissement `UNSAFE, DO NOT USE!`, clic utilisateur et délai.

Cet avertissement revient au démarrage. Le remplacer par un message de
confiance constructeur n'est pas une étape d'installation.

**Recommandé : démarrer une fois le firmware officiel avant de déverrouiller.**
La première fois que le firmware officiel Trezor démarre sur un stockage vide,
il verrouille définitivement les objets de l’élément sécurisé qui limitent les
essais de PIN. feuristic continue d’utiliser ces objets mais ne réalise jamais
lui-même ce verrouillage irréversible. La plupart des appareils ont déjà
exécuté le firmware officiel ; un appareil neuf déverrouillé immédiatement les
laisse déverrouillés. Voir [sécurité matérielle](../hardware-security.md).

## Préparer le binaire et les outils

Depuis la racine du dépôt déjà préparé :

```sh
uv run trezorctl --help
uv run trezorctl device unlock-bootloader --help
uv run trezorctl firmware update --help
```

`trezorctl` provient du sous-module épinglé, via l'environnement `uv` du projet.
Prévoir un câble USB de données fiable et une alimentation stable. Fermer Suite,
les navigateurs et les autres clients de l'appareil avant le flash.

Construire **le modèle exact**, par exemple T2B1 :

```sh
make firmware MODEL=T2B1
```

Sélectionner le fichier de ce modèle, de cette version et du commit courant
avec les commandes suivantes. Si la campagne fournit un autre artefact,
définir `FW` avec son chemin exact et comparer au manifeste reçu. Ne pas
utiliser un fichier `DEBUG.bin`.

```sh
FEURISTIC_TEST_MODEL=T2B1
FEURISTIC_TEST_VERSION=$(uv run --quiet python -c "import sys; sys.path.insert(0,'src'); from feuristic.version import VERSION; print(VERSION)")
FEURISTIC_TEST_REV=$(git rev-parse --short=12 HEAD)
FW="$PWD/dist/feuristic-$FEURISTIC_TEST_VERSION-$FEURISTIC_TEST_MODEL-$FEURISTIC_TEST_REV.bin"
```

Depuis le dossier contenant le binaire et son fichier `.sha256`, vérifier ensuite :

```sh
shasum -a 256 -c "$(basename "$FW").sha256"
uv run trezorctl firmware update --dry-run --filename "$FW"
```

Le dry-run requiert un appareil détectable ; il valide les étapes hôte sans
écrire le firmware. Les builds d'essai utilisent les clés de développement
publiques amont : un avertissement de clés de développement peut apparaître.
Un SHA-256 assure l'intégrité par rapport au manifeste reçu ; il ne prouve pas
à lui seul l'identité de son émetteur. Une erreur de modèle, d'en-tête ou de
signature doit être diagnostiquée avant tout flash. Ne pas contourner ces
contrôles avec `--raw` ou `--skip-check`.

## Déverrouiller puis installer

1. Noter le modèle, la version de bootloader, la révision du dépôt et le
   SHA-256 du binaire dans le journal de [recette](../acceptance/README.md).
2. Démarrer en bootloader : débrancher puis reconnecter le Safe 3 en maintenant
   le bouton gauche. Si le sous-menu propose « Factory Reset », « Exit menu »
   et « Reboot Trezor », sélectionner « Exit menu » avec gauche/droite et valider
   avec les deux boutons. Depuis l'écran principal du bootloader, choisir
   « Init connection » à gauche pour activer l'USB ; avant cette action,
   `trezorctl` peut ne détecter aucun appareil. Les indications affichées
   par l'appareil priment si son bootloader demande une autre séquence.
3. Après lecture des conséquences ci-dessus, lancer :

   ```sh
   uv run trezorctl device unlock-bootloader
   ```

   Confirmer physiquement le déverrouillage sur l'appareil. L'effacement est
   effectué par le bootloader. Annuler à l'écran permet de renoncer avant cet
   effacement, pas de restaurer les secrets après confirmation.
   Lorsque « Bootloader unlocked / Please reconnect the device » apparaît,
   débrancher/rebrancher puis reprendre l'étape 2, y compris « Init connection ».
4. Toujours dans le bootloader, installer le fichier déjà vérifié :

   ```sh
   uv run trezorctl firmware update --filename "$FW"
   ```

5. Vérifier le modèle et les avertissements sur l'appareil, confirmer, puis
   attendre la fin sans retirer le câble. Redémarrer si demandé.
6. Le premier démarrage doit montrer l'avertissement tiers, le choix de langue,
   puis la création du PIN. Suivre [R01](../acceptance/R01.md) avant les autres
   essais. Un échec reste un défaut de candidat à enregistrer, jamais une
   qualification implicite.

La [procédure officielle Trezor](https://trezor.io/support/troubleshooting/device-issues/install-custom-firmware-on-trezor-safe-3)
décrit l'installation d'un fichier via Suite et les confirmations du bootloader.
Elle ne constitue pas une validation de feuristic. La procédure ci-dessus
utilise les commandes standard disponibles dans le code amont épinglé.

## Mise à jour et récupération

**Mettre à jour feuristic conserve vos données.** Toutes les images feuristic
portent le même en-tête fournisseur et la même version d’en-tête : le
bootloader conserve donc le stockage quand vous installez une autre image
feuristic par-dessus. Comme la version d’en-tête n’augmente pas, le
bootloader demande une confirmation sur l’appareil. Avant de mettre à jour :

1. Exportez vos identités dans une sauvegarde QR chiffrée et gardez la phrase
   de passe à part.
2. Vérifiez à nouveau le modèle et l’empreinte de la nouvelle image.
3. Démarrez en bootloader et relancez `firmware update --filename`. Ne
   déverrouillez pas à nouveau un appareil déjà déverrouillé.

Les versions postérieures à la 0.1.0 refusent au démarrage, avant le PIN, un
stockage écrit par un format plus récent. Si vous revenez à une version
antérieure après un tel changement, l’appareil affiche **Données d’un
feuristic plus récent** : réinstallez l’image plus récente, ou effacez
l’appareil et restaurez votre sauvegarde.

**Un autre firmware peut aussi conserver vos données.** Le bootloader conserve
le stockage pour toute image portant le même en-tête fournisseur
`UNSAFE, DO NOT USE!`, pas seulement feuristic. Un tel firmware peut lire vos
clés feuristic dès que vous saisissez votre PIN. Effacez l’appareil
(**Réglages → Effacement intégral**, ou **Factory Reset** dans le bootloader)
avant d’installer un firmware auquel vous ne faites pas confiance. Le firmware
officiel Trezor a un autre en-tête fournisseur : l’installer efface le
stockage de feuristic.

**PIN oublié.** Après 16 PIN faux, l’appareil efface son stockage. Vous pouvez
aussi l’effacer immédiatement avec **Factory Reset** dans le bootloader :
maintenez gauche à la connexion, ouvrez le menu et confirmez. Configurez
ensuite feuristic à nouveau et restaurez votre sauvegarde. Sans sauvegarde,
les passkeys, secrets OTP et clés de carte sont perdus : enregistrez de
nouveau l’appareil auprès de chaque service.

**L’application ne démarre plus.** Utilisez le bootloader officiel :
maintenez gauche à la connexion et envoyez une image connue du bon modèle. Ne
remplacez ni le boardloader ni le bootloader et n’utilisez pas les commandes
SWD/DFU prévues pour les cartes vierges. Pour revenir au firmware officiel,
suivez les instructions actuelles du constructeur ; cela efface les données
de feuristic et ne restaure pas l’attestation d’usine.

Voir [sécurité matérielle](../hardware-security.md) pour les protections qui
subsistent après le déverrouillage.
