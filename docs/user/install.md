<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Installation pour essais matériels / Hardware test installation

**Development firmware for Trezor Safe 3 T2B1 and T3B1.** A first physical
T2B1/macOS campaign passed the core workflows; full qualification remains pending.
Read the [hardware results](../acceptance/campaign-2026-10-21-T2B1-macos.md).

## Quick installation

1. **Download and verify** the `.bin` for the internal model reported by
   `trezorctl get-features` from [Releases](https://github.com/jean-voila/feuristic/releases).
   Follow [checksum verification](../downloads.md). Back up the existing wallet.
2. **Unlock and upload.** Enter the bootloader with the left button held while
   reconnecting. Activate **Init connection**, unlock once with
   `trezorctl device unlock-bootloader`, and confirm the irreversible erase on
   the device. Reconnect in bootloader mode. In Trezor Suite, open
   **Settings → Device → Danger Area → Install custom firmware** and select or
   drag the `.bin` into the upload box. Confirm the device prompts. The detailed
   CLI route below was tested on T2B1 with bootloader 2.1.16.
3. **Start Feuristic.** Accept the third-party warning, choose a language and
   create a test PIN. Continue with the [English](guide-en.md) or
   [French](guide-fr.md) guide.

Installing erases the wallet and irreversibly removes original manufacturer
attestation. Reinstalling official firmware does not restore it. Upload the
binary through the bootloader; the OTP import drive does not install firmware.

The detailed procedure below is in French. Commands are the same in either language.

## Conséquences à accepter avant toute manipulation

Utiliser un appareil dédié aux essais, sans fonds ni identités de production.
Conserver les sauvegardes existantes hors de cet appareil. Feuristic ne restaure
aucune phrase Trezor et ne migre aucun portefeuille.

Le déverrouillage du bootloader est **irréversible**. Il efface le stockage et
les secrets d'appairage Optiga ; la preuve d'authenticité constructeur et
l'attestation FIDO d'origine ne sont plus utilisables. Le firmware continue
avec les protections restantes du stockage, mais ne revendique pas la même
configuration d'attestation qu'un appareil d'origine. Feuristic emploie une
attestation FIDO propre à son profil, sans certification constructeur.

Preuves dans la base épinglée :

- [workflow de déverrouillage](../../upstream/trezor-firmware/core/embed/projects/bootloader/workflow/wf_unlock_bootloader.c) : confirmation locale, `erase_storage`, puis `secret_unlock_bootloader` ;
- [secret STM32F4](../../upstream/trezor-firmware/core/embed/sec/secret/stm32f4/secret.c) et [secret STM32U5](../../upstream/trezor-firmware/core/embed/sec/secret/stm32u5/secret.c) : effacement du secret ou des emplacements privés ;
- [initialisation Optiga](../../upstream/trezor-firmware/core/embed/sec/optiga/optiga_init.c) : perte du canal protégé et des attestations lorsque le secret n'est plus disponible ;
- [en-tête tiers T2B1](../../upstream/trezor-firmware/core/embed/models/T2B1/vendorheader/vendor_unsafe.json) et [T3B1](../../upstream/trezor-firmware/core/embed/models/T3B1/vendorheader/vendor_unsafe.json) : avertissement `UNSAFE, DO NOT USE!`, clic utilisateur et délai.

Cet avertissement revient au démarrage. Le remplacer par un message de
confiance constructeur n'est pas une étape d'installation.

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

Vérifier ensuite :

```sh
shasum -a 256 -c "$FW.sha256"
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
Elle ne constitue pas une validation de Feuristic. La procédure ci-dessus
utilise les commandes standard disponibles dans le code amont épinglé.

## Mise à jour et récupération

Avant une mise à jour Feuristic, exporter les identités et effectuer un essai
réel de restauration sur un autre appareil de test. La conservation du stockage
entre versions non qualifiées n'est pas une garantie. Vérifier à nouveau
modèle et empreinte, démarrer en bootloader et réutiliser `firmware update
--filename` ; ne pas déverrouiller à nouveau un appareil déjà déverrouillé.

Si l'application ne démarre plus, le bootloader officiel constitue le chemin de
récupération : maintenir gauche à la connexion et flasher un binaire connu du
bon modèle. Ne pas remplacer boardloader/bootloader et ne pas employer les
commandes SWD/DFU prévues pour cartes vierges. Un retour au firmware officiel
doit suivre les instructions actuelles du constructeur ; il ne récupère ni
les identités effacées ni l'attestation d'usine.
