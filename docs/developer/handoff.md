<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Reprise du développement — 18 octobre 2026

Cette note permet de poursuivre le projet sans dépendre d'une conversation.
Le cahier des charges reste la référence :
[cahier-des-charges-v1.0.md](../spec/cahier-des-charges-v1.0.md).
**Le produit n'est pas terminé et aucune validation sur matériel réel n'a eu lieu.**

## Origine et consignes conservées

La session Claude Desktop **« Feuristic firmware development »**, identifiant
`03bd068b-7780-424e-810b-816465f6c010`, contient le développement depuis le dossier
vide. Son journal JSONL, les journaux de 14 sous-agents et les fichiers annexes
ont été retrouvés et archivés localement hors du dépôt : 46 fichiers,
31 180 781 octets avant compression. Une liste SHA-256 et des extractions
lisibles accompagnent l'archive. Les journaux bruts ne doivent pas être ajoutés
au dépôt : ils contiennent aussi le contexte privé des outils de développement.

Le mandat initial est de construire entièrement un firmware GPL-3.0-only pour
les deux révisions du Trezor Safe 3, avec administration sur l'appareil,
protocoles standards, tests nombreux, émulation, mode debug, CI et documentation.
Pas de compagnon obligatoire, de compte, de cloud, de télémétrie, ni de
cryptomonnaie. Ne pas tester ou installer sur un vrai Trezor à ce stade.
Le dépôt distant est privé : `jean-voila/feuristic`.

**Travailler sur la branche courante `main`.** Ne pas créer de branche ni de
worktree sans demande explicite. Les sources amont sont épinglées ; conserver
leur intégration par la série `patches/`, sans enregistrer par erreur le commit
local amont patché comme nouvelle référence du sous-module.

## Architecture à respecter

- Base : `trezor-firmware` `core/v2.12.5`, noyau, stockage norcow, PIN,
  MicroPython et UI Rust réutilisés. Application sous `src/feuristic/` ; code
  natif sous `firmware/` ; bibliothèques C portables sous `lib/`.
- USB normal : FIDO HID + CCID. Heure : CDC-ACM temporaire exclusif. Import :
  MSC FAT12 temporaire exclusif, suivi d'une éjection hôte avant le retour.
  Les images sont décodées en flux, en mémoire bornée (ADR-0003).
- Aucun parseur d'image, de QR ou de protocole applicatif dans le noyau.
  Les classes USB privilégiées déplacent seulement les paquets bornés.
- Stockage partagé : secteur actif de 64 Kio ; namespaces séparés ; records
  atomiques par copie avant suppression ; compteurs redondants persistants.
  L'heure de session disparaît à la coupure d'alimentation.
- Sauvegardes QR chiffrées, une identité à la fois : CBOR canonique,
  PBKDF2-HMAC-SHA-256, 600 000 itérations, AES-256-GCM et trames Base45.
  Phrase distincte du PIN, saisie et confirmations sur l'appareil.
- Le Python partagé doit respecter
  [micropython-compat.md](micropython-compat.md). Les tests CPython ne prouvent
  pas à eux seuls la compatibilité avec le runtime réduit du firmware.

Voir [architecture.md](../architecture.md), les protocoles, le modèle de menace
et les ADR pour les contrats détaillés. Ne pas déduire la conformité de la
seule présence d'un module ou d'une entrée dans le menu.

## Point d'arrêt de Claude, vérifié dans les fichiers

Le dernier commit initial était `5cdb31e` (corrections CI). Claude commençait
le test R04 du budget de stockage. Trois travaux étaient interrompus :

| Travail | État retrouvé |
|---|---|
| QR C (`fqr`) | Bibliothèque enregistrée ; tests, 311 images, générateurs, fuzz et benchmark M4 présents mais non enregistrés ; documentation manquante |
| Menus de gestion | Seul `ui/app_otp.py` présent ; adaptation de `ui/screens.py` commencée ; les cinq autres modules d'interface manquants |
| Documentation utilisateur/développeur/acceptation | Agent arrêté pendant la lecture ; plusieurs documents liés par le README n'existent pas |

Les piles FIDO2, OTP, OpenPGP, PIV, AES/RNG, sauvegarde/restauration et import
ont leurs implémentations et tests, ainsi que leurs interfaces de gestion
logique `localmgmt.py`. Le raccordement de cette logique aux menus reste un
travail réel, notamment pour les exports QR. La méthode `_call()` de
`ui/menus.py` affiche actuellement « not available » pour les modules absents.

La CI distante `39112127696`, sur `5cdb31e`, réussissait les deux firmwares,
les tests hôte, les bibliothèques C, le cross-build ARM, le fuzzing et le SBOM.
Elle échouait sur le format C de `fqr` et sur une alerte GCC
`g.br.x/y may be used uninitialized` pendant la construction de l'émulateur.
Les tests PC/SC réels ajoutés juste avant l'arrêt n'avaient donc pas été
atteints par ce run.

## Travail repris dans Codex

1. Archivage de la session et récupération de ses décisions, traces d'outils,
   résultats et tâches interrompues ; conservation des changements préexistants.
2. Initialisation complète de `geom_t` dans `fqr_detect.c` et formatage C avec
   la version épinglée 19.1.7. Le générateur de tables produit maintenant le
   même format que le contrôle CI (`gen_tables.py --check`).
3. Test R04 par le client python-fido2 inchangé : 100 passkeys avec extensions,
   32 HOTP actifs, 4 Kio de largeBlobs réécrits trois fois, mises à jour avec
   copies temporaires, refus du dépassement de capacité et rechargement.
   Les variantes habituelle et à champs maximaux passent.
4. Correction du modèle `FakeKV` : les compteurs publics ne portent pas le
   surcoût de chiffrement des valeurs protégées ; les petits items norcow
   occupent un seul bloc. Les tailles suivent le code amont, avec tests des
   frontières de blocs. Voir [storage-budget.md](storage-budget.md).
5. Même scénario maximal exécuté sur le vrai norcow de l'émulateur, avec
   mises à jour répétées pour déclencher la compaction. Suites MicroPython
   exécutées pour les deux modèles.
6. Correction du build de l'émulateur T2B1 : le placement CCM
   `.no_dma_buffers` est réservé au matériel, pas au binaire macOS.
7. Correction de `tools/fuzz.sh` pour les tableaux vides sous Bash 3.2 livré
   avec macOS ; exécution du fuzz QR et du benchmark Cortex-M4 sous QEMU.
8. Attente de la fin des threads de refus FIDO et de confirmation horaire
   avant fermeture du debuglink, pour empêcher une course au nettoyage du test.

Vérifications locales de ce lot :

| Contrôle | Résultat |
|---|---|
| Tests hôte + couverture | 2 037 passés, 2 ignorés ; couverture 90,76 % |
| Bibliothèques C, Clang ASan/UBSan | 15 suites passées |
| Bibliothèques C, GCC 16 optimisé | 15 suites passées |
| Fonctionnels T3B1 | 27 passés, 4 PC/SC ignorés ; alerte de thread corrigée ensuite |
| Régression FIDO/heure, alertes de thread en erreurs | 7 passés, aucune alerte |
| MicroPython T2B1, stockage réel émulé | 3 suites passées |
| Cross-compilation C Cortex-M4/M33 | 8 constructions passées avec `-Werror` |
| Fuzz QR local | 15 034 exécutions en 61 s, aucun échec signalé |
| Lint, format, SPDX, shellcheck et compatibilité MicroPython | passent |

Les résultats de ce premier lot sont locaux. La CI distante `39120687843`
a ensuite validé les deux firmwares et les couches hôte/C/fuzz, mais échoué
sur deux tests PC/SC : GET CHALLENGE après sélection OpenSC et GnuPG sans TTY.
Ces deux défauts ont été corrigés ; les quatre tests GnuPG/OpenSC passent
localement contre un lecteur virtuel Linux relié à l'émulateur macOS.

Le deuxième lot implémente les menus FIDO2, OpenPGP, PIV, AES/RNG et
sauvegarde, avec chaînes FR/EN, PIN appareil, confirmations maintenues,
annulation et exports chiffrés. Les 13 scénarios de gestion passent sur T3B1,
dont les contrôles CCID et python-fido2 ; 26 tests hôte couvrent les transitions
de l'interface. Le parcours de restauration fragmentée a été vérifié par
un encodeur/déchiffreur indépendant, avec mauvaise phrase puis nouvelle
tentative, export de toutes les trames et annulation.

Les guides utilisateur/développeur, les ADR 0001/0002 et les fiches
d'acceptation R01–R16 existent désormais. Le verrouillage libère les tâches,
providers et caches privés ; GET CHALLENGE reste accessible sur appareil
verrouillé. Les modes USB temporaires suspendent les tâches normales et
attendent la libération de leurs références avant d'allouer le décodeur.

La saisie native accepte maintenant les phrases de 128 octets (patch 0008).
Les fermetures du workflow parent par les écrans de saisie et de progression
ont été corrigées et testées sur MicroPython.

## Prochain travail prioritaire

1. Terminer la correction RAM d'import/restauration T2B1. Son heap matériel
   mesure 167 400 octets ; le décodeur 512 px occupe à lui seul environ
   113 Kio, hors objets Python. Le harness à 20 Mio masque cette contrainte.
   La sonde frozen et les corrections de traitement par identité sont en cours.
2. Terminer le correctif de navigation native : confirmation avec les deux
   boutons, maintien continu non cumulable, combinaison intermédiaire sans
   action latérale. Les tests natifs et une première intégration T2B1 passent ;
   la série de patchs doit être exportée après régression complète.
3. Refaire les suites complètes, les deux builds matériels, les budgets
   flash/RAM et la CI (désormais matricée sur les deux modèles d'émulateur).
   Exécuter la reproductibilité Nix, puis produire le candidat et son manifeste.
4. Établir la préparation à l'acceptation réelle, sans publier de version
   stable avant les résultats physiques R01–R16 sur les deux révisions.

Le PID USB de test `1209:0001`, la lisibilité physique des QR, les essais
R01–R16 sur les deux révisions et la reproductibilité restent des points de
publication à traiter. Le déverrouillage du bootloader et l'avertissement
tiers sont déjà documentés dans l'architecture. Le journal initial indique
aussi que Homebrew avait supprimé automatiquement `llvm@22` pendant
l'installation de SDL ; aucun logiciel n'a été supprimé pendant cette reprise.

## Commandes utiles

```sh
uv run --no-sync pytest -q tests/host --cov
make test-c
make emu MODEL=T3B1
uv run --no-sync pytest -q tests/functional
make emu MODEL=T2B1
FEURISTIC_EMU="$PWD/upstream/trezor-firmware/core/build-xtask/artifacts/T2B1/firmware-emu" \
  uv run --no-sync pytest -q tests/functional/test_upy.py
make lint
uv run --no-sync python lib/fqr/tools/gen_tables.py --check
tools/fuzz.sh 60 fqr
```

Les tests fonctionnels désactivent les suites si le binaire demandé n'existe
pas : toujours contrôler le nombre de tests passés et ignorés.
