---
title: Sécurité matérielle du Trezor Safe 3
description: Comment feuristic utilise l’élément sécurisé Optiga Trust M du Trezor Safe 3, quelles protections matérielles subsistent après le déverrouillage du bootloader, ce qui est volontairement exclu et les risques résiduels.
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Sécurité matérielle du Trezor Safe 3

Cette page décrit ce que le matériel du Safe 3 protège réellement dans
feuristic. Elle s’appuie sur les sources amont épinglées (`core/v2.12.5`).
Chaque point marqué **source** a été vérifié dans ce code. **À vérifier sur
appareil** signale ce qui reste à observer sur un appareil physique.
L’émulateur n’a pas d’élément sécurisé : son pilote Optiga est un bouchon,
aucun test sur émulateur n’exerce donc la puce.

## Résumé

| Protection | État dans feuristic | Preuve |
|---|---|---|
| Stockage protégé chiffré par une clé qui exige le PIN **et** des secrets internes à l’Optiga | Actif pour tous les secrets feuristic (secret maître, passkeys, OTP, OpenPGP, PIV, clés AES, état du PIN FIDO) | Source ; campagne T2B1 déverrouillage/persistance |
| Limites d’essais de PIN imposées par les compteurs de l’Optiga, effacement après 16 PIN faux | Actif (stockage amont) | Source ; R15 à vérifier sur appareil |
| Génération des clés par TRNG du MCU XOR TRNG de l’Optiga | Actif pour toutes les clés durables, le secret maître, les sels et les identifiants de sauvegarde | Source ; `tests/host/test_hardware_invariants.py` |
| Arrêt de l’appareil si l’Optiga échoue pendant la vérification du PIN ou l’aléa fort | Actif (`ensure` amont) | Source |
| Clés d’attestation du fabricant (`0xE0F0`, `0xE0F2`) | **Perdues** après le déverrouillage ; FIDO utilise l’auto-attestation | Source |
| Clés d’identité générées et utilisées dans l’Optiga | **Non utilisé**, par décision (voir plus bas) | — |
| Configuration irréversible de l’Optiga par feuristic | **Jamais** (pas de compilation `--production`, aucun appel direct à l’Optiga) | Tests de garde |

## Ce que contient l’Optiga Trust M

Le code amont configure ces objets sur un Safe 3 (un seul emplacement de PIN
étiré, `STRETCHED_PIN_COUNT = 1`, 16 essais de PIN) :

| Objet | Rôle | Condition d’accès (source) | Après déverrouillage |
|---|---|---|---|
| `0xE0F0` clé d’appareil, `0xE0E1` certificat | Preuve d’authenticité Trezor | exécution : canal blindé avec le secret d’appairage `0xE140` | inutilisable : la copie MCU du secret d’appairage est effacée |
| `0xE0F2` clé FIDO, `0xE0E2` certificat | Attestation FIDO Trezor | idem | inutilisable |
| `0xF1D0` secret de PIN | secret protégé par compteur, mélangé à la clé de stockage | lecture : preuve du PIN étiré | utilisé par feuristic via le stockage amont |
| `0xF1D4` PIN étiré, `0xF1D8` clé HMAC | vérification et étirement HMAC du PIN | exécution limitée par les compteurs `0xE120`, `0xE122` | utilisé |
| `0xE200` clé AES, `0xE0F3` clé ECDH | étirement CMAC et ECDH du PIN | exécution limitée par le compteur de vie `0xE121` | utilisé |
| `0xE121` compteur de vie | 600 000 opérations d’étirement sur la durée de vie de la puce | modification : jamais | utilisé, partagé avec l’usage passé du firmware officiel |

La clé de stockage dérive du PIN, d’un sel aléatoire en flash et des
résultats des étapes d’étirement de l’Optiga. Une copie de la flash ne
suffit pas pour tester des PIN hors ligne : chaque essai passe par l’Optiga,
dont les compteurs limitent le nombre d’essais.

**Limite de durée de vie.** Chaque vérification de PIN consomme quatre
opérations d’étirement : l’Optiga autorise donc environ **150 000
vérifications de PIN** sur la vie de l’appareil. Cela comprend les
déverrouillages après le verrouillage automatique de 5 minutes et les
nouvelles saisies du PIN avant un export ou une suppression. À 30
vérifications par jour, cela représente plus de 13 ans. L’usage passé sous
firmware officiel est décompté du même budget.

## Pourquoi les clés d’identité ne sont pas stockées dans l’Optiga

La puce sait générer et utiliser des clés ECC P-256 et RSA-2048 non
extractibles. Ses objets encore libres sont un emplacement de clé ECC
(`0xE0F1`), deux emplacements RSA (`0xE0FC`, `0xE0FD`), un compteur et
quelques objets de données. feuristic n’y place ni passkeys, ni clés OpenPGP,
PIV ou AES :

1. **Elles survivraient à un effacement.** Un effacement du stockage (16 PIN
   faux, le menu de l’appareil, le bootloader, un changement de firmware)
   efface la flash du MCU, pas l’Optiga. Une clé restée dans la puce resterait
   utilisable après l’effacement censé la détruire.
2. **Leurs règles d’accès pourraient être réécrites.** Sans verrouiller les
   métadonnées d’un objet à l’état opérationnel, ce qui est irréversible,
   n’importe quel code exécuté sur le MCU pourrait plus tard changer qui a le
   droit d’utiliser la clé. Verrouiller des objets libres serait une
   modification irréversible que feuristic refuse de faire.
3. **La capacité ne suffit pas.** Un emplacement ECC ne contient pas 100
   passkeys, et le Trust M ne sait ni importer ni désencapsuler une clé privée
   sans une ancre de confiance du fabricant, rendue inutilisable par le
   déverrouillage.
4. **Les clés d’attestation ne sont plus disponibles.** Les seules clés munies
   d’un certificat du fabricant exigent le canal blindé, dont le secret
   d’appairage est effacé par le déverrouillage.

L’Optiga protège tout de même chaque clé indirectement : toutes les clés sont
dans le stockage protégé, qui ne se déchiffre pas sans le PIN et la puce.

## Ce que feuristic s’engage à ne pas faire

`tests/host/test_hardware_invariants.py` fait échouer la compilation si l’un
de ces points change :

- le code feuristic (Python, C, correctifs) n’appelle aucune API de l’Optiga,
  y compris la temporisation `set_sec_max` ;
- aucun correctif ne touche l’élément sécurisé amont, le secteur des secrets,
  le stockage du PIN, le bootloader, le boardloader, prodtest, les en-têtes de
  modèle ni les fichiers de version. L’en-tête du firmware garde la version et
  le compteur monotone amont : le firmware officiel reste réinstallable et
  aucun compteur OTP n’est consommé ;
- aucune commande de compilation ne passe `--production`, qui verrouillerait
  définitivement les métadonnées de l’Optiga ;
- la cible de version n’active jamais debuglink.

## Risques résiduels

**Remplacer le firmware conserve vos données.** Le bootloader conserve le
stockage quand la nouvelle image a le même en-tête fournisseur et une
version au moins égale à la version de correctif de l’image installée
(source : `wf_firmware_update.c`, `detect_installation`). Toutes les images
sous l’en-tête public `UNSAFE, DO NOT USE!` partagent cet en-tête et ses clés
de signature sont publiques. Une personne ayant un accès physique peut donc
installer un firmware modifié sans effacer le stockage de feuristic. Ce
firmware a toujours besoin de votre PIN, et les compteurs de l’Optiga bornent
ses essais, mais il peut enregistrer le PIN la prochaine fois que vous le
saisissez. Considérez un appareil sorti de votre contrôle comme non fiable et
effacez-le depuis le bootloader avant de le réutiliser.

**L’état de verrouillage de l’Optiga dépend de l’historique de l’appareil.**
Le firmware officiel de production verrouille les objets du PIN la première
fois qu’il démarre sur un stockage vide (source : `init_wiped_storage` →
`optiga_pin_init`). feuristic est compilé en mode développement et ne les
verrouille jamais. Sur un Safe 3 qui a exécuté le firmware officiel avant le
déverrouillage, cas habituel, les objets sont verrouillés. Sur un appareil
déverrouillé sans avoir jamais exécuté le firmware officiel, ils restent
déverrouillés ; la protection qu’offrent alors encore les conditions de
modification de l’Optiga contre un firmware malveillant est **à vérifier sur
appareil**. Pour en être sûr, démarrez une fois le firmware officiel avant de
déverrouiller.

**La cryptographie s’exécute sur le MCU.** Signatures, déchiffrement et HMAC
tournent dans le STM32 avec du code à temps constant. MicroPython ne garantit
pas que chaque copie d’un secret soit effacée de la RAM après verrouillage
(voir le [modèle de menace](threat-model.md)).

**Pas d’attestation du fabricant.** Les services qui n’acceptent que des
authentificateurs attestés refuseront feuristic.

## État des vérifications

| Propriété | Émulateur | Appareil physique |
|---|---|---|
| Déverrouillage du stockage, persistance, coupure de courant | Tests fonctionnels (deux modèles) | Campagne T2B1 du 21/10/2026 ; T3B1 à faire |
| Étirement du PIN par l’Optiga actif, arrêt en cas de panne de la puce | Non observable (bouchon) | À faire (R15) |
| Effacement après 16 essais sur les vrais compteurs de l’Optiga | Non observable | À faire (R15) |
| État de verrouillage (LcsO) des objets du PIN | Non observable | À faire : lecture avec un outil en lecture seule ; ne jamais lancer les commandes d’écriture ou de verrouillage de prodtest |
| Mélange de l’aléa fort avec l’Optiga | Garde de code uniquement | À faire (statistiques R11) |
