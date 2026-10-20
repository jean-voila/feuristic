<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Reprise autonome — 20 octobre 2026

**Branche courante : `main`, HEAD `4d0077f48601afc4d4c192af66b17bbce2276d99`.**
La CI de ce commit est verte. Les corrections ultérieures sont encore dans
l'arbre de travail : elles ne constituent **pas un candidat final**. Le budget
RAM matériel de 171 492 octets reste à qualifier et aucun essai physique
R01–R16 n'a été exécuté. Les anciens binaires de `dist/` ne représentent pas
la source actuelle.

## Mandat et contexte à conserver

La session Claude Desktop **« Feuristic firmware development »**,
ID `03bd068b-7780-424e-810b-816465f6c010`, son développement initial et les journaux
de 14 sous-agents ont été archivés hors dépôt : 46 fichiers avec empreintes et
extractions lisibles. Ne pas ajouter ces journaux privés au dépôt. La reprise
vise le firmware complet des deux révisions Safe 3, avec agents spécialisés,
implémentations effectives et vérifications indépendantes.

Le [cahier des charges](../spec/cahier-des-charges-v1.0.md) est normatif :
GPL-3.0-only, administration sur l'appareil, sans compagnon obligatoire, compte,
cloud, télémétrie ou cryptomonnaie. Conserver la branche courante, sans nouveau
worktree ; aucun commit/push n'est autorisé par cette note. Ne pas manipuler
un appareil physique dans cette phase. La base `trezor-firmware core/v2.12.5`
est intégrée par les dix patchs exportés, sans enregistrer la tête locale
patchée comme référence du sous-module. Voir [architecture](../architecture.md),
[patches](patches.md) et [compatibilité MicroPython](micropython-compat.md).

## État actuel

Les menus FR/EN FIDO2, OTP, OpenPGP, PIV, AES/RNG et sauvegarde/restauration
appellent les opérations réelles. Les actions sensibles redemandent le PIN
appareil ; les actions destructrices exigent un maintien continu des deux
boutons. NORMAL expose FIDO HID et CCID ; la synchronisation utilise CDC-ACM
seul et l'import MSC FAT12 seul, jusqu'à l'éjection hôte. Le verrouillage ferme
workers/pollers et libère les références privées. Le RNG public reste accessible
verrouillé ; le lecteur déjà alimenté devient privé après déverrouillage.

Les corrections non enregistrées à préserver concernent :

| Domaine | État de la correction |
|---|---|
| Temps/autoverrouillage | Compteur monotone MCU étendu et entretien toutes les 60 s ; tests simulant 40 jours et plusieurs wraps. Le trafic USB seul ne repousse plus les cinq minutes d'inactivité |
| Nonces AES | Namespace de 64 bits dérivé du secret maître, de la clé et de l'époque du compteur, suivi d'un index de 32 bits ; anciens chiffrés compatibles, plancher persistant non régressif et cache borné |
| Mémoire NORMAL | Applets CCID créées au SELECT ; sélection/libellés FIDO paresseux ; tables STRINGS stables sans copie centrale ; `RecordIndex` et `CredentialIndex` en arenas fixes, sans changement du format persistant |
| Index sous manque de mémoire | Déplacement des métadonnées FIDO sans slices allouées pendant mutation ; effacement réutilisant l'arena existante. Deux défauts reproduits, corrigés et revus indépendamment |
| Mémoire IMPORT | Purge après suspension des transports, puis déchargement des providers entre identités ; registre, traductions et horloges conservés. Appelant OTP sans références aux anciens modules/comptes ; progression KDF séparée de l'export |
| Décodeur natif | Scratch image/QR partagé et API `fimg_init_scattered()` en blocs disjoints alignés sur huit octets, de 16 Kio maximum ; historique DEFLATE de 32 Kio et binariseur segmentés |

La restauration traite une identité à la fois : pause/libération du décodeur,
authentification complète, validation avant écriture, confirmation, écriture
atomique par identité, libération puis reprise du décodeur. Les copies refusées
pendant la pause renvoient NOT READY avec le résidu complet ; aucune image
acquittée n'est jetée silencieusement. Les bornes appareil sont **une identité,
12 Kio collectés, 192 enveloppes et quatre sels par session**. Le cas OpenPGP de
234 images passe en lots de 32 noms courts, avec suppression des fichiers déjà
traités dans la même session. Voir [mémoire import](import-memory.md) et
[préparation sauvegarde](backup-readiness.md).
La source conserve une sortie interne T2B1 de 384 pixels, sans réduire les
limites d'entrée de 1024×1024 et 256 Kio ; ce choix reste à qualifier en RAM.

## Propriétés des fichiers et coordination

Tous les agents partagent le checkout : ne pas réinitialiser leurs modifications.
Coordonner toute édition partagée et tout remplacement de binaire utilisé.

| Agent | Périmètre actuel |
|---|---|
| `root` | Intégration ; `core/packed_index.py`, `core/store.py`, FIDO credentials/CTAP, i18n, transports/session ; preuve RAM NORMAL, CI et candidats |
| `management_ui` | Menus/chaînes de gestion, OTP, progression sauvegarde, CCID paresseux, tests UI/import/lifecycle et C segmentés ; cette note et audit logiciel global |
| `backup_ui` | Bridge natif `modfeuristic_import`, import/restauration et quotas, temps monotone/nonces AES, pont natif des cinq providers |
| `documentation` | `lib/fimg` segmentée, arbre/build i686 frozen, preuve RAM RESTORE, guides/acceptation. Coordonner les fichiers `fw/session.py`, `fw/transports.py`, `fw/import_mode.py` avec root |

Ports des suites : root `22000`, management `26000`, backup `28000`.
L'interop locale utilise `30000`, les wrappers `build/interop-bin`, le container
`feuristic-interop` et **un seul endpoint PC/SC `35963`** : les deux modèles
passent séquentiellement. Le container RAM `feuristic-memory32-cross` et l'arbre
`build/emu32-tree` sont isolés de la production ; ne pas relancer leur préparation
pendant un build/une sonde, ni reconstruire un artifact utilisé par un autre agent.

## Vérifié, avec la portée exacte des preuves

La [CI 39208735751, tentative 2](https://github.com/jean-voila/feuristic/actions/runs/39208735751/attempts/2)
est entièrement verte sur **`4d0077f`** : treize jobs, dont les deux firmwares,
les deux suites émulateur, C/ARM/fuzz et les deux builds reproductibles. Elle
ne couvre pas les modifications ultérieures encore non enregistrées.

| Vérification | Résultat |
|---|---|
| Host complet avant packed | 2 105 PASS, 2 skips, couverture 88,40 % ; `/tmp/feuristic-host-current.log` |
| Audit host complet du 20 octobre après packed | **2 107 PASS, 2 skips, couverture 88,44 %**, 26,96 s ; `/tmp/feuristic-host-audit20.log`, XML/coverage de même préfixe. Deux avertissements JUnit `record_property` du harnais, aucun échec |
| Stockage/FIDO/PIV/sauvegarde après packed | 900 PASS, un skip ; `/tmp/feuristic-packed-index-final.log` |
| Vérification indépendante packed | 21/21 PASS après les deux correctifs OOM ; `/tmp/feuristic-packed-independent-review.log` |
| Fonctionnels complets antérieurs | 56/56 PASS T3B1 en 524,85 s et T2B1 en 521,03 s, alertes de threads traitées en erreurs |
| Régressions purge/lazy/progress T2 | 18/18 PASS puis 3/3 restauration/progress ; `/tmp/feuristic-t2-lazy-purge-regression.log`, `/tmp/feuristic-t2-progress-restore.log` |
| Inventaire fonctionnel actuel | **61 collectés hors interop**, incluant les nouvelles suites MicroPython ; pas encore 61 exécutés avec succès sur chaque modèle final |
| Interop réelle après lazy CCID | GnuPG status/génération/signature/vérification, OpenSC GET CHALLENGE et PIV : 4/4 T2 en 38,70 s, 4/4 T3 en 39,50 s ; `build/interop-final-T2B1.xml`, `build/interop-final-T3B1.xml` |
| C segmenté ASan/UBSan | 3/3 PASS ; 286 vecteurs et 2 809 046 checks contigu/segmenté/pagé. API finale 33 609 checks, dont 14 336 géométries ; `/tmp/feuristic-c-scattered-final.log`, `/tmp/feuristic-c-scattered-api-final.log` |
| ARM/fuzz segmenté | Huit builds M4/M33 `-Werror` ; 280 414 exécutions sans défaut : PNG 129 339, inflate 19 047, JPEG 132 028 ; `build/fimg-segmented-{arm,png-fuzz,inflate-fuzz,jpeg-fuzz}.log` |
| Contrôles statiques du 20 octobre | Ruff et format Python/C, compatibilité MicroPython (125 fichiers), SPDX et shellcheck passent ; nouveaux fichiers C/SPDX non enregistrés contrôlés également ; logs `/tmp/feuristic-audit20-*.log` |

Le pont natif des cinq providers exporte, efface norcow, change le secret maître,
restaure en IMPORT et revient en NORMAL, puis utilise réellement les identités.
Il passe sur les deux émulateurs et ne remplace pas R14 physique.

Les builds reproductibles de **`4d0077f`**, et seulement de ce commit, donnent :

| Modèle | SHA-256 firmware |
|---|---|
| T2B1 | `497e38fcc9ef31e9d1f1243a23d74f9b31e4794f65dd10e4c221575382453e56` |
| T3B1 | `7bc7d1b222df9d0d5cc2367296520d3cadf7906be11c031a5ddb41b0ec0474b0` |

Logs : `build/reproducible-4d0077f-T2B1.log` et
`build/reproducible-4d0077f-T3B1.log`. Artefacts/checksums téléchargés :
`build/ci-4d0077f/{T2B1,T3B1}/`. Ces hashes ne désignent pas la source actuelle.

## Restant, dans cet ordre

La RAM est la gate immédiate. Les **171 492 octets** viennent du linker T2B1,
pas d'une mesure de heap libre. Les anciennes sondes i686 frozen ont échoué :
fragmentation en petits trous dans NORMAL, puis allocations image/bitmap dans
IMPORT. La segmentation C et les arenas packed corrigent des causes identifiées,
mais **aucune preuve complète finale de capacité n'est encore acquise**. Ne pas
diviser une mesure 64 bits par deux pour annoncer un fit matériel.

1. **NORMAL 32 bits** : utiliser le nouveau `tools/probe_normal_memory32.py`,
   à freezer comme `feuristic.fw.normal_memory_probe` via la préparation isolée.
   Il exécute deux processus, peuplement puis rechargement : 100 FIDO à champs
   maximaux, 32 HOTP et 4 Kio largeBlobs. Vérifier RP distincts, applets sélectionnées
   et réserve de heap ; le reload doit mesurer le pic temporaire `owners`.
   Ce nouveau driver n'est pas encore qualifié frozen 32 bits. Ne pas relancer
   les anciens `probe-normal-*.py` temporaires ou leurs anciens binaires.
2. **RESTORE 32 bits** : reconstruire le snapshot final, bridge segmenté avec
   préallocations triées, NORMAL préchauffé et MSC hors heap comme la CCM réelle.
   Exécuter les providers maximaux avec PBKDF2 réel à 600 000 itérations et chaque
   reprise du décodeur. Les anciens `build/restore-memory32-sorted*.log` sont des
   traces d'échecs, pas des PASS. Conserver les largest free blocks et le manifeste
   exact `build/emu32-tree/source-snapshot.json`. Procédure : `import-memory.md`.
3. Après stabilisation : reconstruire les deux émulateurs avec le natif final,
   puis host/couverture, C/lint, **61 fonctionnels actuels sur
   les deux modèles**, nouvelles suites MicroPython et quatre interops par modèle,
   sans alerte de thread. Recompter si la collection change ; collecte ≠ succès.
4. Faire valider l'enregistrement de la source finale, puis CI/reproductibilité
   de ce commit exact. Produire ensuite les deux candidats sans debug, checksums,
   SBOM/provenance et préparation R01–R16. Ne pas publier stable avant les résultats
   physiques des deux modèles.

Les PID USB de test `1209:0001`, clés de signature de développement amont et
lisibilité physique des QR restent des gates de publication. La zéroïsation
complète des copies immuables MicroPython et buffers de saisie Rust n'est pas
garantie ; conserver cette limite dans le modèle de menace/R15.

## Commandes de reprise

Depuis la racine, après coordination des ressources concernées. Le fichier
`/tmp/feuristic-T2B1-debug-final` conservé pour les dernières interops contient
encore le natif **contigu antérieur**, avec Python applicatif chargé depuis les
sources. Il sert aux régressions Python, pas à qualifier le nouveau bridge
segmenté : reconstruire et choisir le binaire final avant la campagne finale.

```sh
git status --short
git log -1 --oneline
uv run --no-sync pytest --collect-only -q tests/functional --ignore=tests/functional/interop
uv run --no-sync pytest -q tests/host --cov
make test-c
make lint
shellcheck tools/*.sh tools/ci/*.sh

# Régression Python sur l'ancien debug conservé ; choisir le nouveau binaire
# segmenté après reconstruction pour qualifier la production finale.
FEURISTIC_EMU=/tmp/feuristic-T2B1-debug-final FEURISTIC_EMU_BASE_PORT=26000 \
  uv run --no-sync pytest -vv tests/functional --ignore=tests/functional/interop \
  -W error::pytest.PytestUnhandledThreadExceptionWarning --junitxml=build/final-T2B1.xml

# PC/SC : T2 puis T3, jamais simultanément.
PATH="$PWD/build/interop-bin:$PATH" TMPDIR="$PWD/build/interop-tmp" \
  FEURISTIC_INTEROP=1 FEURISTIC_EMU=/tmp/feuristic-T2B1-debug-final \
  FEURISTIC_EMU_BASE_PORT=30000 uv run --no-sync pytest -q tests/functional/interop \
  -W error::pytest.PytestUnhandledThreadExceptionWarning --junitxml=build/interop-final-T2B1.xml

# Seulement après rebuild i686 frozen contenant normal_memory_probe.
uv run --no-sync python tools/probe_normal_memory32.py \
  --emulator build/feuristic-memory32-latest-unix \
  --container feuristic-memory32-cross --heap 171492 --reserve 8192
```

Pour T3, choisir `upstream/trezor-firmware/core/build-xtask/artifacts/T3B1/firmware-emu`
et un port distinct si une autre suite tourne. Les debug se reconstruisent par
`make emu MODEL=T2B1`/`T3B1` après coordination. L'arbre i686 se prépare par
`tools/prepare_import_memory32.py` avant son build isolé ; les adaptations PRNG
hôte, contexte secp256k1 i686 et MSC en `.bss` n'appartiennent pas à la production.
Les tests sautent si le binaire manque : vérifier systématiquement PASS et skips.
