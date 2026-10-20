<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Reprise — 20 octobre 2026

**Utilisateur : travailler seul, sans sous-agents, et limiter les validations
répétées aux changements nécessaires.** Cette instruction remplace le mode
précédent avec agents spécialisés. Conserver `main`, sans branche ni worktree.
Aucun hardware n'a été manipulé ; R01–R16 physiques restent non exécutés.

La dernière CI complète verte avant ce lot est
[39378787342](https://github.com/jean-voila/feuristic/actions/runs/39378787342),
sur **0580d87e1d2aefa1901570fb424d059dd779dec9** : treize jobs, incluant les deux
firmwares, les tests, les cross-compilations, le fuzzing et la reproductibilité.
Ce résultat ne qualifie pas les modifications ultérieures de cette reprise.
Ne pas annoncer stable ni livrer les anciens `dist/` comme source finale.

## Contexte conservé

Session Claude Desktop **« Feuristic firmware development »**,
`03bd068b-7780-424e-810b-816465f6c010` : contexte intégral et quatorze agents
archivés hors dépôt, 46 fichiers avec manifestes, dans
`/Users/jean/.codex/visualizations/2026/10/18/01a14e90-f087-7693-b7f2-203b1b9e2580/claude-handoff/`.
Ne jamais ajouter ces journaux privés au dépôt.

Le [cahier des charges](../spec/cahier-des-charges-v1.0.md) reste normatif.
Safe 3 T2B1/T3B1, base `core/v2.12.5`, dix patches exportés. Le sous-module est
localement patché : **ne jamais enregistrer son gitlink modifié**. Utiliser
`tools/upstream.py check`, sans reset/apply dans le checkout de travail.

Les menus FR/EN et opérations FIDO2, OTP, OpenPGP, PIV, AES/RNG et sauvegarde
sont présents. NORMAL expose FIDO HID+CCID ; CDC et MSC sont exclusifs et
provisoires. Le PIN appareil et les confirmations physiques sont intégrés.
Les capacités promises simultanément sont 100 passkeys, 32 OTP et 4 Kio de
largeBlobs ; PIV/PGP/AES partagent le reste des 64 Kio norcow.

## Correctifs de cette reprise

- Moins de copies largeBlobs : fragments CBOR hachés séparément, vues de lecture,
  tampon de réception préalloué avec préfixe génération. La tête A/B est lue
  avant ce tampon ; une écriture locale ou un reset invalide le transfert.
- Reconstruction FIDO : index temporaires d'ownership par digest de 32 octets,
  avec vérification du propriétaire réel avant toute suppression. Les requêtes
  OTP parcourent les comptes sans retenir les 32 secrets simultanément.
- Export complet : snapshot d'identifiants et libellés chargés à la demande ;
  providers temporaires déchargés sans supprimer les modules des transports actifs.
- Images : API segmentée 32 blocs, pages 2/4 Kio, historique DEFLATE complet,
  unfilter PNG sur une ligne (−8192 octets), JPEG paginé. Le bloc image de
  12288 octets sert ensuite au QR. README inclus dans les allocations triées.
- Noms d'import et caractères ASCII en ROM : corrige les assertions de QSTR
  dans le firmware figé. Générateurs i18n et QSTR vérifiés par host/CI.
- Tests fonctionnels exécutables avec application réellement figée :
  `FEURISTIC_EMU_FROZEN=1`, imports limités à `.frozen`. Les tests MicroPython
  externes sont injectés séparément ; leur propre allocation de noms ne doit
  pas déclencher l'assertion QSTR réservée au parcours applicatif figé.

## Fiabilité des sondes mémoire — correction indispensable

**Les anciens scripts figés utilisaient des assertions avec effets de bord.**
`mpy-cross -O3` les supprimait, notamment unlock, CTAP, collecte, pause/reprise.
Leurs marqueurs de réussite ne prouvent donc pas un parcours complet.
`tools/memory_probe_source.py` transforme désormais les assertions en contrôles
explicites exécutés même sous optimisation. Cinq régressions host le vérifient.

La préparation i686 invalide aussi les `.i`/`.mpy` Feuristic générés : une copie
de fichiers avec mtimes anciens avait réutilisé une variante diagnostique.
Les scripts imposent `.frozen` avant montage des fixtures pour éviter un
chargement silencieux des fichiers Python depuis le disque.

Les expériences de segments sub-kilooctets et de presizing des modules n'ont
pas résolu le budget et **ne sont pas livrées**. Ne pas réutiliser leurs images
ni leurs logs comme qualification. Voir [import-memory.md](import-memory.md).

## Évidence disponible et limites

- Host complet de ce lot : **2140 PASS, 2 skips**,
  `build/solo-host-final.log`. Lint Python/C, compatibilité et SPDX passent.
- Après digest propriétaire : **572 tests ciblés PASS**, dont collision forcée
  sans mutation ; `build/owner-digest-tests.log`.
- C : 15 suites complètes ont passé puis les trois suites fimg finales ont passé
  après correction de leur budget ; ASan/UBSan, 286 vecteurs et géométries.
  `build/solo-final-c-tests.log`, `build/solo-final-fimg-tests.log`.
- ARM M4/M33 : huit bibliothèques `-Werror` ; `build/solo-final-arm.log`.
  Fuzz final : inflate 10426, JPEG 99135, PNG 51397 cas sans défaut,
  `build/solo-final-fuzz.log`.
- Les premiers parcours entièrement figés ont donné **56/61 sur chaque modèle** :
  cinq échecs sauvegarde ont révélé les noms/caractères QSTR manquants.
  Après correction, **6/6 sauvegardes T2 figées PASS**, 189,56 s,
  `build/frozen-backup-ascii-T2B1.log`. Ne pas présenter cela comme une nouvelle
  suite complète 61/61 sur chaque binaire final ; la CI doit l'exécuter.
- **NORMAL 32 bits valide après correction des sondes : peuplement puis vrai
  redémarrage PASS** pour 100 passkeys d'un RP, 32 HOTP, largeBlobs 4096 octets,
  trois écritures locales, trois écritures CTAP authentifiées et 100 assertions.
  `build/normal-memory32-owner.log`, image `build/feuristic-memory32-owner-unix`
  et manifeste associé. Le rechargement finit à 123120 octets utilisés/44432 libres.
  Cela ne prouve ni RP distincts, ni tous les applets CCID chargés, ni export maximal.

## Frontière restante

1. **Budget T2B1 : 171492 octets bruts / 167552 utilisables GC.** Le décodeur
   échoue encore dans les sondes avant réception ; dernier exemple valide
   `build/restore-memory32-owner320.log` (allocation QR 12288). La source garde
   une sortie de 384 pixels, non qualifiée. Ne réduire ni l'entrée 1024²/256 Kio,
   ni les formats ; ne descendre sous 256 pixels. Corpus 103/103 à 256/320/384.
2. Vérifier NORMAL avec 100 RP distincts, CCID préchauffé et export des 132
   identités. Dernières sondes : `build/normal-memory32-final-{distinct,warm}.log`.
   RP distincts : les écritures 4 Kio passent, puis échec776 octets pendant
   l’énumération des RP. CCID préchauffé : échec4400 octets au premier index.
   Ces échecs sont reproduits et restent ouverts.
3. Une fois la RAM résolue : source finale, 61 fonctionnels figés par modèle,
   interop réelle GnuPG/OpenSC (4 par modèle), CI/reproductibilité du commit exact,
   puis binaires développement sans debug, hashes, SBOM et fiches matérielles.

Les builds locaux de ce lot compilent pour les deux MCU : T2 FLASH528,6/768Kio,
FLASH2 829,5/896Kio ; T3 FLASH1378/1664Kio.
Ces résultats vérifient le lien mais pas la RAM d’exécution. Les noms produits
par `make firmware` contiennent le HEAD antérieur alors que l’arbre est modifié :
**ils ne constituent pas des artefacts de provenance finale**.
Les signatures
utilisent les clés de développement publiques amont et un vendor header unsafe.
Aucune qualification stable ni manipulation de hardware ne doit être déduite.

## Ressources

`feuristic-memory32-cross` sous Colima : cross-build i686 isolé,
`tools/prepare_import_memory32.py`, `build/emu32-cross-build.sh`. Ne pas préparer
l'arbre pendant un build ou une sonde. Utiliser des copies immuables des binaires.

Interop : wrappers `build/interop-bin`, container `feuristic-interop`, endpoint
PC/SC unique 35963 ; tests des deux modèles séquentiels. Les derniers 4/4 par
modèle précèdent les changements de ce lot et ne suffisent pas à sa qualification.

Les limites de zéroïsation des copies immuables MicroPython et buffers Rust sont
explicitement dans [R15](../acceptance/R15.md) et le modèle de menace ; ne pas
promettre une purge physique complète de RAM par `gc.collect()`.
