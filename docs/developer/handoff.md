<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Reprise — 21 octobre 2026

Travailler seul, sans sous-agents. Rester sur `main`, sans branche ni worktree.
Objectif : candidats T2B1/T3B1 prêts aux essais matériels. Aucun hardware n'a
été manipulé ; R01–R16 physiques restent NON EXÉCUTÉS. Ne pas annoncer stable.

La base avant ce lot est `5933b82dca588583ba21c5c568f92495b659992c`, dont la
[CI 39473656986](https://github.com/jean-voila/feuristic/actions/runs/39473656986)
a treize jobs verts. Pour ce lot, utiliser la CI du commit exact et la provenance
jointe aux nouveaux binaires ; les anciens `dist/*5933b82*` proviennent d'arbres
intermédiaires et ne sont pas les artefacts à livrer.

## Contexte conservé

Session Claude Desktop « Feuristic firmware development »,
`03bd068b-7780-424e-810b-816465f6c010`, archivée intégralement hors dépôt :
`/Users/jean/.codex/visualizations/2026/10/18/01a14e90-f087-7693-b7f2-203b1b9e2580/claude-handoff/`.
Ne pas commiter les journaux privés. Le cahier des charges reste normatif.
Base amont `core/v2.12.5`, dix patches exportés. Le sous-module est localement
patché : ne pas enregistrer son gitlink modifié ni reset/apply dans ce checkout.
`tools/upstream.py check` doit passer.

## Correctifs livrés par ce lot

- RP FIDO compactés en UID représentatif + compteur (9 octets/RP), tri/menu et
  CredentialManagement paresseux. La pagination utilise le slicing de `range`,
  disponible sur MicroPython, et non `slice.indices`, absent du runtime.
- Applets PGP/PIV déchargées après désélection ; seuls leurs modules nouvellement
  chargés sont retirés. AES conserve son consentement de session jusqu'au reset.
- Export chiffré : USB temporairement déconnecté, pollers et applets libérés,
  contexte FIDO stocké et snapshot largeBlobs partagés. Retour indépendant à
  NORMAL même après fermeture/annulation du workflow. Le debug émulateur garde
  debuglink mais suspend toujours les pollers.
- Snapshot d'export compact en pages256 ; libellés chargés à la demande.
- NORMAL réserve son tampon largeBlobs4100 octets avant la fragmentation ;
  cache de tête A/B opt-in et invalidation des transferts concurrents.
- IMPORT réserve5440 octets et le registre anti-rejeu7680 octets avant le
  décodeur. Les compteurs suivent la partie utilisée sans agrandir le registre.
  Les identifiants et SHA-256 complets, limites192/4 et règles de conflit restent.
- L'arène consommée sert au déchiffrement GCM authentifié, puis est effacée
  après décodage CBOR en valeurs indépendantes. Elle est prêtée aux index FIDO
  et écritures synchrones PGP/PIV/FIDO, avec révision d'invalidation et effacement.
  Le helper d'effacement accepte aussi les vues mutables, testé avec mauvais tag.
- CBOR itératif : pas de grande liste de fragments. Le merge64 largeBlobs
  conserve les encodages/vues et décode une seule entrée à la fois.
- T2 bitmapinterne256 pixels, payloadQR1024 octets (limite URI/FB1 déjà admise).
  Entrées inchangées PNG/JPEG1024²/256Kio. Historique DEFLATE complet32Kio.
  Pages image1Kio pour le petit profil, scanlinePNG128 et binarizer512.
  Descripteurs104, historique32 pages, bandes JPEG16 pages.
- Contexte image réservé6496 octets en CCM ; lien T2 réel99.86%/30Kio.
  Tas brut171492, utilisable GC167552 octets, blocs16 par défaut. Aucun GC8.
  Pause : tout est effacé, bitmap et réservation image/QR12Kio restent ; close
  libère tout. Cela empêche les reçus de fragmenter les deux plus gros trous.
- GC anticipé partagé avec les sondes :2048 octets par tranche complète128Kio
  de tas utilisable, minimum2048. Les grands émulateurs bénéficient d'un seuil
  proportionnel, sans scanner20Mio à chaque petite allocation.

## Évidence logicielle locale

- Hôte :2160 PASS,2 skips, couverture86.42%, `build/ram-release-host.log`.
  Les skips sont GPG host opt-in et fallback RSA obsolète. L'interop est séparée.
- C fimg :3/3 ASan/UBSan,44.23s, `build/ram-history-final-c-tests.log`.
  Corpus103/103 à256/512, zéro régression,6/6 trop grands refusés :
  `build/ram-history-final-images.log`. ARM M4/M33,8 bibliothèques -Werror :
  `build/ram-history-final-arm.log`. Six cibles fuzz sans défaut :
  `build/ram-history-final-fuzz.log`.
- NORMAL32 :100 RP distincts +32 OTP +largeBlobs4096, applets chaudes,
  écritures locales et CTAP authentifiées, enum/update/assertions, export132
  dans les deux profils puis redémarrage indépendant. Deux marqueurs requis,
  populate/reload. Variante avec8Kio supplémentaires réservés PASS :
  `build/normal-memory32-candidate-distinct.log`. RP commun et même marge PASS :
  `build/normal-memory32-hardware-common.log`.
- IMPORT32 exact dernier C :192 restaurations, cinq providers maximaux réels,
 64 blobs associés, écran natif et frames de coroutines retenus. Profils dense
  et grands modules PASS : `build/restore-memory32-history-final-{dense,large}.log`.
  Dernières reprises :5328 et5312 octets libres aux points de mesure ; ce ne
  sont pas des minima physiques mesurés entre chaque allocation.
- Réexport32 de ces cinq maxima, dans les deux profils et rendu QR natif :
  `build/restore-memory32-bound-export.log`, deux marqueurs RESTORE/MAX_EXPORT.
  Enveloppes5127/4847/2500/379/241 octets et OpenPGP234 grands QR réellement
  construits. Séquence/count192 et timestamp maximal forcés sans dupliquer
 192 tuples. Cela vérifie aussi les largeBlobs associés à l'export.
- Le cycle précédent complet figé donnait60/61 par modèle ; l'unique échec
  (pagination RP) est corrigé et le test dédié passe. Source finale :22/22 sur chaque modèle
  pour les tests ciblés incluant15 MicroPython,6 sauvegardes et le menu FIDO,
  `build/ram-hardware-targeted-{T2B1,T3B1}.log`. La suite complète61/61 de la
  CI du commit exact reste indispensable avant livraison.
- Interop réelle :4/4 sur chaque modèle, `build/ram-qualified-interop-{T2B1,T3B1}.log`.
  Les dernières petites pages image et changements de sauvegarde sont postérieurs ;
  la CI finale doit reconfirmer les quatre cas par modèle.

## Reproduction et qualification finale

Conteneur Colima `feuristic-memory32-cross`, arbre isolé `build/emu32-tree`.
Préparer avec `tools/prepare_import_memory32.py`, puis exécuter dans le conteneur
`build/emu32-cross-build.sh`. Attendre la fin avant de copier l'exécutable
`build/emu32-arm/i686-unknown-linux-gnu/debug/unix` ET `source-snapshot.json`
sous des noms immuables. Ne pas préparer pendant une sonde.
`--msc-on-heap` conserve l'allocation Unix pour le budget de l'autre modèle.
Le remplacement CCM→BSS ne concerne que l'arbre isolé ; vrai ABIi686/GC16.

Les assertions des sondes sont transformées en contrôles avant -O3 ; les anciens
logs antérieurs à `memory_probe_source.py` et les `*-INVALID-old-exe.log` ne sont
pas des preuves complètes. Les imports imposent `.frozen`, sans code applicatif
chargé sur disque. Le secteur simulant l'hôte est préalloué une fois ; le device
ne reçoit que des frames65 octets. Les maxima passent par le BOT/FAT12 natif.

La qualification finale doit lier commit propre, CI13 jobs (dispatch pour
reproductibilité), binaires sans debug des deux modèles, hashes, SBOM et
provenance. Ne pas créer de tag ni de release publique. Les clés de signature
sont les clés développement publiques amont, avec vendor header unsafe.
Les essais physiques et leurs limites figurent dans le registre R01–R16.
