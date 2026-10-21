<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Candidat aux essais matériels

Les binaires de développement T2B1 et T3B1 doivent provenir du même commit
propre, avec CI complète et reproductibilité validées. Le dossier
`dist/hardware-<révision>/` associe chaque `.bin` à son SHA-256, un SBOM et une
provenance donnant le commit exact, la CI et les contrôles logiciels exécutés.
Utiliser ces fichiers, et non les anciens binaires de travail présents dans
`dist/`.

1. Identifier précisément la révision T2B1 ou T3B1 et suivre
   [l'installation et ses conséquences](../user/install.md).
2. Vérifier les SHA-256 du dossier candidat avant installation. La signature
   est celle des clés de développement publiques amont, avec avertissement
   unsafe obligatoire ; ce n'est pas une signature privée de distribution.
3. Exécuter les fiches [R01–R16](../acceptance/README.md) sur les deux révisions,
   en enregistrant pour chaque résultat le modèle, le hash, l'OS et les preuves.
   Tester en particulier les copies MSC, les deux profils QR, la restauration
   croisée et les interruptions d'alimentation.

Les sondes32 bits et les émulateurs constituent des preuves logicielles.
Ils ne valident ni l'USB physique, ni la lisibilité OLED/caméra, ni les pics RAM
sur le MCU réel. Tous les résultats matériels restent NON EXÉCUTÉS tant que
les fiches n'ont pas été renseignées. La publication stable reste conditionnée
à la [checklist de release](../release-checklist.md).
