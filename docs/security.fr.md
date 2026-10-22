---
title: Politique de sécurité
description: Signaler une vulnérabilité feuristic en privé, comprendre le périmètre des signalements et les versions recevant des correctifs.
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Politique de sécurité

## Signaler une vulnérabilité

**Ne publiez pas les détails d’une vulnérabilité dans une issue ou une discussion
publique.** Utilisez le [signalement privé GitHub](https://github.com/jean-voila/feuristic/security/advisories/new)
(**Security → Report a vulnerability**) pour contacter les responsables en privé.
Le dépôt est public, mais les signalements de vulnérabilité restent privés.
Ne joignez ni secrets de production, ni PIN, ni sauvegardes réelles.

Un signalement doit indiquer :

- La version ou le commit et le modèle concerné : T2B1, T3B1 ou émulateur.
- Le défaut et ses conséquences.
- Les étapes ou une preuve de concept permettant de le reproduire.

La politique prévoit un accusé de réception sous sept jours, une date de
divulgation concertée (90 jours par défaut, plus courte en cas d’exploitation
active) et un crédit pour les personnes qui le souhaitent. Les correctifs sont
distribués dans de nouvelles versions et dans l’[historique](security-history.md).

Les défauts des composants amont doivent aussi être signalés à leurs responsables ;
la coordination s’effectue lorsqu’ils touchent feuristic.

## Périmètre

Le firmware, les correctifs, bibliothèques, outils hôte, formats de sauvegarde
et annexes de protocole du dépôt sont concernés.

Le bootloader officiel et son avertissement tiers, les attaques nécessitant
l’approbation explicite de l’opération à l’écran et les défauts uniquement
reproductibles avec debuglink sur l’émulateur sont hors périmètre de cette
politique. Cela ne dispense pas de documenter les limites du modèle de sécurité.

Avant la version 1.0, seule la dernière version distribuée reçoit des correctifs.
Consultez le [modèle de menace](threat-model.md). La politique de référence du
dépôt est [SECURITY.md](../SECURITY.md).
