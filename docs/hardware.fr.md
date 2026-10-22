---
title: "Matériel Trezor compatible"
description: "Identifier les révisions T2B1 et T3B1 du Trezor Safe 3 et choisir le bon binaire feuristic. Safe 5, Safe 7, Model T et Model One ne sont pas pris en charge."
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Matériel compatible

| Appareil | Modèle interne | feuristic |
|---|---|---|
| Trezor Safe 3, révision A | **T2B1** · STM32F427 | Compilation et émulateur ; première campagne physique T2B1/macOS réalisée |
| Trezor Safe 3, révision B | **T3B1** · STM32U585 | Compilation et émulateur ; qualification physique à effectuer |
| Trezor Safe 5 | T3T1 | Non pris en charge |
| Trezor Safe 7 | Autre matériel | Non pris en charge |
| Trezor Model T / Model One | T2T1 / T1B1 | Non pris en charge |

Deux appareils vendus sous le nom Safe 3 peuvent nécessiter des binaires
différents. Lisez `internal_model` avec `trezorctl get-features` sous le firmware
officiel ou le bootloader. Dans feuristic, ouvrez **Réglages → Matériel / version**.

```sh
trezorctl get-features
```

La couleur de la coque et le nom commercial ne suffisent pas à choisir un
binaire. L’installateur doit identifier le modèle exact avant le transfert.

## Ce que change l’installation

Le Safe 3 devient une clé de sécurité et une carte à puce. feuristic ne propose
ni portefeuille Bitcoin, ni signature de transactions en cryptomonnaies, ni
restauration d’une seed Trezor, ni migration depuis Suite. Le bootloader
officiel reste le chemin de récupération.

La [procédure d’installation](user/install.md) détaille l’effacement, le
déverrouillage du bootloader et la perte permanente de l’attestation d’origine.
