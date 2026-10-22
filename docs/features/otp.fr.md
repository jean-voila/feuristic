---
title: "Codes TOTP et HOTP sur Trezor Safe 3"
description: "Importer des QR otpauth en PNG/JPEG, synchroniser l’heure par USB et afficher des codes TOTP/HOTP avec feuristic sur Trezor Safe 3."
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# TOTP et HOTP

feuristic gère jusqu’à **32 comptes OTP**, avec SHA1, SHA256 ou SHA512.
Les comptes s’importent depuis des images QR contenant une URI `otpauth://`.
Utilisez d’abord un secret public de test.

## Importer un compte

1. Ouvrez **Authentification → OTP → Ajouter QR par USB**.
2. Copiez l’image QR **PNG ou JPEG de base** sur le volume temporaire.
3. Vérifiez service, compte, type, algorithme et paramètres sur l’écran,
   confirmez, puis éjectez proprement le volume depuis l’ordinateur.

Ne copiez ni binaire de firmware ni image contenant un secret de production
pendant les essais. Les formats et limites figurent dans la
[référence otpauth](../protocols/otpauth.md).

Les images sont limitées à **256 Kio et 1024 × 1024 pixels**, avec un seul
QR pertinent. JPEG progressif et HEIC ne sont pas pris en charge. Les codes
ont 6, 7 ou 8 chiffres ; les périodes TOTP vont de 15 à 300 secondes.

## TOTP : synchroniser l’heure

Ouvrez **Réglages → Heure TOTP → Synchroniser par USB**, puis envoyez l’heure
avec `uv run python tools/feuristic_time.py` ou le [protocole série](../protocols/time-sync-v1.md). Après un redémarrage,
synchronisez à nouveau avant de comparer les codes.

Sous **Voir le code**, l’écran affiche le code et le compte à rebours, par
exemple `Encore 13 s`. Le format des accolades a été corrigé et vérifié sur le
T2B1 physique.

## HOTP : conserver le compteur

Chaque génération confirmée consomme un compteur. Ne générez pas plusieurs
codes sans les utiliser si le service attend une séquence précise. Le vecteur
RFC 4226 `755224`, puis `287082`, a été vérifié avec persistance du compteur
après les mises à jour.

Voir le [guide d’utilisation](../user/guide.md), le
[rapport physique](../acceptance/campaign-2026-10-21-T2B1-macos.md) et le
[format de sauvegarde OTP](../protocols/backup-otp.md).
