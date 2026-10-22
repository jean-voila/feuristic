---
title: Essai matériel Trezor Safe 3 T2B1 sur macOS
description: "Essai physique partiel de feuristic sur un vrai Trezor Safe 3 T2B1 sous macOS : signatures, AES-GCM, import OTP, synchronisation de l’heure et mises à jour."
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Première campagne physique — T2B1 / macOS, 21 octobre 2026 UTC

Campagne partielle sur un vrai Safe 3 **T2B1**, bootloader **2.1.16**, macOS
27.0.1 ARM64. L'utilisateur effectue les confirmations physiques ; les clients
utilisent le HID, PC/SC et CDC natifs du Mac, sans debuglink ni lecteur virtuel.
Toutes les identités sont jetables. Les originaux privés, commandes et scripts
sont conservés localement dans `build/hardware-20261021-T2B1/` ; ils ne sont pas
publiés avec les identifiants de l'appareil ou le trousseau GnuPG.

Le firmware officiel initial était 2.12.5, avec stockage initialisé et bootloader
verrouillé. Après confirmation explicite de la sauvegarde et de l'effacement,
le déverrouillage a réussi ; `bootloader_locked=False` et `initialized=False`
ont été relus avant le premier flash.

## Binaires employés

| Source | Origine | SHA-256 du fichier T2B1 |
|---|---|---|
| `148390f5c364` | Candidat Nix de la CI 39560119956 | `d8a6e37e79ce7ab2e1e9c1a613be29f121dc814088a460f05c52ccca0450fe22` |
| `f56f02ef4018` | Build local macOS, correction TOTP | `a812c1a7224b6ce19d62ddc459f3d839aca7fab26c224b68ff6a489807b1ab01` |
| `b97aa7cb9ae2` | Build local macOS, accueil verrouillé visible | `e4da82768739d41f89a14b5e8b95abe320c25d32e7950ea74779afee41fb1860` |

Les modèles et signatures de chaque fichier passent le contrôle standard de
`trezorlib` épinglé. Les builds locaux ne sont pas présentés comme des builds
Nix reproductibles. L'avertissement tiers et l'accord utilisateur restent actifs.

## Observations physiques

| Essai effectivement exécuté | Résultat |
|---|---|
| Premier démarrage, langue FR et création du PIN | PASS, confirmé par l'utilisateur |
| USB normal | PASS : HID classe 3 et CCID classe 11, sans debuglink |
| HID/CTAP | PASS : INIT, PING 100 octets, GetInfo FIDO 2.1 ; les extensions annoncées ne constituent pas leur recette complète |
| Passkey résidente ES256 | PASS : création, assertion découvrable et signature vérifiée sur le Mac |
| Refus physique FIDO | PASS : `OPERATION_DENIED` |
| Coupure réelle puis même passkey | PASS : signature valide, compteur de 2 à 33 |
| CCID natif | PASS : SELECT OpenPGP/PIV/AES et douze APDU publiques, avant et après import |
| GET CHALLENGE | PASS : 1 et 32 octets, rejet de 33 et d'une longueur absente ; aucune prétention de mesure d'entropie |
| OpenPGP avec GnuPG 2.5.22 | PASS : carte 3.4, génération Ed25519/X25519, certificat exporté, signature vérifiée et déchiffrement identique au message initial |
| PIV | PASS : authentification d'administration AES-192, génération P-256 en 9A et signature vérifiée indépendamment |
| AES-GCM | PASS : aller-retour de 0, 1, 31, 127 et 3584 octets, jusqu'à 256 octets AAD ; tags/AAD corrompus refusés sans texte clair, taille 3585 refusée, nonce fourni par l'hôte refusé ; cinq nonces distincts |
| Import PNG puis JPEG baseline | PASS : FAT12 monté par macOS, MSC seul, copie/fsync, confirmation locale, éjection et reprise HID/CCID |
| HOTP RFC 4226, compteur initial 0 | PASS : code matériel `755224` |
| CDC natif | PASS : interfaces 2/10 seules, neuf cas HELLO/framing/erreurs, heure acceptée puis retour normal |
| Horloge conservée pendant import JPEG | PASS : TOTP matériel `172068`, correspondant au calcul indépendant pour la fenêtre UTC 21:38:00 |
| Correction du compte à rebours TOTP | PASS sur `f56f02ef4018`, confirmé par l'utilisateur |
| Accueil visible après `b97aa7cb9ae2` | PASS : FEURISTIC/consigne FR visibles, bouton vers PIN, ancien PIN accepté |
| Identités conservées après les mises à jour | PASS : même passkey (compteur 65), mêmes signatures PIV et OpenPGP, même clé AES, HOTP compteur 1 = `287082` |
| Nonces AES après coupure/mise à jour | PASS : indices 0–4 avant puis 256–260 après, dix nonces distincts sur cette campagne |
| État final | PASS : heure remise, HID + CCID seuls, GetInfo/PING FIDO et APDU CCID à nouveau fonctionnels |

Une première demande de signature GnuPG a répondu « Conditions of use not
satisfied » malgré une confirmation annoncée. L'expiration de 30 secondes est
une cause possible, non démontrée. Le nouvel essai, validé explicitement sur
la dernière page, a produit une signature vérifiée ; cet écart est conservé.

## Correctifs issus de l'essai

- `f56f02ef4018` : remplacer les deux traductions non formatées du TOTP par
  `t("otp.remaining", remaining)` ; tests EN/FR sur deux rafraîchissements.
  Documenter « Exit menu », « Init connection » et la reconnexion après unlock.
- `b97aa7cb9ae2` : remplacer l'écran noir de verrouillage par **FEURISTIC** et
  une consigne EN/FR. Un appui mène au PIN, sans déverrouiller le stockage.
  Le wrapper d'entrée reste local au dialogue pour libérer sa classe après usage.

Validation logicielle du dernier correctif : **340 tests hôte ciblés**, **9 tests
de boot/verrouillage T2B1** (FR/EN, gauche/droite/deux boutons, redémarrage,
mauvais puis bon PIN), lint et compatibilité MicroPython. Les tests fonctionnels
locaux utilisent le mode normal de l'émulateur ; une tentative `.frozen` seule
était inapplicable à ce build local, dépourvu de module `main` gelé.

## Portée

Ce compte rendu ne valide aucun R01–R16 dans son intégralité. Restent notamment
T3B1, Windows/Linux, caméra et restauration inter-révisions, capacité/endurance,
coupures pendant écritures, extensions CTAP, certificats et interop OpenSC,
injections de défaut RNG, politiques PIN et tests complets de consentement.
Il ne constitue pas une décision de publication stable.

Le firmware laissé sur l'appareil est **`b97aa7cb9ae2`**, SHA-256
`e4da82768739d41f89a14b5e8b95abe320c25d32e7950ea74779afee41fb1860`.
Les deux comptes OTP, la passkey, l'identité OpenPGP, la clé PIV 9A et la clé
AES #1 restent des données de test. Les deux défauts d'affichage signalés ont
été corrigés et vérifiés physiquement.
