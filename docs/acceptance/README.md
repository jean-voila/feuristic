<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Recette matérielle R01–R16

**Statut initial de toute cette campagne : NON EXÉCUTÉE sur matériel.** Les tests
hôte et émulateur constituent des preuves préparatoires distinctes. Aucun
résultat ci-dessous ne qualifie un appareil physique par sa seule présence.

Une release stable exige chaque critère sur **T2B1 et T3B1**, et chaque OS
spécifié. Employer deux appareils sacrifiables, des secrets de test, un câble de
données fiable, macOS/Windows/Linux, au moins deux téléphones/caméras ordinaires
pour R13 et un moyen contrôlé de couper réellement l'alimentation pour R04/R12.
Le déverrouillage efface les données et l'attestation d'origine de façon
irréversible ; suivre [installation](../user/install.md).

## Registre de campagne

Créer un dossier de preuves privé par commit/modèle/OS, puis un fichier de
résultats contenant date UTC, opérateur, modèle exact et référence d'appareil,
version bootloader, version firmware, commit complet, SHA-256 du binaire,
propreté du source/diff, versions des outils et OS, alimentation/câble, commandes,
étapes, résultat observé, écarts et liens vers preuves. Répertorier chaque essai
`PASS`, `FAIL` ou `NON EXÉCUTÉ`. Un skip ne vaut pas PASS. Garder les originaux
privés et produire une copie expurgée avant publication (PIN, clés, photos QR et
APDU peuvent révéler des secrets).

Consigner séparément pour chaque critère : T2B1/macOS, T2B1/Windows,
T2B1/Linux, T3B1/macOS, T3B1/Windows, T3B1/Linux lorsque le critère concerne les
OS ; pour les autres, au minimum une exécution physique par modèle. R14 exige
les deux directions inter-révisions. Après un défaut ou changement de binaire,
reprendre les critères affectés et identifier le nouveau hash.

| Critère | Procédure | T2B1 | T3B1 |
|---|---|---|---|
| R01 | [Boot, boutons, PIN, FR/EN](R01.md) | NON EXÉCUTÉ | NON EXÉCUTÉ |
| R02 | [FIDO et passkeys](R02.md) | NON EXÉCUTÉ | NON EXÉCUTÉ |
| R03 | [CTAP 2.1 et extensions](R03.md) | NON EXÉCUTÉ | NON EXÉCUTÉ |
| R04 | [Capacité, endurance, coupures](R04.md) | NON EXÉCUTÉ | NON EXÉCUTÉ |
| R05 | [Import MSC par OS](R05.md) | NON EXÉCUTÉ | NON EXÉCUTÉ |
| R06 | [Images/QR hostiles](R06.md) | NON EXÉCUTÉ | NON EXÉCUTÉ |
| R07 | [Heure CDC-ACM](R07.md) | NON EXÉCUTÉ | NON EXÉCUTÉ |
| R08 | [Vecteurs TOTP/HOTP](R08.md) | NON EXÉCUTÉ | NON EXÉCUTÉ |
| R09 | [Interop OpenPGP/GnuPG](R09.md) | NON EXÉCUTÉ | NON EXÉCUTÉ |
| R10 | [Interop PIV/OpenSC](R10.md) | NON EXÉCUTÉ | NON EXÉCUTÉ |
| R11 | [Aléa GET CHALLENGE](R11.md) | NON EXÉCUTÉ | NON EXÉCUTÉ |
| R12 | [AES-GCM/nonces](R12.md) | NON EXÉCUTÉ | NON EXÉCUTÉ |
| R13 | [Lisibilité caméra et multi-QR](R13.md) | NON EXÉCUTÉ | NON EXÉCUTÉ |
| R14 | [Sauvegardes inter-révisions](R14.md) | NON EXÉCUTÉ | NON EXÉCUTÉ |
| R15 | [Consentement, PIN, effacement](R15.md) | NON EXÉCUTÉ | NON EXÉCUTÉ |
| R16 | [Build, licences, SBOM, reproductibilité](R16.md) | NON EXÉCUTÉ | NON EXÉCUTÉ |

## Préparation logicielle commune

Suivre [building](../developer/building.md) et [testing](../developer/testing.md)
pour figer les outils et lancer lint, tests host/C, cross compilation,
fuzzing et les deux émulateurs avant le flash. Ne pas exporter des données
réelles pour créer la campagne. Le PID `1209:0001` est provisoire ;
[CCID](../protocols/ccid.md) décrit les conditions de liaison libccid sur Linux.
Les modes temporaires suspendent FIDO/CCID et exigent la réouverture des clients
après réénumération. Un lecteur virtuel d'émulateur n'est pas un vrai lecteur USB.

## Décision de publication

Toute cellule NON EXÉCUTÉE, tout échec de lecture caméra, dépassement mémoire,
perte d'atomicité, réemploi de nonce ou export sans consentement bloque la
qualification. Le responsable joint les preuves et signe la décision de
campagne ; modifier le tableau sans exécuter les essais est interdit.
La [checklist de release](../release-checklist.md) ajoute les gates de PID,
signature/provenance et distribution des sources/licences.
