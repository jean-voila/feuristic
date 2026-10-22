---
title: Contribuer à feuristic
description: Proposer un correctif, documenter des essais matériels et préparer une pull request feuristic avec les vérifications adaptées.
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Contribuer à feuristic

Les correctifs ciblés, la documentation, les résultats matériels et les
améliorations de protocole sont bienvenus. Consultez les issues avant un gros
changement. Pour une vulnérabilité, suivez la [politique de sécurité](security.md).

## Préparer une contribution

Lisez l’[architecture](architecture.md), le [modèle de menace](threat-model.md)
et le protocole concerné. Installez l’[environnement](developer/building.md).
Pour la documentation seule, `uv sync --frozen --only-group docs` suffit.

Les contributions sont sous GPL-3.0-only. Vous devez disposer des droits
nécessaires, préserver les notices amont et ajouter l’en-tête SPDX aux nouveaux
fichiers concernés. Aucun accord de cession de droits séparé n’est demandé.

## Politique de pull request

1. Décrivez le problème concret et le comportement obtenu ; liez l’issue utile.
   Séparez les modifications sans rapport.
2. Expliquez les effets sur PIN, consentement, USB, stockage, clés ou récupération.
   Une propriété de sécurité ne doit pas être affaiblie silencieusement.
3. Donnez les vérifications réellement exécutées, modèle/OS et preuves.
   Indiquez explicitement les essais matériels non exécutés.
4. Ajoutez un test de régression adapté aux changements de comportement. Les
   textes d’interface doivent exister en anglais et en français.
5. Un responsable vérifie correction, sécurité, licences et tests. Les contrôles
   requis doivent passer avant fusion. Une approbation d’un responsable est
   attendue pour le code ; les changements sensibles demandent une personne
   connaissant le protocole concerné.

Ne joignez ni PIN, seed, clé privée, sauvegarde réelle, identifiant d’appareil
personnel ni export d’environnement sans rapport. Employez des identités jetables.

## Vérifications

| Changement | Contrôles |
|---|---|
| Documentation | `uv run --group docs mkdocs build --strict` |
| Logique Python | `make test-host` et `make lint` |
| Interface / USB / démarrage | Tests hôte et tests fonctionnels concernés sur les deux émulateurs |
| C, analyseurs, crypto | `make test-c`, compilation ARM et fuzzing concernés |
| Candidat matériel | Deux builds, CI requise et procédures physiques applicables |

Les rapports matériels vont dans `docs/acceptance/`. Consultez les
[tests](developer/testing.md) et les règles de [traduction](developer/documentation.md).

## Modifications amont

Gardez les changements dans `patches/`, documentés avec un trailer
`Feuristic-Rationale:`. Ne stagez pas le gitlink du sous-module modifié et ne
réinitialisez pas un arbre préparé comme réparation courante. Suivez le
[guide des correctifs](developer/patches.md).

Le projet n’ajoute ni fonctions de cryptomonnaies, télémétrie, compte réseau ni
service compagnon obligatoire. La [politique complète](../CONTRIBUTING.md) et le
[code de conduite](../CODE_OF_CONDUCT.md) s’appliquent.
