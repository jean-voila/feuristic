---
title: Design specification — original French document
content_language: fr
---

# feuristic
## Cahier des charges définitif de conception — firmware cryptographique alternatif pour Trezor Safe 3

**Version :** 1.0 — conception figée  
**Date :** 17 octobre 2026  
**Statut :** exigences fonctionnelles et choix architecturaux arrêtés ; conformité sur matériel **non encore testée**  
**Licence :** GNU General Public License v3.0 (`GPL-3.0-only`)  
**Matériel :** Trezor Safe 3 **T2B1 (rév. A)** et **T3B1 (rév. B)**, sans modification physique

> **Objectif :** un « couteau suisse cryptographique » USB, libre, agnostique et fondé sur des standards. Toute la configuration et la gestion des secrets se font sur l'écran du Safe 3, avec ses deux boutons. Pas de logiciel compagnon feuristic, de service cloud, de compte, de terminal obligatoire pour configurer le périphérique, ni de fonctionnalité liée aux cryptomonnaies.

**Précision essentielle :** le présent document ne contient **aucun arbitrage produit laissé ouvert**. Cela n'implique pas que les pilotes, protocoles et performances ont été matériellement validés : les **essais d'acceptation non exécutés** restent obligatoires avant de déclarer le firmware fonctionnel ou stable. Toute exigence échouant sur l'une des deux révisions doit être corrigée par l'implémentation ; elle ne doit pas être annoncée comme accomplie.

---

## 1. Principes non négociables

1. **Compatibilité des deux révisions**, avec des binaires propres à `T2B1` et `T3B1` issus d'un même code fonctionnel.
2. **Configuration autonome** depuis l'appareil : création/suppression des comptes et clés, paramètres FIDO, PIN, export/restauration, langues, sécurité, interfaces USB.
3. **Interfaces USB interopérables** : USB HID pour FIDO2 ; USB CCID/PC-SC et APDU ISO 7816 pour la carte cryptographique en mode normal ; CDC-ACM pour la synchronisation horaire et Mass Storage pour l’import de QR **dans deux modes temporaires exclusifs**.
4. **Aucun compagnon dédié** n'est obligatoire. Les logiciels utilisateurs *habituels* (navigateurs, GnuPG, OpenSC, OpenSSH, outils PC/SC) restent naturellement nécessaires pour leurs propres fonctions. Un standard de transport ne garantit pas automatiquement qu'un logiciel métier prend en charge toutes les fonctions.
5. **Code source libre et auditable**, pas de télémétrie, pas de service distant, pas de dépendance à Trezor Suite.
6. **Toutes les opérations sensibles sont confirmées physiquement** si elles dévoilent, modifient, exportent ou utilisent des clés ou secrets selon les règles de sécurité ci-dessous.
7. **Nouveau stockage vierge** : aucune migration des données ou des sauvegardes du firmware Trezor officiel.
8. **Pas de fonction de portefeuille de cryptomonnaies.**

### 1.1 Matériel et limites prises en compte

- Écran OLED monochrome **128 × 64**, deux boutons, USB-C, absence de caméra et d'horloge persistante sans alimentation.
- Les cryptographies peuvent être exécutées par le microcontrôleur : **« calculée dans le Trezor » ne signifie pas nécessairement « accélérée ou isolée dans le Secure Element »**.
- PIN et protections du stockage s'appuient autant que possible sur les composants éprouvés du projet Trezor, sous réserve d'un isolement strict des espaces de noms.
- Le firmware alternatif exige un bootloader déverrouillé, avec les conséquences irréversibles sur l'attestation d'origine acceptées dans le cadrage.

---

## 2. Fonctionnalités obligatoires

| ID | Fonction | Norme/profil choisi | Parcours |
|---|---|---|---|
| F01 | **TOTP/HOTP** | RFC 6238 / RFC 4226 ; URI `otpauth://` | Comptes administrés sur l'écran ; import PNG/JPEG par volume MSC temporaire ; codes sur l'écran |
| F02 | **Passkeys et gestion avancée** | FIDO2 / WebAuthn / **CTAP 2.1** | `clientPIN`, `credentialManagement`, `credProtect`, `largeBlobs`, `hmac-secret` ; menus locaux |
| F03 | **OpenPGP/GPG** | **OpenPGP Card 3.4**, **ISO 7816**, CCID | Clés de signature / déchiffrement / authentification ; GnuPG standard sans `trezor-agent` |
| F04 | **Signatures génériques et certificats** | **PIV** (NIST SP 800-73, profil PIV), CCID/PC-SC | Clés P-256 et RSA-2048 là où requis par interopérabilité ; certificats X.509 ; outil OpenSC standard |
| F05 | **AES authentifié sur l'appareil** | **AES-256-GCM**, commandes de sécurité **ISO 7816-8**, CCID/PC-SC | Clés internes par identifiant ; blocs/flux fragmentés sur APDU ; confirmation et PIN selon politique |
| F06 | **Aléa matériel** | **ISO 7816-4 `GET CHALLENGE`**, CCID/PC-SC | Octets RNG provenant de la chaîne d'entropie matérielle et du DRBG du firmware |
| F07 | **Challenge-response standard** | **CTAP2/WebAuthn** (`hmac-secret`) et **PIV** (`GENERAL AUTHENTICATE`) | Défis et réponses sur les protocoles standards uniquement |

**Fonctions FIDO conservées :** U2F/WebAuthn, clés OpenSSH `ecdsa-sk`/`ed25519-sk` quand acceptées par l'implémentation et les clients, signature Git SSH. Aucune ancienne interface SSH propre à Trezor.

### 2.1 Règle d'interopérabilité — point important pour AES/RNG

L'interface USB retenue pour **AES et RNG** est **CCID/PC-SC**, avec APDU relevant respectivement d'**ISO 7816-8** (opérations cryptographiques) et d'**ISO 7816-4** (`GET CHALLENGE`). Les primitives, les algorithmes et le mode GCM sont standards ; l'encodage complet de sélection des clés et des paramètres de session doit être **publié et versionné dans la documentation feuristic**, car ISO 7816 n'impose pas un profil universel AES-GCM prêt à l'emploi pour toutes les cartes.

**Conséquence assumée :** un lecteur PC/SC générique peut transporter les APDU sans pilote feuristic, mais **OpenSC/PKCS#11 n'offrira pas automatiquement AES-256-GCM** avec un module PIV standard. La compatibilité « transparente avec toute application PKCS#11 » **n'est pas promise**. Un module logiciel spécialisé serait nécessaire pour ce niveau supplémentaire d'intégration, et est **hors périmètre obligatoire**. Pour le RNG, `GET CHALLENGE` est accessible via outils smartcard/PC-SC génériques ; l'exposition `C_GenerateRandom` d'un module PKCS#11 n'est pas garantie.

OpenPGP et PIV sont des **applications distinctes sur la même carte virtuelle**, sélectionnées par leurs AID standard. Elles ne partagent aucune clé sans action explicite de l'utilisateur.

---

## 3. USB : architecture fixée

### 3.1 Mode normal (« crypto »)

- **USB HID CTAP** : FIDO U2F/CTAP2.1, sans passerelle feuristic.
- **USB CCID** : un lecteur de carte virtuelle proposant les applications **OpenPGP Card**, **PIV**, et le profil cryptographique ISO 7816-8 pour AES/RNG.
- **Ni CDC-ACM ni Mass Storage en mode normal.**
- **Raison technique vérifiée par documentation du contrôleur :** sur la révision T2B1 (STM32F427, USB OTG_FS), le périphérique USB dispose de **trois endpoints IN non nuls maximum**. Un composite FIDO HID + CCID + CDC-ACM simultané dépasserait ce budget si CDC-ACM prend ses endpoints standard. Le profil **HID + CCID** tient dans cette limite sous réserve que les descripteurs reflètent le nombre effectif de points de terminaison (un IN HID ; un IN bulk CCID ; un IN interrupt CCID optionnel). Les deux révisions utiliseront les **mêmes modes USB**, sans divergence d'usage.

### 3.2 Mode temporaire « Régler l'heure »

- Depuis **`Réglages → Heure TOTP → Synchroniser par USB`**, le Safe 3 réénumère temporairement comme **CDC-ACM seul**.
- L'hôte transmet `TIME 1 <unix-seconds>\n` par un terminal ou service série générique. L'utilisateur valide le nouvel horaire sur le Safe 3 lorsque la politique de sécurité le demande.
- Dès réception réussie ou annulation depuis le menu, le périphérique réénumère en **FIDO HID + CCID** ; l'heure reste active tant que l'appareil demeure alimenté.
- Le mode heure ne réclame pas de compagnon propriétaire, mais **le PC doit envoyer l'heure** ; il n'existe pas d'automatisme USB universel annoncé.

### 3.3 Mode temporaire « Importer un QR »

- L'utilisateur l'active depuis le menu. Le Trezor **déconnecte logiquement puis réénumère** son périphérique USB comme **Mass Storage seul**, avec volume **`FEURISTIC-IMPORT`**, format **FAT12**.
- La suspension momentanée de FIDO2/CCID/CDC pendant l'import est **un comportement voulu**, et réduit les besoins simultanés en points de terminaison USB.
- La partition logique n'expose **jamais le stockage confidentiel**. Elle est éphémère et reçoit uniquement des images d'import.
- L'appareil accepte **PNG** et **JPEG baseline**, image contenant **exactement un QR pertinent**, poids maximal **256 Kio** et dimensions maximales **1024 × 1024** ; un fichier trop grand ou une variante JPEG non prise en charge affiche une erreur compréhensible.
- Le traitement doit se faire **en flux / mémoire bornée** : jamais de tampon plein cadre RGBA. Aucun octet non fiabilisé n'est interprété comme commande système.
- L'analyse débute après réception complète et synchronisation des écritures. Le QR doit encoder `otpauth://` ou des trames de sauvegarde `feuristic-backup` versionnées.
- Le Safe 3 présente l'aperçu du compte ou de l'identité ; l'utilisateur confirme sur l'écran.
- Pour une sauvegarde QR **fragmentée**, l'interface reste ouverte jusqu'à réception et vérification de **toutes** les trames, puis confirmation locale ; les fichiers arrivant successivement sont pris en charge sans exigence de quitter le mode entre chaque fragment.
- Après import et confirmation, **le Trezor demande l'éjection du volume**. L'interface ne disparaît **qu'après éjection SCSI / arrêt propre** par l'hôte ; ensuite le périphérique se réénumère en mode normal. Aucune disparition brutale dès que le QR est détecté.
- Si le câble est retiré ou une opération échoue, l'import est annulé et le stockage temporaire est purgé sans altérer les entrées déjà enregistrées.

**Règle d'intégrité :** la copie de fichier, son analyse et l'ajout effectif du secret sont **trois opérations séparées** ; l'écriture définitive du secret est atomique. Ne jamais enregistrer une entrée partielle.

---

## 4. Heure pour TOTP

- **Pas d'horloge persistante hors tension** : TOTP est inutilisable tant que l'appareil ne connaît pas une heure fiable dans la session d'alimentation courante.
- **Mode choisi** : **CDC-ACM seul, activé provisoirement depuis le menu**, protocole texte public minimal, versionné. Message hôte : `TIME 1 <unix-seconds>\n` ; réponse : `OK <unix-seconds>\n` ou `ERR <code>\n`. Le firmware contrôle syntaxe, bornes et erreurs.
- La transmission est possible par les mécanismes série habituels des OS ; **aucune synchronisation automatique universelle n'est annoncée**. Un terminal ou une automatisation système peut être utilisé pour envoyer l'heure ; **ils ne sont pas requis pour administrer les comptes OTP**.
- Une horloge monotone de session maintient l'heure **tant que le Trezor reste alimenté**. Après coupure, indication **« Heure à synchroniser »** au lieu d'un code incorrect.
- Toute tentative de reculer l'heure de plus de **60 secondes** par rapport au temps de session nécessite une **confirmation physique** ; une dérive en avant manifeste est également affichée avant acceptation.
- Les comptes HOTP fonctionnent sans heure, avec compteur persistant, avance atomique et confirmation avant génération.

---

## 5. Passkeys / FIDO2

- Comportement FIDO2/CTAP 2.1 interopérable avec les navigateurs, Windows, macOS, Linux et les utilitaires FIDO standards.
- Implémenter et annoncer **uniquement les extensions réellement opérationnelles** : `clientPIN`, `credentialManagement`, `credProtect`, `largeBlobs` et `hmac-secret` ; ne jamais signaler une option CTAP si le firmware ne sait pas l'exécuter correctement.
- Depuis le menu : liste paginée par service et compte, suppression ciblée, informations de protection, PIN, effacement global confirmé.
- **Objectif contractuel de capacité : 100 identifiants découvrables**, conformément à la limite du stockage amont ; **32 comptes OTP** en plus ; espace partagé `largeBlobs` plafonné à **4 Kio** pour garantir une allocation bornée.
- Les passkeys **non découvrables** restent possibles selon les procédures CTAP habituelles.
- La génération, l'utilisation et la restauration de clés répondent à la même politique d'authentification que les autres identités ; le firmware gère les indicateurs de sauvegarde WebAuthn conformément au fonctionnement réel, sans présenter comme « non exportable » une clé qu'il permet d'exporter via un QR de sauvegarde.
- Les authentifications et les créations de passkeys nécessitent les consentements locaux prévus par CTAP ; `credProtect` empêche les divulgations non autorisées.

---

## 6. OpenPGP, PIV et signatures

### 6.1 OpenPGP Card

- Implémenter **OpenPGP Card 3.4** comme application CCID sélectionnable par AID.
- Trois rôles classiques : **signature**, **déchiffrement** et **authentification**.
- Génération de clés et gestion du PIN localement ; disponibilité et opérations via **GnuPG/scdaemon** standard.
- Profil d'algorithmes principal : **Ed25519** pour signature/authentification et **X25519** pour déchiffrement lorsque le client GnuPG est compatible ; **RSA-2048** comme profil de compatibilité optionnel non prioritaire.

### 6.2 PIV / signatures génériques

- Implémenter une application PIV compatible avec les commandes et objets communs au **NIST SP 800-73** ; exposer au minimum **P-256/ECDSA** et **RSA-2048** dans les emplacements de signature/authentification PIV usuels.
- Les certificats **X.509** publics peuvent être importés via les mécanismes standard PIV. Les **clés privées** sont générées et gérées sur l'appareil ; le profil ne garantit pas leur extraction par le logiciel hôte.
- Prise en charge cible de la signature TLS client, OpenSC/PKCS#11, des certificats et applications PIV standard.
- Les clés PIV, OpenPGP et AES sont isolées par application et par usage : interdiction de réutiliser la même clé sur différents protocoles.

### 6.3 Confirmation de signature

- Afficher **type de signature, rôle de la clé et empreinte cryptographique**. Si le format de données n'est pas interprétable localement, indiquer clairement **« Signature d'empreinte non interprétée »** et ne pas inventer de présentation sémantique.
- Refus explicite, temporisation et verrouillage par PIN selon la politique.

---

## 7. AES-256-GCM et RNG

- **AES-256-GCM** uniquement pour le service de chiffrement général ; clé de 256 bits générée sur l'appareil, nonce 96 bits unique par opération et tag 128 bits. Aucun déchiffrement ne fournit de plaintext avant authentification du tag.
- **Aucun réemploi de nonce pour une même clé**, y compris après coupure de courant. Pour l'encryption, les nonces proviennent d'un compteur persistant atomique et d'une composante unique associée à la clé, ou d'un schéma ayant une garantie équivalente ; un nonce choisi librement par l'hôte n'est pas accepté sans garantie d'unicité.
- API smartcard **ISO 7816-8 `PSO` Encipher/Decipher**, environnement de sécurité `MSE`, sélection de clé et encodages publiés dans une annexe de protocole libre. Opérations fragmentées sur APDU (pas de prétention à une accélération rapide de gros fichiers).
- **RNG** : `GET CHALLENGE` ISO 7816-4 ; jusqu'à **32 octets par requête** ; réponse refusée si l'état santé RNG/DRBG n'est pas satisfaisant. L'hôte ne contrôle pas le secret d'entropie.
- Les sorties brutes RNG sont accessibles **sans PIN** (fonction publique), mais avec contrôle anti-abus et sans perturbation des opérations sensibles.
- L'écran permet **de créer, nommer, désactiver et supprimer** les clés AES. Aucun secret n'est révélé automatiquement au PC.

---

## 8. Sauvegarde / restauration par QR — règles entièrement définies

**Décision produit :** **l'export se lance et se confirme exclusivement depuis l'écran du Trezor**, en affichant des **QR codes** ; **la restauration passe par des images PNG/JPEG** déposées sur le volume MSC temporaire, exactement comme l'ajout d'un compte OTP. Aucune application compagnon feuristic requise.

### 8.1 Comptes OTP

- Pour **TOTP/HOTP individuel**, le firmware affiche un QR `otpauth://` standard, avec service, compte, paramètres et secret ; HOTP comprend aussi son compteur au moment de l'export.
- **L'export expose volontairement le secret** : PIN, confirmation explicite, avertissement « toute personne photographiant ce QR peut reproduire les codes ». Désactiver automatiquement l'affichage après 60 secondes.
- Les URI très longs sont représentés par des QR de plus grande version ou, au besoin, par le format de sauvegarde fragmentée ci-dessous ; la lecture sur 128×64 **doit réussir aux tests d'acceptation sur écran physique** avant publication.

### 8.2 Autres données (passkeys, PIV/OpenPGP/AES, métadonnées, `largeBlobs`)

- Mode **« Exporter une identité »**, **une seule identité à la fois**, plus option **« Export complet »** qui enchaîne les mêmes objets. L'export chiffré contient les données nécessaires à la restauration de l'identité (clé privée lorsqu'elle est sauvegardable, identifiants, paramètres d'algorithmes, métadonnées, compteur et données `largeBlobs` associées).
- Format de sauvegarde **documenté, ouvert, déterministe et versionné** : enveloppe binaire en **CBOR canonique (RFC 8949)** ; chiffrement **AES-256-GCM** ; KDF **PBKDF2-HMAC-SHA-256**, 600 000 itérations, sel aléatoire de 16 octets, phrase de sauvegarde distincte du PIN et nonce unique de 12 octets ; authentification avant import.
- L'utilisateur renseigne la **phrase de sauvegarde sur le Trezor**, avec navigation aux deux boutons. Une phrase d'au moins **12 caractères** est exigée. Elle n'est ni mémorisée en clair ni transmise à l'ordinateur.
- Les octets chiffrés sont répartis en **trames QR numérotées**, chacune contenant un identifiant de sauvegarde, un numéro de fragment, le nombre total et une somme de contrôle de transport ; trames encodées en **Base45 (RFC 9285)** ou binaire QR. L'export ne déclare pas un seul QR quand plusieurs sont nécessaires.
- Pour restaurer : photographier **tous** les QR de la séquence, les déposer **un par un** comme PNG/JPEG sur le volume d'import, saisir la phrase sur l'appareil, vérifier le réassemblage, puis confirmer. L'ordre peut être indépendant ; les doublons sont ignorés ; toute trame manquante bloque l'import sans modifier le stockage actif.
- Avant d'écraser une identité existante, afficher son nom, son empreinte et demander une confirmation spécifique. Une restauration complète est atomique par identité.
- Une sauvegarde chiffrée **réduit l'intérêt de l'inexportabilité physique** : elle rend les clés récupérables par toute personne possédant les images et la phrase. L'interface doit annoncer cette propriété ; l'appareil ne doit jamais prétendre que de telles clés sont définitivement non exportables.
- **Restriction volontaire :** la sauvegarde QR complète de nombreuses passkeys/`largeBlobs` peut nécessiter de très nombreuses images, sur un écran petit. C'est fonctionnellement spécifié mais **ce n'est pas présenté comme rapide ni ergonomique**. Le test physique de lisibilité est indispensable. Aucun faux engagement « un QR unique pour 100 passkeys ».

### 8.3 Stockage vierge et modèles de récupération

- À l'installation ou après effacement, l'utilisateur repart de zéro. **Aucune importation de phrases de récupération Trezor Suite, ni migration de portefeuilles.**
- Le format de sauvegarde feuristic est indépendant de la sauvegarde d'un portefeuille Trezor ; les deux ne sont pas interchangeables.
- Les sauvegardes doivent afficher un identifiant de version et être indépendantes de la révision T2B1/T3B1 pour permettre la récupération inter-révisions.

---

## 9. Ergonomie et écran

```text
feuristic
├── Authentification
│   ├── Passkeys (utiliser / voir / supprimer / protections)
│   ├── OTP (voir code / ajouter QR USB / sauvegarder QR / supprimer)
│   └── Challenge-response (FIDO2 / PIV)
├── Cryptographie
│   ├── OpenPGP (générer / voir / supprimer / exporter QR)
│   ├── PIV (identités / certificats / signatures / exporter QR)
│   ├── AES (clés / paramètres / supprimer / exporter QR)
│   └── Aléa (RNG : état / informations)
├── Sauvegarde
│   ├── Exporter une identité (QR)
│   ├── Export complet (séquences QR)
│   └── Restaurer (import MSC temporaire)
└── Réglages
    ├── PIN / verrouillage
    ├── Heure TOTP (CDC-ACM)
    ├── Interfaces USB
    ├── Langue FR / EN
    ├── Matériel / version / diagnostics
    └── Effacement intégral
```

- **Deux boutons** : gauche = précédent, droite = suivant, pression simultanée = valider ; pression longue sur gauche = retour. Le système doit interdire qu'une combinaison équivoque valide silencieusement un effacement.
- Toutes les opérations sensibles affichent un libellé compréhensible, l'identité concernée et un écran de confirmation distinct.
- Langues intégrées **français et anglais** dès la première release, sans chargement de traduction par logiciel hôte.
- Limite d'inactivité : verrouillage après **5 minutes**, réauthentification pour export de secrets ; la configuration reste navigable sans PC.

---

## 10. Sécurité, fiabilité et conformité

1. **PIN obligatoire** dès l'initialisation pour le stockage de secrets ; limitation des essais et délais hérités de l'architecture de stockage protégée quand disponible.
2. Domain separation pour toutes les clés : FIDO2, OpenPGP, PIV, AES, OTP, sauvegarde, avec identifiants d'applications et KDF distincts.
3. Aucune clé privée ou secret OTP exposé dans l'USB normal, **hormis une opération d'export explicitement armée dans le menu**, et dans ce cas uniquement via QR affiché sur l'écran.
4. Mode MSC **isolé** ; pas de fichiers secrets visibles ; fichiers d'import purgés ; une image QR hostile ne doit pas permettre d'écrire au-delà d'un buffer, d'exécuter de code ou de toucher au stockage sécurisé.
5. Entrées CCID, HID et CDC-ACM à tailles maximales, validation stricte, timeouts, fuzzing et contrôle des APDU autorisés.
6. Écritures atomiques pour HOTP, clés et restauration ; résistance aux coupures et protection contre les répétitions d'AES-GCM.
7. Tests de santé de la chaîne RNG/DRBG, test vectors AES/TOTP/HOTP, tests de signature, vérification par clients externes.
8. Publications reproductibles, artefacts identifiés par modèle et commit, empreintes, SBOM, historique de sécurité et procédure de signalement de failles.
9. Modèle de menace publié : hôte compromis, QR photographié par un tiers, backup volé, perte de l'appareil, restauration altérée, USB hostile, défaillance flash, mauvais PIN, vol de l'appareil.
10. Toutes les opérations d'export et d'effacement exigent une vérification sur le Trezor, **pas uniquement l'accord du PC**.

---

## 11. Licence et construction

- **Licence du nouveau firmware et des contributions propres à feuristic : `GPL-3.0-only`.** Conserver les notices d'origine des fichiers Trezor sous GPLv3/LGPLv3/MIT ou licences compatibles ; ne pas déclarer que toutes les dépendances amont portent la même licence.
- Code source intégral, scripts de construction, schéma des messages, formats de sauvegarde, tests, documentation utilisateur et développeur dans le dépôt.
- Builds séparés `T2B1` / `T3B1` avec **mêmes fonctions et même format de sauvegarde**, différences uniquement HAL, drivers et ajustements mémoire.
- Ne jamais utiliser les identifiants USB/Trezor officiels d'une manière suggérant une certification ou signature du fabricant. Déclarer le statut de firmware tiers.

---

## 12. Critères de recette obligatoires (non encore exécutés)

La conception ci-dessus est **figée** ; ce tableau décrit des **tests d'exécution**, pas des décisions restant à prendre. Un échec est un bug ou un blocage de release, pas une dispense implicite d'exigence.

| Test | Résultat exigé | Où |
|---|---|---|
| R01 | Firmware bootable, menu deux boutons, PIN, FR/EN | T2B1 et T3B1 réels |
| R02 | USB FIDO2 reconnu, passkey créée et utilisée | macOS, Windows, Linux ; deux révisions |
| R03 | CTAP 2.1 : `clientPIN`, `credentialManagement`, `credProtect`, `largeBlobs`, `hmac-secret` | libfido2 et navigateur ; deux révisions |
| R04 | **100 passkeys découvrables + 32 comptes OTP + 4 Kio largeBlobs**, sans corruption | deux révisions, tests endurance et coupure |
| R05 | Le volume FAT12 apparaît **seulement** après `Ajouter QR`, accepte PNG et JPEG, se retire après éjection propre, FIDO est restauré | Finder, Explorateur Windows, Linux |
| R06 | Rejet sûr d'images hostiles, tronquées, compressées excessivement, trop grandes, de QR hors format | fuzzing + deux révisions |
| R07 | Mode temporaire CDC-ACM, retour au mode HID+CCID, reprise au sein de la même alimentation USB, invalidation après coupure, confirmation en cas de recul | macOS, Windows, Linux |
| R08 | TOTP RFC 6238 et HOTP RFC 4226 corrects sur vecteurs de test ; compteur atomique | deux révisions |
| R09 | GnuPG détecte et utilise OpenPGP Card 3.4 **sans trezor-agent** | GnuPG/scdaemon ; deux révisions |
| R10 | OpenSC/PC-SC détecte PIV, cert, signature, challenge-response standards | macOS, Windows, Linux |
| R11 | `GET CHALLENGE` retourne des octets et respecte les protections RNG | outils PC/SC courants |
| R12 | APDU AES-256-GCM chiffrent, authentifient, rejettent les tags corrompus et n'utilisent jamais le même nonce sur une clé | vecteurs + coupures |
| R13 | Export de QR **réellement lisible par une caméra ordinaire** sur écran 128×64 ; import multi-QR, restauration, mauvais mot de passe, trame manquante | deux révisions et plusieurs téléphones |
| R14 | Export/restauration de chaque catégorie de données et compatibilité croisée T2B1→T3B1 / T3B1→T2B1 | deux révisions |
| R15 | Aucune clé n'est exportée sans procédure physique ; effacement, PIN, timeout et RAM nettoyée | tests fonctionnels et sécurité |
| R16 | Firmware compilé depuis source GPLv3 avec SBOM, notices et reproductibilité documentées | CI publique |

**Condition de publication :** **aucune release stable tant que tous les tests obligatoires ne passent pas sur les deux révisions**. En particulier, l'absence de preuve de lisibilité des sauvegardes QR et d'un espace mémoire suffisant pour la coexistence des modules bloque la release stable. Les tests ne sont pas prétendus réussis dans ce cahier des charges.

---

## 13. Ordre de réalisation arrêté

1. **Socle T2B1/T3B1** : construction, stockage, PIN, écran, FIDO2 minimal.
2. **USB et OTP** : CDC-ACM, MSC temporaire, FAT12, parsing PNG/JPEG QR, HOTP/TOTP, confirmations.
3. **CTAP 2.1 avancé** : gestion des passkeys, permissions, `largeBlobs`, protection d'identifiants.
4. **CCID / OpenPGP Card / PIV** : sélection AID, signatures, déchiffrement et certificats.
5. **AES / RNG ISO 7816** : environnement de sécurité, schéma d'APDU public, interopérabilité PC/SC.
6. **Sauvegarde/restauration QR** : `otpauth://`, enveloppes CBOR chiffrées, QR fragmentés, import atomique et compatibilité croisée.
7. **Durcissement** : tests de sécurité, fuzzing, coupures de courant, documents de menaces, reproductibilité et deux modèles physiques.

---

## 14. Références normatives et amont

- Trezor firmware : https://github.com/trezor/trezor-firmware
- Modèles Trezor : https://github.com/trezor/trezor-firmware/blob/main/docs/common/reproducible-build.md
- Licences Trezor : https://github.com/trezor/trezor-firmware/blob/main/LICENSE.md
- Stockage résident Trezor : https://github.com/trezor/trezor-firmware/blob/main/core/src/storage/resident_credentials.py
- FIDO CTAP 2.1 : https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html
- NIST PIV : https://csrc.nist.gov/pubs/sp/800/73/4/upd1/final
- OpenPGP Card : https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf
- OATH HOTP : https://www.rfc-editor.org/rfc/rfc4226
- OATH TOTP : https://www.rfc-editor.org/rfc/rfc6238
- CBOR : https://www.rfc-editor.org/rfc/rfc8949
- Base45 : https://www.rfc-editor.org/rfc/rfc9285
- ISO/IEC 7816-4 / 7816-8, USB CCID : normes internationales applicables aux cartes à puce.
- ST AN4879, capacité et endpoints USB FS sur STM32F427 : https://www.st.com/content/st_com/en/technical-documents/an4879-introduction-to-usb-hardware-and-pcb-guidelines-using-stm32-mcus-stmicroelectronics_asset/chunk-001-topic-an4879-usb-on-stm32-products.html

**Fin du cahier des charges feuristic v1.0.**
