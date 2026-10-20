<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Guide utilisateur — français

**Version candidate pour essais, non validée sur matériel réel.** Employer des
identités de test. L'installation efface les données et dégrade irréversiblement
l'attestation constructeur : lire [installation](install.md). Les critères
[R01–R16](../acceptance/README.md) doivent passer sur T2B1 **et** T3B1 avant une
release stable. Il n'existe aucune fonction portefeuille ni migration de seed.

## Première utilisation et navigation

Après l'avertissement `UNSAFE, DO NOT USE!`, choisir Français, lire le statut de
firmware tiers et saisir deux fois un nouveau PIN de **4 à 50 chiffres**. Ce PIN
protège le stockage de l'appareil ; le choisir avant d'ajouter des identités.

- Gauche : précédent ; droite : suivant ; les deux : sélectionner/valider.
- Maintenir gauche environ une seconde : retour ou annulation.
- Sur un écran de confirmation, lire toutes les pages et suivre l'indication
  « maintenir » pour une action destructive. Une annulation ne doit jamais
  équivaloir à une validation.
- La saisie se fait sur l'appareil : choisir les caractères/chiffres avec les
  boutons, valider les choix, puis l'action de fin proposée par le clavier.
- Les listes longues utilisent « Suite... ». Revenir avec « Retour » ou gauche
  longue pour remonter d'un niveau.

Le menu principal contient Authentification, Cryptographie, Sauvegarde,
Réglages et Verrouiller. Le verrouillage intervient après **5 minutes**
d'inactivité ; Verrouiller permet de le déclencher immédiatement. Refaire le
PIN pour reprendre. Les erreurs de PIN consomment des essais persistants,
avec délais ; l'épuisement des essais du stockage amont efface l'appareil.
Ne pas tester cette limite sur les seules copies d'identités utiles.

Les PIN ne sont pas interchangeables :

| Secret | Usage |
|---|---|
| PIN de l'appareil | déverrouillage local, réauthentification export/gestion |
| PIN FIDO | vérification utilisateur WebAuthn, demandé par le client standard |
| OpenPGP PW1/PW3/code de réinitialisation | opérations utilisateur/administration de la carte |
| PIV PIN/PUK/clé d'administration | opérations et configuration PIV |
| Phrase de sauvegarde | chiffrement des QR ; 12 à 128 caractères ASCII imprimables, distincte du PIN |

## Passkeys, clé de sécurité et challenge-response

Déverrouiller et laisser le mode USB normal actif. Dans les réglages de
sécurité d'un **compte de test**, demander l'ajout d'une clé de sécurité USB
ou d'une passkey. Le navigateur peut demander un PIN FIDO : il est distinct
du PIN de l'appareil. Vérifier le nom du service et du compte sur le Safe 3,
puis confirmer. Déconnecter la session du site et vérifier une connexion avec
la clé, en refusant aussi une demande pour constater qu'elle échoue.

Gestion locale : **Authentification → Passkeys → Services → service → compte**.
Consulter les informations/protections, exporter l'identité ou supprimer la
passkey choisie. Le menu Passkeys propose également le PIN FIDO et l'effacement
des données FIDO. La suppression locale d'une passkey ne supprime pas son
inscription côté site ; supprimer aussi l'ancienne clé dans les réglages du
compte si nécessaire. Les clés non découvrables ne figurent pas dans cette liste
et ne font pas partie des sauvegardes d'identités découvrables.

FIDO2/CTAP 2.1 propose `clientPIN`, `credentialManagement`, `credProtect`,
`largeBlobs` et `hmac-secret`, ainsi que U2F. Il n'y a ni biométrie ni
attestation constructeur. Les passkeys découvrables peuvent être sauvegardées
et exportent donc leur clé privée sous forme chiffrée ; elles ne sont pas
présentées comme inexportables. Les paramètres WebAuthn de sauvegarde reflètent
ce fonctionnement. Détails : [protocole FIDO2](../protocols/fido2.md).

Pour OpenSSH compatible FIDO, une création de clé de test standard est :

```sh
ssh-keygen -t ed25519-sk -O resident -f ./feuristic-test-sk
```

Choisir un nom de fichier neuf, définir le PIN FIDO si le client le demande et
confirmer à l'écran. Le fichier local est une référence à la clé matérielle ;
son emploi dépend du support FIDO du client/serveur. Les signatures SSH de Git
utilisent ensuite la configuration SSH normale de Git.

**Authentification → Challenge-response** donne les indications de protocole.
Une opération réelle est déclenchée par un client WebAuthn `hmac-secret` ou
PIV `GENERAL AUTHENTICATE`, avec les contrôles de présence prévus ; il n'existe
pas de protocole SSH propriétaire ni de calcul de défi saisi dans ce menu.

## Ajouter et utiliser un OTP

1. Obtenir, auprès du service de test, son QR `otpauth://`. Préparer une image
   PNG ou **JPEG baseline**, contenant un seul QR pertinent, ≤ **256 Kio**,
   dimensions ≤ **1024 × 1024**. JPEG progressif et image HEIC ne conviennent pas.
2. Sélectionner **Authentification → OTP → Ajouter QR par USB**. Le volume
   temporaire d'import apparaît ; HID FIDO et CCID sont suspendus.
3. Copier l'image sur le volume FAT12 de Feuristic. Copier un fichier à la fois
   et attendre l'analyse. Le volume n'est pas un disque de sauvegarde : relire
   les images peut renvoyer des zéros, elles ne sont pas conservées.
4. Vérifier service, compte, type et paramètres sur l'appareil. Confirmer
   physiquement l'ajout ; une copie seule n'ajoute jamais le secret.
5. Quand l'appareil le demande, **éjecter proprement le volume sur l'ordinateur**
   (Finder, Explorateur ou éjection du périphérique Linux). Attendre le retour
   au mode normal avant de relancer une opération FIDO/smartcard.

Sélectionner un compte puis Voir le code. TOTP nécessite l'heure de la session
courante. HOTP demande une confirmation avant de générer le code et d'avancer
son compteur persistant. Ne pas avancer plusieurs fois un HOTP pour le plaisir
de vérifier l'écran : le serveur peut limiter la fenêtre de resynchronisation.

Le profil accepte SHA1/SHA256/SHA512, 6/7/8 chiffres ; les périodes TOTP vont de
15 à 300 s. Le service distant doit employer les mêmes paramètres. L'import
refuse les autres formats et les dépassements de capacité. Une erreur laisse
les entrées existantes intactes. Annuler puis éjecter pour quitter ; en cas de
réordonnancement/fragmentation des écritures, recommencer dans un nouveau mode
d'import. Voir [profil otpauth](../protocols/otpauth.md).

## Synchroniser l'heure TOTP

Sélectionner **Réglages → Heure TOTP → Synchroniser par USB**. Le Safe 3
réapparaît temporairement comme port série CDC-ACM, FIDO/CCID sont indisponibles.
Un terminal série standard peut envoyer `TIME 1 ` suivi de l'heure Unix en
secondes et d'un retour à la ligne. `OK` confirme ; `ERR` indique un refus ou
une erreur. L'horloge de l'ordinateur doit être correcte.

L'outil facultatif fourni envoie la même commande standard :

```sh
uv run python tools/feuristic_time.py
```

Il détecte le VID/PID d'essai actuel. Avec plusieurs ports, indiquer le vrai
chemin en argument. Les exemples macOS, Linux et PowerShell sont dans le
[protocole heure](../protocols/time-sync-v1.md). Un recul de plus de 60 s ou une
avance de plus de 300 s demande une confirmation à l'écran. Succès, annulation
ou délai de cinq minutes ramènent au mode USB normal. L'heure survit à cette
réénumération, **pas au retrait de l'alimentation** ; après coupure l'écran
montre « Heure à synchroniser » au lieu d'inventer un code.

## OpenPGP avec GnuPG

**Cryptographie → OpenPGP** permet de générer les trois clés, voir leurs rôles/
algorithmes/empreintes, supprimer une ou toutes les clés, exporter l'identité,
gérer les PIN et réinitialiser l'application. Synchroniser d'abord l'heure
pour une génération locale : les empreintes OpenPGP incluent la date de clé.
Choisir le profil Ed25519/X25519, ou RSA-2048 pour les besoins de compatibilité.
Une nouvelle génération remplace les trois rôles ; sauvegarder auparavant.

Les valeurs initiales sont PW1 **123456** et PW3 **12345678** : les changer dans
PIN de la carte. Le code de réinitialisation est facultatif. Le déverrouillage
local par PIN de l'appareil permet également de gérer les essais bloqués.

Installer GnuPG avec `scdaemon` et PC/SC, sans `trezor-agent`. L'appareil
présente une carte OpenPGP 3.4 via CCID :

```sh
gpg --card-status
gpg --card-edit
```

GnuPG peut générer les clés par sa procédure `admin`, puis `generate` ; chaque
génération/opération sensible exige aussi l'accord sur l'appareil. Conserver
le certificat OpenPGP public, les sous-clés et les informations de révocation
selon les procédures GnuPG : une sauvegarde de la carte n'est pas une copie
complète du trousseau public GnuPG. Utiliser `disable-ccid` dans
`scdaemon.conf` lorsque GnuPG doit passer par PC/SC. Une restauration sur un
autre appareil change le numéro de carte ; relancer `gpg --card-status` pour
réapprendre les clés. Détails : [OpenPGP](../protocols/openpgp.md).

## PIV, certificats et signatures

**Cryptographie → PIV → Identités → emplacement** propose informations,
génération P-256/RSA-2048, certificat, politique PIN, export QR et suppression.
Les quatre emplacements sont 9A (authentification), 9C (signature), 9D (accord
de clé) et 9E (authentification de carte). Générer de nouveau détruit l'ancienne
clé et son certificat. Les certificats X.509 publics (≤ 2048 octets) sont
chargés avec un outil PIV standard et doivent correspondre à la clé créée.

Dans Réglages PIV, changer le PIN initial **123456**, le PUK **12345678** et la
clé d'administration AES-192 initiale
`010203040506070801020304050607080102030405060708`. Le PIN/PUK local est de 6 à
8 chiffres. Une clé d'administration générée se montre localement en Hex ou QR,
pendant une durée limitée : la conserver confidentiellement pour configurer les
outils hôte. Ce QR représente un secret d'administration, pas un certificat.

Détection via OpenSC :

```sh
opensc-tool --list-readers
pkcs15-tool --dump
yubico-piv-tool -r '' -a status
```

Le filtre `-r ''` permet à cet outil de voir une carte qui n'est pas nommée
Yubikey. Utiliser OpenSC/PKCS#11 ou un client PIV pour les certificats, TLS ou
SSH. Les commandes détaillées et règles PIN sont dans [PIV](../protocols/piv.md).
Une confirmation de signature affiche rôle, algorithme et empreinte de clé.
« Signature d'empreinte non interprétée » signifie que l'appareil voit une
empreinte/un bloc et ne peut pas attester la signification du document hôte.

## AES-256-GCM et aléa

**Cryptographie → AES** : créer une clé, choisir son identifiant 1–16, nommer
avec 1–16 caractères ASCII et choisir la confirmation à chaque opération ou
une fois par session. Dans la clé : informations/empreinte, renommage,
politique, activation/désactivation, export chiffré, suppression. La politique
« par session » autorise ensuite des opérations sans nouvelle confirmation
jusqu'à réinitialisation de la carte, verrouillage ou changement USB.

Le chiffrement utilise CCID/PC-SC, SELECT/MSE/PSO du
[profil AES-GCM v1](../protocols/aes-gcm-iso7816-v1.md), avec client complet
publié dans cette annexe. Il ne s'agit pas d'une fonction AES automatiquement
exposée par le module PIV PKCS#11. Limites par opération : 3584 octets de texte,
256 octets de données associées ; nonce généré par l'appareil et tag authentifié.
La désactivation d'une clé refuse les opérations sans la détruire.

**Cryptographie → Aléa** montre état, informations et autotest. Le test peut
être relancé avec réauthentification. Exemple standard PC/SC pour 32 octets :

```sh
opensc-tool -s 0084000020
```

`GET CHALLENGE` est limité à 1–32 octets, sans PIN applicatif, avec contrôles
santé et anti-abus. Une erreur de santé doit refuser la sortie, pas fournir
une chaîne supposée aléatoire.

## Sauvegarde et restauration

Toute photo d'un QR OTP non chiffré permet de reproduire ses codes. Les QR
chiffrés d'identité contiennent les clés privées : photos **et** phrase suffisent
pour les restaurer. Photographier hors de la vue de tiers et maîtriser toute
synchronisation cloud de la caméra. Aucune phrase n'est récupérable par Feuristic.

Pour un OTP individuel, son menu Sauvegarder QR montre un `otpauth://` standard
après PIN et avertissement. Si l'URI ne tient pas à l'écran, suivre le repli en
sauvegarde chiffrée fragmentée proposé par l'interface.

1. Choisir **Sauvegarde → Exporter une identité**, puis catégorie/identité, ou
   **Export complet** pour enchaîner les identités sauvegardables.
2. Choisir Lisibilité QR : Gros modules (davantage de photos) ou dense.
   La lecture physique des deux profils reste à qualifier en R13.
3. Lire/valider les avertissements, saisir deux fois une phrase de 12–128
   caractères ASCII imprimables, différente du PIN, puis réauthentifier le PIN
   de l'appareil. Attendre la dérivation de clé ; ne pas retirer l'alimentation.
4. Photographier **toutes** les trames de chaque identité. Le numéro est affiché
   avant chaque QR ; gauche revient, droite avance, droite sur la dernière
   termine l'identité ; les deux terminent après que toutes ont été vues.
   Gauche longue ou 60 s sans action interrompt/masque l'affichage.
5. Conserver les images et la phrase séparément. Vérifier la restauration
   avant d'effacer l'original. « Export terminé » prouve l'affichage, pas la
   qualité des photos ni leur conservation.

Pour restaurer, **Sauvegarde → Restaurer** ouvre le volume temporaire. Convertir
les photos en PNG/JPEG baseline répondant aux limites, sans perdre les modules.
Copier un fichier à la fois, **toutes les trames d'une seule identité**, puis
appuyer sur Continuer. L'ordre des fragments est libre et les doublons identiques
sont ignorés ; une trame manquante bloque cette identité sans la modifier.
Saisir la phrase sur l'appareil et confirmer l'identité, puis tout écrasement
annoncé. Pendant ces confirmations et calculs, l'import d'un nouveau fichier est
suspendu : une copie refusée par l'ordinateur doit être **recommencée après que
l'appareil invite à copier l'identité suivante**. Ne pas interpréter un échec
« périphérique pas prêt » comme une importation réussie.

Si une identité contient beaucoup d’images, la racine FAT12 possède seulement
64 entrées. Utiliser des noms courts comme `QR000001.PNG` et des lots de
32 images au plus. Attendre que le compteur de l’appareil indique leur
réception, puis supprimer **uniquement ces copies du volume d’import** ;
conserver les images originales de la sauvegarde ailleurs. Copier le lot
suivant sur le même volume monté, sans éjection ni redémarrage avant réception
de toutes les trames de cette identité.

Répéter pour chaque identité en gardant le volume monté. La même phrase n'est
pas redemandée pour les identités du même ensemble tant que sa clé de session
est en cache. Choisir Terminé pour finir, lire le bilan et l'avertissement si
l'ensemble reste incomplet, puis éjecter quand demandé. Les identités déjà
confirmées restent restaurées si la suivante échoue ou manque. Une mauvaise
phrase/tag ne modifie jamais l'identité en cours. L'appareil affiche le nombre
d'identités restaurées ; retrouver celles-ci dans leurs menus.

Une restauration est atomique **par identité**, pas une transaction globale :
un export complet est une succession d'identités indépendantes. Le PIN de
l'appareil, le PIN FIDO et les identifiants d'administration PIV ne constituent
pas un clonage global des réglages ; la destination conserve ses propres
identifiants PIV, tandis que l'identité OpenPGP conserve ses références PIN.
HOTP ne recule pas son compteur pour le même secret. L'usage parallèle d'une
clé AES restaurée sur plusieurs appareils n'offre pas une garantie absolue
d'unicité mondiale des nonces ; voir [limites AES](../protocols/backup-aes.md).

## Capacité, USB et dépannage

Les **100 passkeys découvrables + 32 OTP + 4096 octets de largeBlobs** partagent
le secteur de 64 Kio avec les autres applications. Ce contrat ne signifie pas
que toutes les capacités maximales OpenPGP/PIV/AES s'ajoutent sans limite.
Un refus « Stockage plein » doit conserver les identités présentes. Les
sauvegardes volumineuses peuvent nécessiter des centaines de photos ; ne pas
promettre un QR unique ou une restauration rapide. Sur T2B1 la mémoire est
particulièrement contrainte ; le bilan est dans le [budget](../developer/storage-budget.md).

Réglages permet de changer le PIN de l'appareil, la langue FR/EN et l'heure,
voir les informations USB et Matériel/version. Interfaces USB est un écran
informatif ; il n'active pas simultanément tous les protocoles. Effacement
intégral exige confirmations renforcées et PIN, puis redémarre vierge.

Le VID/PID actuel `1209:0001` est un **identifiant de test**, pas un PID attribué
au projet. Linux/libccid peut nécessiter un enregistrement local du lecteur ;
voir [CCID, notes hôte](../protocols/ccid.md). Après un mode temporaire, rouvrir
les logiciels qui ont conservé un ancien handle USB. S'il n'y a pas de port
série/disque, vérifier que le bon mode est actif et que le câble transporte les
données. Ne jamais reformater le volume d'import. En cas d'échec, noter version,
modèle, OS, action et message sans publier de secret, puis suivre
[SECURITY.md](../../SECURITY.md) si le défaut touche à la sécurité.

Le volume FAT12 porte le libellé `FEURISTIC` ; le nom SCSI du périphérique est
`FEURISTIC-IMPORT` (le nom complet dépasse les 11 caractères d'un label FAT).
Le mode d'import expire après dix minutes. Le récepteur matériel traite une
identité à la fois, avec une enveloppe chiffrée de **12 Kio maximum**, ce qui
couvre les exports natifs testés, y compris OpenPGP/RSA et passkey avec largeBlob.
Le format public v1 autorise des enveloppes jusqu'à 64 Kio et 16 éléments dans
une enveloppe Full : ces bornes génériques ne constituent pas une promesse
d'import de n'importe quel paquet tiers sur l'appareil. Un export complet natif
enchaîne des enveloppes indépendantes à une identité, dans le même volume monté.
