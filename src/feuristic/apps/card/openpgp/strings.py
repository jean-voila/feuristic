# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""English/French strings of the OpenPGP card application (spec §9)."""

from ....core import i18n

STRINGS = {
    # prompt titles
    "openpgp.confirm.sign": ("OpenPGP signature", "Signature OpenPGP"),
    "openpgp.confirm.decrypt": ("OpenPGP decryption", "Déchiffrement OpenPGP"),
    "openpgp.confirm.auth": ("OpenPGP authentication", "Authentification OpenPGP"),
    "openpgp.confirm.generate": ("Generate OpenPGP key", "Générer une clé OpenPGP"),
    "openpgp.confirm.replace_key": ("Replace OpenPGP key", "Remplacer la clé OpenPGP"),
    "openpgp.confirm.attr_change": ("Change key algorithm", "Changer l'algorithme de clé"),
    "openpgp.confirm.terminate": ("Factory reset OpenPGP", "Réinitialiser OpenPGP"),
    # field labels
    "openpgp.field.type": ("Type", "Type"),
    "openpgp.field.role": ("Key", "Clé"),
    "openpgp.field.algorithm": ("Algorithm", "Algorithme"),
    "openpgp.field.fingerprint": ("Fingerprint", "Empreinte"),
    "openpgp.field.uninterpreted": (
        "Uninterpreted digest signature",
        "Signature d'empreinte non interprétée",
    ),
    "openpgp.field.input_hash": ("Data (SHA-256)", "Données (SHA-256)"),
    "openpgp.field.pubkey_hash": ("Public key (SHA-256)", "Clé publique (SHA-256)"),
    "openpgp.field.warning": ("Warning", "Attention"),
    "openpgp.field.created": ("Created", "Créée le"),
    # values
    "openpgp.role.sig": ("Signature", "Signature"),
    "openpgp.role.dec": ("Decryption", "Déchiffrement"),
    "openpgp.role.aut": ("Authentication", "Authentification"),
    "openpgp.type.eddsa": ("EdDSA signature", "Signature EdDSA"),
    "openpgp.type.rsa_pkcs1": ("RSA PKCS#1 v1.5 signature", "Signature RSA PKCS#1 v1.5"),
    "openpgp.type.ecdh": ("ECDH key agreement", "Accord de clé ECDH"),
    "openpgp.type.rsa_decrypt": ("RSA PKCS#1 v1.5 decryption", "Déchiffrement RSA PKCS#1 v1.5"),
    "openpgp.warn.key_lost": (
        "The existing key is destroyed",
        "La clé existante est détruite",
    ),
    "openpgp.warn.terminate": (
        "All OpenPGP keys and data are erased",
        "Toutes les clés et données OpenPGP sont effacées",
    ),
    "openpgp.no_fingerprint": ("(not set)", "(non définie)"),
    # menus / local management (spec §9: OpenPGP générer / voir / supprimer / exporter QR)
    "openpgp.menu.title": ("OpenPGP", "OpenPGP"),
    "openpgp.menu.generate": ("Generate keys", "Générer les clés"),
    "openpgp.menu.view": ("View keys", "Voir les clés"),
    "openpgp.menu.delete": ("Delete keys", "Supprimer les clés"),
    "openpgp.menu.export": ("Export QR", "Exporter QR"),
    "openpgp.menu.pins": ("Card PINs", "PIN de la carte"),
    "openpgp.menu.reset": ("Factory reset", "Réinitialisation"),
    "openpgp.profile.ed25519": ("Ed25519 / Curve25519", "Ed25519 / Curve25519"),
    "openpgp.profile.rsa2048": ("RSA-2048 (compatibility)", "RSA-2048 (compatibilité)"),
    "openpgp.pin.pw1": ("User PIN (PW1)", "PIN utilisateur (PW1)"),
    "openpgp.pin.pw3": ("Admin PIN (PW3)", "PIN administrateur (PW3)"),
    "openpgp.pin.rc": ("Resetting code", "Code de réinitialisation"),
    "openpgp.pin.retries": ("{} tries left", "{} essais restants"),
    "openpgp.pin.blocked": ("Blocked", "Bloqué"),
    "openpgp.pin.too_short": ("At least {} digits", "Au moins {} chiffres"),
    "openpgp.status.no_key": ("No key", "Aucune clé"),
    "openpgp.status.terminated": ("Application terminated", "Application terminée"),
    "openpgp.status.signatures": ("Signatures: {}", "Signatures : {}"),
    "openpgp.time_required": (
        "Synchronise the time before generating keys",
        "Synchronisez l'heure avant de générer des clés",
    ),
    "openpgp.generating": ("Generating keys...", "Génération des clés..."),
    # backup
    "openpgp.backup.label": ("OpenPGP card", "Carte OpenPGP"),
    "openpgp.backup.warning": (
        "Exported keys can be restored by anyone holding the QR codes and the passphrase",
        "Les clés exportées sont restaurables par quiconque possède les QR et la phrase",
    ),
}


def register() -> None:
    i18n.register(STRINGS)


register()
