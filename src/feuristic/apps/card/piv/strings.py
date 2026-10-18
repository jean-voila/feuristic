# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""English / French strings of the PIV application (spec §9: FR/EN built in)."""

STRINGS = {
    # menu (spec §9: PIV identités / certificats / signatures / exporter QR)
    "piv.title": ("PIV", "PIV"),
    "piv.identities": ("Identities", "Identités"),
    "piv.certificates": ("Certificates", "Certificats"),
    "piv.signatures": ("Signatures", "Signatures"),
    "piv.export_qr": ("Export as QR", "Exporter en QR"),
    "piv.settings": ("PIV settings", "Réglages PIV"),
    "piv.slot.empty": ("Empty", "Vide"),
    "piv.slot.key_only": ("Key, no certificate", "Clé sans certificat"),
    "piv.slot.cert_only": ("Certificate, no key", "Certificat sans clé"),
    "piv.slot.key_cert": ("Key + certificate", "Clé + certificat"),
    "piv.generate": ("Generate key", "Générer une clé"),
    "piv.delete": ("Delete slot", "Supprimer l'emplacement"),
    "piv.set_pin": ("Set PIV PIN", "Définir le PIN PIV"),
    "piv.set_puk": ("Set PIV PUK", "Définir le PUK PIV"),
    "piv.mgmt_key": ("Management key", "Clé d'administration"),
    "piv.mgmt_key.generate": ("Generate new key", "Générer une nouvelle clé"),
    "piv.mgmt_key.default": ("Restore default key", "Rétablir la clé par défaut"),
    "piv.reset": ("Reset PIV", "Réinitialiser PIV"),
    "piv.no_cert": ("No certificate", "Aucun certificat"),
    "piv.cert.unreadable": ("Certificate not readable", "Certificat illisible"),
    "piv.cert.compressed": ("Compressed certificate", "Certificat compressé"),
    # slot roles (spec §6.3 "rôle de la clé")
    "piv.role.auth": ("PIV Authentication", "Authentification PIV"),
    "piv.role.sign": ("Digital Signature", "Signature numérique"),
    "piv.role.keymgmt": ("Key Management", "Gestion de clés"),
    "piv.role.cardauth": ("Card Authentication", "Authentification carte"),
    # prompt titles / operations
    "piv.prompt.sign": ("PIV signature?", "Signature PIV ?"),
    "piv.prompt.decrypt": ("PIV private key operation?", "Opération clé privée PIV ?"),
    "piv.prompt.ecdh": ("PIV key agreement?", "Accord de clé PIV ?"),
    "piv.prompt.cardauth": ("PIV card authentication?", "Authentification carte PIV ?"),
    "piv.prompt.generate": ("Generate PIV key?", "Générer une clé PIV ?"),
    "piv.prompt.replace": ("Replace PIV key?", "Remplacer la clé PIV ?"),
    "piv.prompt.delete": ("Delete PIV slot?", "Supprimer l'emplacement PIV ?"),
    "piv.prompt.set_mgmt": ("Change PIV management key?", "Changer la clé d'administration PIV ?"),
    "piv.prompt.reset": ("Reset the PIV application?", "Réinitialiser l'application PIV ?"),
    "piv.op.sign": ("Signature", "Signature"),
    "piv.op.rsa": ("RSA private operation", "Opération RSA privée"),
    "piv.op.ecdh": ("ECDH key agreement", "Accord de clé ECDH"),
    "piv.op.challenge": ("Challenge-response", "Challenge-response"),
    # spec §6.3: raw digests are never interpreted
    "piv.sign.uninterpreted": ("Uninterpreted digest signature", "Signature d'empreinte non interprétée"),
    # prompt field labels
    "piv.field.operation": ("Operation", "Opération"),
    "piv.field.slot": ("Key", "Clé"),
    "piv.field.algorithm": ("Algorithm", "Algorithme"),
    "piv.field.fingerprint": ("Fingerprint", "Empreinte"),
    "piv.field.data": ("Data", "Données"),
    "piv.field.warning": ("Warning", "Attention"),
    "piv.field.subject": ("Subject", "Sujet"),
    "piv.field.issuer": ("Issuer", "Émetteur"),
    "piv.field.valid_from": ("Valid from", "Valide du"),
    "piv.field.valid_to": ("Valid to", "Valide au"),
    "piv.field.serial": ("Serial", "N° de série"),
    "piv.field.pin_policy": ("PIN", "PIN"),
    "piv.pin_policy.never": ("Never", "Jamais"),
    "piv.pin_policy.once": ("Once per session", "Une fois par session"),
    "piv.pin_policy.always": ("Every use", "À chaque usage"),
    # warnings
    "piv.warn.replace": (
        "The current key and its certificate will be destroyed.",
        "La clé actuelle et son certificat seront détruits.",
    ),
    "piv.warn.delete": (
        "The key and certificate of this slot will be destroyed.",
        "La clé et le certificat de cet emplacement seront détruits.",
    ),
    "piv.warn.reset": (
        "All PIV keys, certificates and settings will be erased.",
        "Toutes les clés, certificats et réglages PIV seront effacés.",
    ),
    "piv.warn.mgmt_host": (
        "Requested by the computer.",
        "Demandé par l'ordinateur.",
    ),
    "piv.warn.default_pin": ("Default PIV PIN (123456) in use", "PIN PIV par défaut (123456) actif"),
    "piv.warn.default_puk": ("Default PIV PUK (12345678) in use", "PUK PIV par défaut (12345678) actif"),
    "piv.warn.default_mgmt": (
        "Default PIV management key in use",
        "Clé d'administration PIV par défaut active",
    ),
    "piv.warn.pin_blocked": ("PIV PIN blocked", "PIN PIV bloqué"),
    "piv.warn.puk_blocked": ("PIV PUK blocked", "PUK PIV bloqué"),
    "piv.rsa.generating": ("Generating RSA key…", "Génération de la clé RSA…"),
}


def register() -> None:
    """Register the PIV strings in :mod:`feuristic.core.i18n` (idempotent)."""
    from ....core import i18n

    i18n.register(STRINGS)
