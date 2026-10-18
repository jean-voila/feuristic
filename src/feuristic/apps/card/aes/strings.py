# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""English / French strings of the AES-256-GCM and RNG functions (spec §9)."""

STRINGS = {
    # menu (spec §9: AES (clés / paramètres / supprimer / exporter QR), Aléa)
    "aes.title": ("AES", "AES"),
    "aes.keys": ("Keys", "Clés"),
    "aes.settings": ("Settings", "Paramètres"),
    "aes.delete": ("Delete", "Supprimer"),
    "aes.export_qr": ("Export as QR", "Exporter en QR"),
    "aes.create": ("Create key", "Créer une clé"),
    "aes.rename": ("Rename", "Renommer"),
    "aes.enable": ("Enable", "Activer"),
    "aes.disable": ("Disable", "Désactiver"),
    "aes.empty": ("No AES key yet", "Aucune clé AES"),
    "aes.full": ("All 16 key slots are used", "Les 16 emplacements de clé sont utilisés"),
    "aes.enabled": ("Enabled", "Activée"),
    "aes.disabled": ("Disabled", "Désactivée"),
    "aes.policy.every": ("Confirm every operation", "Confirmer chaque opération"),
    "aes.policy.session": ("Confirm once per session", "Confirmer une fois par session"),
    "aes.created": ("Key created", "Clé créée"),
    # prompts
    "aes.prompt.encrypt": ("Encrypt with AES key?", "Chiffrer avec la clé AES ?"),
    "aes.prompt.decrypt": ("Decrypt with AES key?", "Déchiffrer avec la clé AES ?"),
    "aes.prompt.delete": ("Delete AES key?", "Supprimer la clé AES ?"),
    "aes.prompt.wipe": ("Delete all AES keys?", "Supprimer toutes les clés AES ?"),
    "aes.field.key": ("Key", "Clé"),
    "aes.field.operation": ("Operation", "Opération"),
    "aes.field.length": ("Data", "Données"),
    "aes.field.fingerprint": ("Check value", "Valeur de contrôle"),
    "aes.field.policy": ("Confirmation", "Confirmation"),
    "aes.field.warning": ("Warning", "Attention"),
    "aes.op.encrypt": ("AES-256-GCM encryption", "Chiffrement AES-256-GCM"),
    "aes.op.decrypt": ("AES-256-GCM decryption", "Déchiffrement AES-256-GCM"),
    "aes.unit.bytes": ("{} bytes", "{} octets"),
    "aes.session_note": (
        "No further confirmation for this key until the device is locked.",
        "Plus de confirmation pour cette clé jusqu'au verrouillage.",
    ),
    "aes.warn.delete": (
        "Data encrypted with this key can no longer be decrypted without a backup.",
        "Les données chiffrées avec cette clé ne pourront plus être déchiffrées sans sauvegarde.",
    ),
    "aes.warn.wipe": (
        "All AES keys will be destroyed.",
        "Toutes les clés AES seront détruites.",
    ),
    # RNG (spec §9: Aléa (RNG : état / informations))
    "rng.title": ("Randomness", "Aléa"),
    "rng.status": ("Status", "État"),
    "rng.info": ("Information", "Informations"),
    "rng.retest": ("Run self-test", "Relancer le test"),
    "rng.state.untested": ("Not tested yet", "Pas encore testé"),
    "rng.state.ok": ("Healthy", "Sain"),
    "rng.state.failed": ("FAILED: output blocked", "ÉCHEC : sortie bloquée"),
    "rng.field.tested": ("Bytes tested", "Octets testés"),
    "rng.field.delivered": ("Bytes delivered", "Octets fournis"),
    "rng.field.requests": ("Requests", "Requêtes"),
    "rng.field.rct": ("Repetition test failures", "Échecs test de répétition"),
    "rng.field.apt": ("Proportion test failures", "Échecs test de proportion"),
    "rng.field.last_failure": ("Last failure", "Dernier échec"),
    "rng.field.rate_limited": ("Rate-limited requests", "Requêtes limitées"),
    "rng.field.source": ("Source", "Source"),
    "rng.source": ("TRNG + secure element + DRBG", "TRNG + élément sécurisé + DRBG"),
    "rng.limits": ("Max 32 bytes per request, 20 req/s", "32 octets max par requête, 20 req/s"),
    "rng.error": ("Random generator unavailable", "Générateur d'aléa indisponible"),
}


def register() -> None:
    """Register the AES/RNG strings in :mod:`feuristic.core.i18n` (idempotent)."""
    from ....core import i18n

    i18n.register(STRINGS)
