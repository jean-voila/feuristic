# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""English/French strings of the QR backup application (spec §8, §9).

Registered with :mod:`feuristic.core.i18n` by :func:`register` (called when
:mod:`feuristic.apps.backup.export` is imported). Placeholders use
``str.format`` positional fields.
"""

from ...core import i18n

STRINGS = {
    # menu (spec §9 "Sauvegarde")
    "backup.menu.title": ("Backup", "Sauvegarde"),
    "backup.menu.export_identity": ("Export an identity (QR)", "Exporter une identité (QR)"),
    "backup.menu.export_full": ("Full export (QR sequences)", "Export complet (séquences QR)"),
    "backup.menu.restore": ("Restore (USB import)", "Restaurer (import USB)"),
    # prompts
    "backup.export.title": ("Export identity", "Exporter l'identité"),
    "backup.export_full.title": ("Full export", "Export complet"),
    "backup.restore.title": ("Restore backup", "Restaurer la sauvegarde"),
    "backup.overwrite.title": ("Overwrite identity?", "Écraser l'identité ?"),
    "backup.restore_incomplete.title": ("Incomplete full export", "Export complet incomplet"),
    "backup.restore_done.title": ("Restore finished", "Restauration terminée"),
    "backup.wrong_passphrase.title": ("Wrong passphrase", "Phrase incorrecte"),
    "backup.passphrase_policy.title": ("Passphrase too weak", "Phrase trop faible"),
    # fields
    "backup.field.identity": ("Identity", "Identité"),
    "backup.field.category": ("Type", "Type"),
    "backup.field.count": ("Identities", "Identités"),
    "backup.field.present": ("Present", "Présentes"),
    "backup.field.restored": ("Restored", "Restaurées"),
    "backup.field.skipped": ("Skipped", "Ignorées"),
    "backup.field.failed": ("Not restored", "Non restaurées"),
    "backup.field.warning": ("Warning", "Avertissement"),
    "backup.field.fingerprint": ("Fingerprint", "Empreinte"),
    # warnings (spec §8.2: mandatory announcement)
    "backup.warn.recoverable": (
        "Anyone who has these QR images and the passphrase can recover the keys. "
        "Exported keys are no longer non-exportable.",
        "Toute personne possédant ces images QR et la phrase peut récupérer les clés. "
        "Les clés exportées ne sont plus inexportables.",
    ),
    "backup.warn.overwrite": (
        "The existing identity will be replaced by the one from the backup.",
        "L'identité existante sera remplacée par celle de la sauvegarde.",
    ),
    "backup.warn.incomplete": (
        "Some identities of this full export are missing. Restore the others anyway?",
        "Certaines identités de cet export complet manquent. Restaurer les autres quand même ?",
    ),
    "backup.warn.slow": (
        "A full export may need many QR codes. It is neither quick nor convenient.",
        "Un export complet peut nécessiter de nombreux QR. Ce n'est ni rapide ni pratique.",
    ),
    # passphrase entry
    "backup.passphrase.enter": ("Enter backup passphrase", "Saisir la phrase de sauvegarde"),
    "backup.passphrase.confirm": ("Repeat the passphrase", "Répéter la phrase"),
    "backup.passphrase.mismatch": ("Passphrases differ", "Les phrases diffèrent"),
    "backup.passphrase_policy": (
        "At least 12 characters, letters, digits, spaces or symbols (ASCII). Not your PIN.",
        "Au moins 12 caractères : lettres, chiffres, espaces ou symboles (ASCII). Pas votre PIN.",
    ),
    "backup.wrong_passphrase": (
        "Wrong passphrase or damaged backup. Nothing was changed.",
        "Phrase incorrecte ou sauvegarde endommagée. Rien n'a été modifié.",
    ),
    # progress / display
    "backup.kdf.progress": ("Deriving key… {}%", "Dérivation de la clé… {} %"),
    "backup.frame.counter": ("QR {} of {}", "QR {} sur {}"),
    "backup.identity.counter": ("Identity {} of {}", "Identité {} sur {}"),
    "backup.profile.dense": ("Dense QR", "QR dense"),
    "backup.profile.large": ("Large modules", "Gros modules"),
    "backup.version": ("Backup format v{}", "Format de sauvegarde v{}"),
    "backup.nothing": ("Nothing to export", "Rien à exporter"),
    # errors (see ERROR_KEYS)
    "backup.err.format": ("Not a valid feuristic backup", "Sauvegarde feuristic invalide"),
    "backup.err.version": (
        "Backup from a newer firmware (unsupported version)",
        "Sauvegarde d'un firmware plus récent (version non prise en charge)",
    ),
    "backup.err.params": ("Unsupported backup parameters", "Paramètres de sauvegarde non pris en charge"),
    "backup.err.auth": (
        "Wrong passphrase or damaged backup. Nothing was changed.",
        "Phrase incorrecte ou sauvegarde endommagée. Rien n'a été modifié.",
    ),
    "backup.err.plaintext": ("Backup content is invalid", "Contenu de sauvegarde invalide"),
    "backup.err.weak": ("Passphrase too weak", "Phrase trop faible"),
    "backup.err.item": (
        "This backup contains an unsupported identity type",
        "Cette sauvegarde contient un type d'identité non pris en charge",
    ),
    "backup.err.frame": ("Unreadable backup QR", "QR de sauvegarde illisible"),
    "backup.err.checksum": ("Damaged QR (checksum error)", "QR endommagé (somme de contrôle)"),
    "backup.err.other_backup": ("QR from another backup", "QR d'une autre sauvegarde"),
    "backup.err.total": ("Inconsistent QR count", "Nombre de QR incohérent"),
    "backup.err.conflict": ("Conflicting duplicate QR", "QR en double contradictoire"),
    "backup.err.limit": ("Backup too large", "Sauvegarde trop volumineuse"),
    "backup.err.missing": ("Missing QR: {}", "QR manquants : {}"),
    "backup.err.storage_full": ("Storage full", "Stockage plein"),
    "backup.err.cancelled": ("Cancelled", "Annulé"),
}


def _error_table() -> tuple:
    from ...core import errors as core_errors
    from . import errors as e

    # most specific classes first (isinstance walk; no __bases__ on MicroPython)
    return (
        (e.UnsupportedVersion, "backup.err.version"),
        (e.UnsupportedParameters, "backup.err.params"),
        (e.BackupFormatError, "backup.err.format"),
        (e.AuthenticationFailed, "backup.err.auth"),
        (e.PlaintextError, "backup.err.plaintext"),
        (e.WeakPassphrase, "backup.err.weak"),
        (e.UnsupportedItem, "backup.err.item"),
        (e.FrameChecksumError, "backup.err.checksum"),
        (e.FrameIdMismatch, "backup.err.other_backup"),
        (e.FrameTotalMismatch, "backup.err.total"),
        (e.FrameConflict, "backup.err.conflict"),
        (e.FrameLimitExceeded, "backup.err.limit"),
        (e.FrameIncomplete, "backup.err.missing"),
        (e.FrameError, "backup.err.frame"),
        (core_errors.StorageFull, "backup.err.storage_full"),
        (core_errors.UserCancelled, "backup.err.cancelled"),
    )


def error_key(exc) -> str:
    """Most specific i18n key for the backup error ``exc``."""
    for cls, key in _error_table():
        if isinstance(exc, cls):
            return key
    return "backup.err.format"


def register() -> None:
    i18n.register(STRINGS)
