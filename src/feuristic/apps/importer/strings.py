# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""English/French strings of the QR import session (spec §3.3, §9)."""

from ...core import i18n

STRINGS = {
    "importer.title": ("Import a QR", "Importer un QR"),
    "importer.instructions": (
        "Copy PNG or JPEG images to the FEURISTIC-IMPORT drive.",
        "Copiez des images PNG ou JPEG sur le volume FEURISTIC-IMPORT.",
    ),
    "importer.eject": (
        "Eject the FEURISTIC-IMPORT drive on the computer.",
        "Éjectez le volume FEURISTIC-IMPORT sur l'ordinateur.",
    ),
    "importer.status.otp_ready": ("OTP account found", "Compte OTP trouvé"),
    "importer.status.frame_added": ("Backup QR {} of {} received", "QR de sauvegarde {} sur {} reçu"),
    "importer.status.backup_complete": ("Backup sequence complete", "Séquence de sauvegarde complète"),
    "importer.status.duplicate": ("Already received, ignored", "Déjà reçu, ignoré"),
    "importer.progress": ("{} of {} QR received", "{} QR reçus sur {}"),
    "importer.progress.sequences": (
        "Sequences: {} complete, {} incomplete",
        "Séquences : {} complètes, {} incomplètes",
    ),
    "importer.missing": ("Missing: {}", "Manquants : {}"),
    "importer.ready_restore": (
        "All QR received. Restore now?",
        "Tous les QR sont reçus. Restaurer maintenant ?",
    ),
    "importer.discard_incomplete": ("Discard incomplete sequence?", "Abandonner la séquence incomplète ?"),
    "importer.err.unsupported": ("Unsupported QR content", "Contenu QR non pris en charge"),
    "importer.err.empty": ("Empty QR code", "QR vide"),
    "importer.err.not_printable": (
        "Invalid characters in the OTP link",
        "Caractères invalides dans le lien OTP",
    ),
    "importer.err.otp_too_long": ("OTP link too long", "Lien OTP trop long"),
    "importer.err.frame_chars": (
        "Invalid backup QR characters",
        "Caractères invalides dans le QR de sauvegarde",
    ),
    "importer.err.frame_too_long": ("Backup QR too long", "QR de sauvegarde trop long"),
    "importer.err.too_large": ("QR content too large", "Contenu QR trop volumineux"),
    "importer.err.backup_version": (
        "Backup QR from an unsupported format version",
        "QR de sauvegarde d'une version de format non prise en charge",
    ),
    "importer.err.frame_invalid": ("Unreadable backup QR", "QR de sauvegarde illisible"),
    "importer.err.checksum": (
        "Damaged backup QR (checksum)",
        "QR de sauvegarde endommagé (somme de contrôle)",
    ),
    "importer.err.conflict": (
        "This QR contradicts one already received",
        "Ce QR contredit un QR déjà reçu",
    ),
    "importer.err.total": ("Inconsistent QR count", "Nombre de QR incohérent"),
    "importer.err.limit": ("Too much data for one import", "Trop de données pour un seul import"),
    "importer.err.mixed": (
        "Finish or cancel the current import first",
        "Terminez ou annulez d'abord l'import en cours",
    ),
    "importer.err.otp_pending": (
        "One OTP account per import. Confirm or cancel it first.",
        "Un compte OTP par import. Confirmez-le ou annulez-le d'abord.",
    ),
    "importer.err.finished": ("Import finished, eject the drive", "Import terminé, éjectez le volume"),
}


def register() -> None:
    i18n.register(STRINGS)
