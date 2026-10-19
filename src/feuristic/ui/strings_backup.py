# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Local backup controls, in English and French."""

from ..core import i18n

STRINGS = {
    "import.ui.wrong_purpose": (
        "Use OTP import for OTP links, and Restore for backup images.",
        "Utilisez l'ajout OTP pour les liens OTP, et Restaurer pour les images de sauvegarde.",
    ),
    "import.ui.ready": (
        "Copies paused. Confirm this identity on the device before copying the next one.",
        "Copies suspendues. Confirmez cette identité sur l'appareil avant de copier la suivante.",
    ),
    "import.ui.instructions": (
        "Copy all QR images of ONE identity to FEURISTIC-IMPORT, then confirm on the device.",
        "Copiez tous les QR d'UNE identité sur FEURISTIC-IMPORT, puis confirmez sur l'appareil.",
    ),
    "import.ui.copy_paused": (
        "Copy refused while waiting for the device. Retry failed copies after resuming.",
        "Copie refusée pendant l'attente de l'appareil. Recommencez les copies après la reprise.",
    ),
    "import.ui.retry_copy": (
        "A copy was refused during confirmation. After resuming, copy those images again.",
        "Une copie a été refusée pendant la confirmation. À la reprise, recopiez ces images.",
    ),
    "import.ui.restored": (
        "{} identities restored. Copy another, or choose Done.",
        "{} identités restaurées. Copiez la suivante ou choisissez Terminé.",
    ),
    "import.ui.incomplete": (
        "Some QR or identities are missing. Earlier restored identities remain restored. Leave now?",
        "Des QR ou identités manquent. Les identités déjà restaurées restent restaurées. Quitter ?",
    ),
    "backup.ui.choose_type": ("Choose identity type", "Choisir le type d'identité"),
    "backup.ui.profile": ("QR readability", "Lisibilité QR"),
    "backup.ui.passphrase": (
        "Use 12 to 128 printable ASCII characters. Keep this phrase separate from your PIN.",
        "Utilisez 12 à 128 caractères ASCII imprimables. Gardez cette phrase à part du PIN.",
    ),
    "backup.ui.controls": (
        "Photograph every QR. Left: previous. Right: next. "
        "Both: finish this identity after viewing all QR. Hold left: cancel. Hidden after 60 s.",
        "Photographiez tous les QR. Gauche : précédent. Droite : suivant. "
        "Deux boutons : finir cette identité après avoir vu tous les QR. "
        "Gauche longue : annuler. Masqué après 60 s.",
    ),
    "backup.ui.frames": ("{} QR images", "{} images QR"),
    "backup.ui.incomplete": ("View every QR before finishing", "Voir tous les QR avant de terminer"),
    "backup.ui.closed": ("QR hidden", "QR masqué"),
    "backup.ui.done": ("Export finished", "Export terminé"),
    "backup.ui.cancelled": ("Export stopped", "Export interrompu"),
    "backup.ui.progress": ("Deriving backup key", "Dérivation de la clé de sauvegarde"),
    "backup.ui.unavailable": ("Identity no longer available", "Identité indisponible"),
    "backup.ui.failed": ("Could not create backup", "Impossible de créer la sauvegarde"),
    "backup.ui.otp_long": (
        "This OTP needs several QR images. An encrypted backup and a separate passphrase will be used.",
        "Cet OTP nécessite plusieurs images QR. "
        "Une sauvegarde chiffrée avec une phrase distincte sera utilisée.",
    ),
}


def register() -> None:
    i18n.register(STRINGS)
