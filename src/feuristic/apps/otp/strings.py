# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""English / French strings of the OTP application (spec §9: FR/EN built in)."""

STRINGS = {
    # menu and status
    "otp.title": ("One-time passwords", "Codes à usage unique"),
    "otp.empty": ("No account yet", "Aucun compte pour l'instant"),
    "otp.view_code": ("View code", "Voir le code"),
    "otp.add_qr_usb": ("Add QR over USB", "Ajouter un QR par USB"),
    "otp.export_qr": ("Back up as QR", "Sauvegarder en QR"),
    "otp.delete": ("Delete", "Supprimer"),
    "otp.rename": ("Rename", "Renommer"),
    "otp.time_not_set": ("Time to synchronise", "Heure à synchroniser"),
    "otp.time_not_set.hint": (
        "Settings > TOTP time > Sync over USB",
        "Réglages > Heure TOTP > Synchroniser par USB",
    ),
    "otp.remaining": ("{} s left", "Encore {} s"),
    "otp.next_counter": ("Next counter: {}", "Prochain compteur : {}"),
    # prompt field labels
    "otp.field.issuer": ("Service", "Service"),
    "otp.field.account": ("Account", "Compte"),
    "otp.field.type": ("Type", "Type"),
    "otp.field.algorithm": ("Algorithm", "Algorithme"),
    "otp.field.digits": ("Digits", "Chiffres"),
    "otp.field.period": ("Period", "Période"),
    "otp.field.counter": ("Counter", "Compteur"),
    "otp.field.warning": ("Warning", "Attention"),
    "otp.field.fingerprint": ("Fingerprint", "Empreinte"),
    "otp.unit.seconds": ("{} s", "{} s"),
    # import / replace
    "otp.import.title": ("Add this account?", "Ajouter ce compte ?"),
    "otp.import.weak_secret": (
        "Weak secret (under 80 bits). The service may be insecure.",
        "Secret faible (moins de 80 bits). Le service est peut-être peu sûr.",
    ),
    "otp.import.added": ("Account added", "Compte ajouté"),
    "otp.import.exists": ("This account already exists", "Ce compte existe déjà"),
    "otp.import.invalid": ("Invalid otpauth QR code", "QR code otpauth invalide"),
    "otp.replace.title": ("Replace the account?", "Remplacer le compte ?"),
    "otp.replace.warning": (
        "A different secret is stored for this account. It will be erased.",
        "Un autre secret est enregistré pour ce compte. Il sera effacé.",
    ),
    "otp.full": ("Storage full (32 accounts maximum)", "Mémoire pleine (32 comptes maximum)"),
    # HOTP
    "otp.hotp_generate.title": ("Generate an HOTP code?", "Générer un code HOTP ?"),
    "otp.hotp_generate.warning": (
        "The counter advances even if the code is not used.",
        "Le compteur avance même si le code n'est pas utilisé.",
    ),
    "otp.hotp.exhausted": ("HOTP counter exhausted", "Compteur HOTP épuisé"),
    # delete / rename
    "otp.delete.title": ("Delete the account?", "Supprimer le compte ?"),
    "otp.delete.warning": (
        "Its codes can no longer be generated on this device.",
        "Ses codes ne pourront plus être générés sur cet appareil.",
    ),
    "otp.deleted": ("Account deleted", "Compte supprimé"),
    "otp.renamed": ("Account renamed", "Compte renommé"),
    # export (spec §8.1)
    "otp.export.title": ("Show the secret as QR?", "Afficher le secret en QR ?"),
    "otp.export.warning": (
        "Anyone who photographs this QR code can reproduce your codes.",
        "Toute personne photographiant ce QR peut reproduire les codes.",
    ),
    "otp.export.autohide": ("Hidden automatically after 60 s", "Masqué automatiquement après 60 s"),
}


def register() -> None:
    """Register the OTP strings in :mod:`feuristic.core.i18n` (idempotent)."""
    from ...core import i18n

    i18n.register(STRINGS)
