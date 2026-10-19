# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""EN/FR strings of the device UI shell (menus, boot, settings)."""

from ..core import i18n

STRINGS = {
    # generic
    "ui.back": ("Back", "Retour"),
    "ui.more": ("More...", "Suite..."),
    "ui.confirm": ("Confirm", "Confirmer"),
    "ui.cancel": ("Cancel", "Annuler"),
    "ui.ok": ("OK", "OK"),
    "ui.yes": ("Yes", "Oui"),
    "ui.no": ("No", "Non"),
    "ui.continue": ("Continue", "Continuer"),
    "ui.hold_to_confirm": ("Hold to confirm", "Maintenir pour confirmer"),
    "ui.error": ("Error", "Erreur"),
    "ui.done": ("Done", "Terminé"),
    "ui.warning": ("Warning", "Attention"),
    "ui.fingerprint": ("Fingerprint", "Empreinte"),
    "ui.not_implemented": ("Not available yet", "Pas encore disponible"),
    "ui.empty": ("Nothing here yet", "Aucun élément"),
    "ui.storage_full": ("Storage is full", "Stockage plein"),
    "ui.qr_autohide": ("Hidden after 60 s", "Masqué après 60 s"),
    # boot / PIN
    "boot.welcome": ("Welcome to feuristic", "Bienvenue dans feuristic"),
    "boot.third_party": (
        "Third-party firmware, not made by Trezor.",
        "Firmware tiers, non produit par Trezor.",
    ),
    "boot.choose_language": ("Language", "Langue"),
    "boot.set_pin_intro": (
        "Choose a PIN to protect your keys.",
        "Choisissez un PIN pour protéger vos clés.",
    ),
    "pin.enter": ("Enter PIN", "Saisir le PIN"),
    "pin.new": ("New PIN", "Nouveau PIN"),
    "pin.repeat": ("Repeat PIN", "Répéter le PIN"),
    "pin.mismatch": ("PINs do not match", "Les PIN ne correspondent pas"),
    "pin.too_short": ("PIN must have 4 to 50 digits", "Le PIN doit avoir 4 à 50 chiffres"),
    "pin.wrong": ("Wrong PIN", "PIN incorrect"),
    "pin.backup_distinct": (
        "Backup phrase must differ from the device PIN",
        "La phrase de sauvegarde doit différer du PIN de l'appareil",
    ),
    "pin.attempts": ("{} attempts left", "{} essais restants"),
    "pin.last_attempt": ("Last attempt!", "Dernier essai !"),
    "pin.changed": ("PIN changed", "PIN modifié"),
    "pin.wiped": ("Too many wrong PINs. Device wiped.", "Trop d'essais. Appareil effacé."),
    "lock.locked": ("Locked", "Verrouillé"),
    # main menu
    "menu.home": ("feuristic", "feuristic"),
    "menu.auth": ("Authentication", "Authentification"),
    "menu.crypto": ("Cryptography", "Cryptographie"),
    "menu.backup": ("Backup", "Sauvegarde"),
    "menu.settings": ("Settings", "Réglages"),
    "menu.lock": ("Lock", "Verrouiller"),
    "menu.passkeys": ("Passkeys", "Passkeys"),
    "menu.otp": ("OTP", "OTP"),
    "menu.challenge": ("Challenge-response", "Challenge-response"),
    "menu.openpgp": ("OpenPGP", "OpenPGP"),
    "menu.piv": ("PIV", "PIV"),
    "menu.aes": ("AES", "AES"),
    "menu.rng": ("Randomness", "Aléa"),
    "menu.export_identity": ("Export an identity", "Exporter une identité"),
    "menu.export_full": ("Full export", "Export complet"),
    "menu.restore": ("Restore", "Restaurer"),
    "menu.pin": ("PIN / lock", "PIN / verrouillage"),
    "menu.time": ("TOTP time", "Heure TOTP"),
    "menu.usb": ("USB interfaces", "Interfaces USB"),
    "menu.language": ("Language", "Langue"),
    "menu.about": ("Hardware / version", "Matériel / version"),
    "menu.wipe": ("Wipe device", "Effacement intégral"),
    # settings
    "settings.change_pin": ("Change PIN", "Changer le PIN"),
    "settings.autolock": ("Auto-lock: 5 min", "Verrouillage : 5 min"),
    "settings.time_sync_usb": ("Sync over USB", "Synchroniser par USB"),
    "settings.time_status": ("Current time", "Heure actuelle"),
    "settings.time_unset": ("Time not synchronised", "Heure à synchroniser"),
    "settings.usb_normal": ("Normal: FIDO + smart card", "Normal : FIDO + carte à puce"),
    "settings.usb_info": (
        "Normal mode exposes FIDO HID and a CCID reader. Time sync and QR import use temporary modes.",
        "Le mode normal expose FIDO HID et un lecteur CCID. L'heure et l'import QR utilisent des modes temporaires.",
    ),
    "settings.wipe_title": ("Wipe device", "Effacer l'appareil"),
    "settings.wipe_text": (
        "All keys, passkeys, OTP accounts and settings will be erased permanently.",
        "Toutes les clés, passkeys, comptes OTP et réglages seront définitivement effacés.",
    ),
    "settings.wipe_again": ("Really wipe everything?", "Vraiment tout effacer ?"),
    "about.title": ("About", "À propos"),
    "about.version": ("Version", "Version"),
    "about.model": ("Model", "Modèle"),
    "about.storage": ("Storage", "Stockage"),
    "about.third_party": ("Third-party firmware", "Firmware tiers"),
    # USB temporary modes
    "usb.timesync_title": ("Time sync", "Synchro de l'heure"),
    "usb.timesync_wait": (
        "Send: TIME 1 <unix>\\n over the serial port.",
        "Envoyez : TIME 1 <unix>\\n sur le port série.",
    ),
    "usb.import_title": ("QR import", "Import QR"),
    "usb.import_wait": (
        "Copy PNG/JPEG images to the FEURISTIC volume.",
        "Copiez les images PNG/JPEG sur le volume FEURISTIC.",
    ),
    "usb.eject_now": ("Eject the volume on your computer.", "Éjectez le volume sur votre ordinateur."),
    "usb.restored": ("Normal USB mode restored", "Mode USB normal rétabli"),
    # QR import mode (fw/import_mode.py)
    "import.receiving": ("Receiving {}...", "Réception de {}..."),
    "import.err.stream": (
        "File not usable (code {}). Copy it again.",
        "Fichier inutilisable (code {}). Recopiez-le.",
    ),
    "import.err.image": ("Unsupported or damaged image ({}).", "Image non prise en charge ou abîmée ({})."),
    "import.err.no_qr": ("No QR code found in the image.{}", "Aucun QR code trouvé dans l'image.{}"),
    "import.err.multiple_qr": (
        "The image must contain exactly one QR code.{}",
        "L'image doit contenir un seul QR code.{}",
    ),
    "import.err.qr_damaged": (
        "QR code unreadable (damaged or blurred).{}",
        "QR code illisible (abîmé ou flou).{}",
    ),
    "import.err.truncated": ("Image truncated. Copy it again.{}", "Image tronquée. Recopiez-la.{}"),
    "import.err.memory": ("Not enough memory for the import.", "Mémoire insuffisante pour l'import."),
    "import.leave_now": ("Leave now", "Quitter"),
    "backup.restore.done": ("Restore finished", "Restauration terminée"),
    "backup.restore.summary": ("{} restored, {} skipped", "{} restaurée(s), {} ignorée(s)"),
}


def register() -> None:
    i18n.register(STRINGS)
