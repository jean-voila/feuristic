# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""English / French strings of the FIDO2 application (spec §9: FR/EN built in)."""

from ...core import i18n

STRINGS = {
    # application / menus (product spec §5, §9 "Passkeys")
    "fido2.app": ("Passkeys", "Passkeys"),
    "fido2.menu.services": ("Services", "Services"),
    "fido2.menu.accounts": ("Accounts", "Comptes"),
    "fido2.menu.info": ("Protection info", "Informations de protection"),
    "fido2.menu.delete": ("Delete passkey", "Supprimer la passkey"),
    "fido2.menu.pin": ("FIDO PIN", "PIN FIDO"),
    "fido2.menu.set_pin": ("Set FIDO PIN", "Définir le PIN FIDO"),
    "fido2.menu.change_pin": ("Change FIDO PIN", "Modifier le PIN FIDO"),
    "fido2.menu.wipe": ("Erase all passkeys", "Effacer toutes les passkeys"),
    "fido2.empty": ("No passkey stored", "Aucune passkey enregistrée"),
    "fido2.count": ("{} of {} passkeys", "{} passkeys sur {}"),
    "fido2.page": ("Page {}/{}", "Page {}/{}"),
    # prompt titles
    "fido2.title.register": ("Create passkey?", "Créer une passkey ?"),
    "fido2.title.sign_in": ("Sign in?", "Se connecter ?"),
    "fido2.title.choose_account": ("Choose account", "Choisir le compte"),
    "fido2.title.already_registered": ("Already registered", "Déjà enregistré"),
    "fido2.title.not_registered": ("Not registered", "Non enregistré"),
    "fido2.title.select": ("Use this key?", "Utiliser cette clé ?"),
    "fido2.title.reset": ("Reset FIDO2?", "Réinitialiser FIDO2 ?"),
    "fido2.title.u2f_register": ("Register (U2F)?", "Enregistrer (U2F) ?"),
    "fido2.title.u2f_sign_in": ("Sign in (U2F)?", "Se connecter (U2F) ?"),
    "fido2.title.delete": ("Delete passkey?", "Supprimer la passkey ?"),
    "fido2.title.wipe": ("Erase all FIDO data?", "Effacer toutes les données FIDO ?"),
    # prompt field labels
    "fido2.rp": ("Service", "Service"),
    "fido2.rp_name": ("Name", "Nom"),
    "fido2.user": ("Account", "Compte"),
    "fido2.accounts": ("Accounts", "Comptes"),
    "fido2.type": ("Type", "Type"),
    "fido2.type.passkey": ("Passkey (stored on device)", "Passkey (stockée sur l'appareil)"),
    "fido2.protection": ("Protection", "Protection"),
    "fido2.algorithm": ("Algorithm", "Algorithme"),
    "fido2.created": ("Created (#)", "Création (n°)"),
    "fido2.backup": ("Backup", "Sauvegarde"),
    "fido2.fingerprint": ("Fingerprint", "Empreinte"),
    "fido2.hmac_secret": ("hmac-secret", "hmac-secret"),
    "fido2.large_blob": ("largeBlob", "largeBlob"),
    "fido2.warning": ("Warning", "Attention"),
    # values
    "fido2.protect.1": ("Presence only", "Présence seule"),
    "fido2.protect.2": ("PIN unless ID known", "PIN sauf si identifiant connu"),
    "fido2.protect.3": ("PIN always required", "PIN toujours exigé"),
    "fido2.backup.eligible": ("Exportable, not yet backed up", "Exportable, pas encore sauvegardée"),
    "fido2.backup.done": ("Exportable, backed up", "Exportable, sauvegardée"),
    "fido2.yes": ("Yes", "Oui"),
    "fido2.no": ("No", "Non"),
    # warnings and results
    "fido2.wipe.warning": (
        "Every passkey, the FIDO PIN and largeBlob data will be erased. Accounts using them will be lost.",
        "Toutes les passkeys, le PIN FIDO et les données largeBlob seront effacés. Les comptes qui les "
        "utilisent seront perdus.",
    ),
    "fido2.delete.warning": (
        "The service will no longer accept this passkey.",
        "Le service n'acceptera plus cette passkey.",
    ),
    "fido2.pin.set": ("FIDO PIN set", "PIN FIDO défini"),
    "fido2.pin.changed": ("FIDO PIN changed", "PIN FIDO modifié"),
    "fido2.pin.wrong": ("Wrong PIN, {} attempts left", "PIN erroné, encore {} essais"),
    "fido2.pin.blocked": ("FIDO PIN blocked: reset FIDO2", "PIN FIDO bloqué : réinitialiser FIDO2"),
    "fido2.pin.policy": ("4 to 63 characters", "4 à 63 caractères"),
    "fido2.pin.status": ("PIN set, {} attempts left", "PIN défini, encore {} essais"),
    "fido2.pin.none": ("No FIDO PIN", "Aucun PIN FIDO"),
    "fido2.deleted": ("Passkey deleted", "Passkey supprimée"),
    "fido2.wiped": ("FIDO data erased", "Données FIDO effacées"),
    "fido2.backup.notice": (
        "Exported passkeys can be restored by anyone holding the QR images and the passphrase.",
        "Les passkeys exportées peuvent être restaurées par toute personne possédant les images QR "
        "et la phrase de sauvegarde.",
    ),
}


def register() -> None:
    i18n.register(STRINGS)
