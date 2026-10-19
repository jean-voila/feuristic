# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""EN/FR strings for local cryptographic application management."""

from ..core import i18n

STRINGS = {
    "manage.info": ("Information", "Informations"),
    "manage.changed": ("Settings saved", "Paramètres enregistrés"),
    "manage.deleted": ("Deleted", "Supprimé"),
    "manage.invalid": ("Invalid value", "Valeur invalide"),
    "manage.missing": ("This identity is no longer available", "Cette identité n'est plus disponible"),
    "manage.denied": ("Operation not permitted in this state", "Opération interdite dans cet état"),
    "manage.memory": ("Not enough memory for this operation", "Mémoire insuffisante pour cette opération"),
    "manage.pin_length": ("Use {} to {} digits", "Utilisez de {} à {} chiffres"),
    "manage.pin_repeat": ("Repeat", "Répéter"),
    "manage.unblock": ("Restore PIN attempts", "Rétablir les essais du PIN"),
    "manage.remove_rc": ("Remove resetting code", "Retirer le code de réinitialisation"),
    "manage.new_value": ("Set new value", "Définir une nouvelle valeur"),
    "manage.status": ("Status", "État"),
    "manage.empty": ("Empty", "Vide"),
    "manage.present": ("Present", "Présent"),
    "manage.policy": ("PIN policy", "Politique du PIN"),
    "manage.new_pin": ("New FIDO PIN", "Nouveau PIN FIDO"),
    "manage.old_pin": ("Current FIDO PIN", "PIN FIDO actuel"),
    "manage.repeat_fido": ("Repeat FIDO PIN", "Répéter le PIN FIDO"),
    "manage.fido_pin_length": ("Use {} to 63 characters", "Utilisez de {} à 63 caractères"),
    "manage.challenge_info": (
        "Use WebAuthn hmac-secret or PIV GENERAL AUTHENTICATE from a standard client. "
        "Every request shows the service or key and asks for approval on this device.",
        "Utilisez WebAuthn hmac-secret ou PIV GENERAL AUTHENTICATE depuis un client standard. "
        "Chaque demande affiche le service ou la clé et demande votre accord sur cet appareil.",
    ),
    "manage.pgp.generate": ("Generate all three keys?", "Générer les trois clés ?"),
    "manage.pgp.replace": (
        "Existing signing, decryption and authentication keys will be destroyed.",
        "Les clés existantes de signature, déchiffrement et authentification seront détruites.",
    ),
    "manage.pgp.generated": ("OpenPGP keys generated", "Clés OpenPGP générées"),
    "manage.pgp.delete": ("Delete OpenPGP keys?", "Supprimer les clés OpenPGP ?"),
    "manage.all_keys": ("All keys", "Toutes les clés"),
    "manage.pgp.reset": (
        "Erase all OpenPGP keys and data; restore PIN 123456 and admin PIN 12345678.",
        "Effacer les clés et données OpenPGP ; rétablir le PIN 123456 et le PIN admin 12345678.",
    ),
    "manage.pgp.pin_info": (
        "PW1: {} attempts; PW3: {}; resetting code: {}",
        "PW1 : {} essais ; PW3 : {} ; code de réinitialisation : {}",
    ),
    "manage.pgp.defaults": (
        "Initial PIN: 123456; admin PIN: 12345678. Change both before using the card.",
        "PIN initial : 123456 ; PIN admin : 12345678. Modifiez-les avant utilisation.",
    ),
    "manage.piv.info": (
        "Generate a key here, then load its public X.509 certificate using a standard PIV client. "
        "Signing and challenge-response use GENERAL AUTHENTICATE over CCID/PC-SC.",
        "Générez une clé ici, puis chargez son certificat X.509 public avec un client PIV standard. "
        "La signature et le challenge-response utilisent GENERAL AUTHENTICATE via CCID/PC-SC.",
    ),
    "manage.piv.retries": ("PIN: {}/{} attempts; PUK: {}/{}", "PIN : {}/{} essais ; PUK : {}/{}"),
    "manage.piv.mgmt_warning": (
        "The previous administration key stops working. "
        "Save the new key privately to configure PIV host tools.",
        "L'ancienne clé d'administration sera invalidée. "
        "Conservez la nouvelle clé pour configurer les outils PIV.",
    ),
    "manage.piv.default_warning": (
        "The public factory administration key will allow the host to administer this application.",
        "La clé d'administration publique d'usine permettra à l'hôte d'administrer cette application.",
    ),
    "manage.piv.default": ("Factory key", "Clé d'usine"),
    "manage.piv.custom": ("Custom key", "Clé personnalisée"),
    "manage.aes.name": ("Key name (1-16 ASCII)", "Nom de clé (1-16 ASCII)"),
    "manage.aes.id": ("Key identifier", "Identifiant de clé"),
    "manage.aes.state": ("Activation", "Activation"),
    "manage.rng.test_ok": ("Random generator self-test passed", "Autotest du générateur réussi"),
}


def register() -> None:
    i18n.register(STRINGS)
