# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Device-menu functions of the OpenPGP card (spec §6.1 "génération de clés
et gestion du PIN localement", §9 "OpenPGP (générer / voir / supprimer /
exporter QR)").

These functions are called by the on-device UI **after** it has shown its own
confirmation screens (the user is physically operating the device). They
never talk to the host. Export to QR is done by the backup application
through :class:`.provider.OpenPgpBackupProvider`.

Fingerprints of locally generated keys are computed exactly as GnuPG
computes them for card keys (OpenPGP v4, Curve25519 ECDH with KDF
parameters SHA-256/AES-128), so that ``gpg --card-status`` and
``gpg --full-generate-key`` → *Existing key from card* (which reuses the
card's key creation time, DO ``CD``) show matching fingerprints.
"""

from micropython import const

from ....core.errors import InvalidInput, PolicyDenied
from . import const as pgp
from . import keys as alg
from .storage import ZERO20, Identity, PinRef, check_pin_length

PROFILE_25519 = "ed25519"
PROFILE_RSA2048 = "rsa2048"

#: earliest acceptable key creation time (2024-01-01); the device has no RTC
MIN_CREATED = const(1_704_067_200)


def profiles() -> list:
    """Available algorithm profiles: ``[(id, i18n_key), ...]``."""
    out = [(PROFILE_25519, "openpgp.profile.ed25519")]
    if alg.rsa_available():
        out.append((PROFILE_RSA2048, "openpgp.profile.rsa2048"))
    return out


def _profile_kinds(profile: str) -> tuple:
    if profile == PROFILE_25519:
        return (pgp.KIND_ED25519, pgp.KIND_X25519, pgp.KIND_ED25519)
    if profile == PROFILE_RSA2048 and alg.rsa_available():
        return (pgp.KIND_RSA2048, pgp.KIND_RSA2048, pgp.KIND_RSA2048)
    raise InvalidInput("unknown profile")


def status(store) -> dict:
    """Snapshot for the menus (no secrets)."""
    ident = store.ident
    keys = []
    for role in pgp.ROLES:
        slot = ident.keys[role]
        keys.append(
            {
                "role": pgp.ROLE_NAMES[role],
                "algorithm": alg.display_name(slot.kind),
                "present": slot.present,
                "origin": slot.origin,
                "fingerprint": alg.format_fingerprint(slot.fpr) if slot.fpr != ZERO20 else "",
                "created": slot.date,
            }
        )
    return {
        "terminated": ident.terminated,
        "keys": keys,
        "pw1_retries": store.remaining(pgp.PW1),
        "pw3_retries": store.remaining(pgp.PW3),
        "rc_retries": store.remaining(pgp.RC),
        "rc_set": ident.pins[pgp.RC] is not None,
        "signatures": store.signature_count() if not ident.terminated else 0,
        "name": ident.name,
    }


async def generate_keys(store, profile: str, created: int, yield_fn=None, progress=None) -> list:
    """Generate the three keys locally; return their fingerprints.

    ``created`` is the UNIX creation time (the session clock; the menu must
    ask for a time synchronisation first, i18n ``openpgp.time_required``).
    All three keys are written in one atomic record update.
    """
    if not isinstance(created, int) or isinstance(created, bool) or not MIN_CREATED <= created <= 0xFFFFFFFF:
        raise InvalidInput("creation time")
    kinds = _profile_kinds(profile)
    ident = store.ident
    if ident.terminated:
        raise PolicyDenied("terminated")
    secrets = []
    for kind in kinds:
        secrets.append(await alg.generate(kind, yield_fn, progress))
    fprs = []
    for role in pgp.ROLES:
        slot = ident.keys[role]
        slot.attr = alg.canonical_attr(kinds[role])
        slot.set_secret(secrets[role], pgp.ORIGIN_GENERATED)
        slot.date = created
        slot.fpr = alg.v4_fingerprint(kinds[role], slot.public(), created)
        fprs.append(slot.fpr)
    store.reset_signature_count()
    store.save()
    store.epoch += 1
    return fprs


def delete_keys(store, roles=pgp.ROLES) -> None:
    """Delete the given key slots (fingerprints and dates included)."""
    ident = store.ident
    for role in roles:
        ident.keys[role].clear()
        if role == pgp.SIG:
            store.reset_signature_count()
    store.save()
    store.epoch += 1


def public_key(store, role: int) -> bytes:
    """Raw public key (32 bytes, or the RSA modulus) of ``role``."""
    slot = store.ident.keys[role]
    if not slot.present:
        raise InvalidInput("no key")
    return slot.public()


def set_pin(store, which: int, pin) -> None:
    """Set PW1, PW3 or the resetting code to ``pin`` (entered on the device)
    and restore its try counter. ``pin=b""`` removes the resetting code."""
    pin = bytes(pin)
    ident = store.ident
    if ident.terminated:
        raise PolicyDenied("terminated")
    if which == pgp.RC and not pin:
        ident.pins[pgp.RC] = None
        store.save()
        store.epoch += 1
        return
    if which not in (pgp.PW1, pgp.PW3, pgp.RC):
        raise InvalidInput("pin reference")
    check_pin_length(which, pin)
    ident.pins[which] = PinRef.create(pin)
    store.save()
    store.tries[which].clear()
    store.epoch += 1


def unblock(store, which: int) -> None:
    """Restore the try counter of a PIN without changing it (device menu,
    after the device PIN was entered)."""
    if which not in (pgp.PW1, pgp.PW3, pgp.RC):
        raise InvalidInput("pin reference")
    store.tries[which].clear()
    store.epoch += 1


def factory_reset(store) -> None:
    """Erase every key and data object; default PINs (123456 / 12345678)."""
    store.activate()


def identity_snapshot_is_default(ident: Identity) -> bool:
    return not ident.has_keys() and not ident.has_aux() and not ident.name
