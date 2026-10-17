# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Logic behind the on-device FIDO2 menus (product spec §5 and §9:
"Passkeys (utiliser / voir / supprimer / protections)", FIDO PIN, confirmed
global erase). Screens live in ``feuristic.ui``; this module only returns
data and performs confirmed actions.

* :func:`list_rps` / :func:`list_credentials` + :func:`paginate` — paginated
  list by service, then by account;
* :func:`credential_info` — protection level (credProtect), creation
  number, algorithm, hmac-secret/largeBlob, WebAuthn backup flags (BE/BS),
  public key fingerprint;
* :func:`delete_credential` — targeted deletion after a DANGER confirmation
  (largeBlob entries encrypted for that credential are purged too);
* :func:`wipe_all` — erase every FIDO2 credential, PIN and largeBlob data
  (same effect as authenticatorReset, without the 10 s power-up window
  because the request comes from the device itself) after a DANGER prompt;
* :func:`pin_status`, :func:`set_pin`, :func:`change_pin` — the FIDO
  clientPIN managed locally. CTAP has no "remove PIN" operation other than
  a reset; the menu mirrors that (use :func:`wipe_all`).
"""

from micropython import const

from ...core import i18n
from ...core.errors import NotFound
from ...core.interaction import DANGER, Prompt
from . import credentials as cr
from .largeblobs import entry_belongs_to

PAGE_SIZE = const(4)


def paginate(items: list, page: int, size: int = PAGE_SIZE) -> tuple:
    """Return ``(items_of_page, page_count)``; ``page`` is clamped."""
    pages = max(1, (len(items) + size - 1) // size)
    page = max(0, min(page, pages - 1))
    return items[page * size : (page + 1) * size], pages


def list_rps(auth) -> list:
    """``[(rpIdHash, rpId, count)]`` sorted by rpId."""
    return [(h, rp_id, n) for rp_id, h, n in auth.store.rps()]


def list_credentials(auth, rp_id_hash: bytes) -> list:
    """``[(uid, account label)]`` of one service, sorted by label."""
    out = [(c.uid, c.label()) for c in auth.store.for_rp(rp_id_hash)]
    out.sort(key=lambda t: t[1])
    return out


def _get(auth, uid: bytes):
    cred = auth.store.get(uid)
    if cred is None:
        raise NotFound("credential")
    return cred


def credential_info(auth, uid: bytes) -> dict:
    """Details shown by "Informations de protection"."""
    cred = _get(auth, uid)
    return {
        "rp_id": cred.rp_id,
        "user_name": cred.user_name,
        "display_name": cred.display_name,
        "cred_protect": cred.cred_protect,
        "protect_key": "fido2.protect." + str(cred.cred_protect),
        "created": cred.seq,
        "algorithm": "ES256" if cred.alg == cr.ALG_ES256 else "EdDSA",
        "hmac_secret": cred.hmac_secret,
        "large_blob": cred.large_blob,
        "backup_eligible": cred.backup_eligible,
        "backup_state": cred.backup_state,
        "backup_key": "fido2.backup.done" if cred.backup_state else "fido2.backup.eligible",
        "fingerprint": cred.fingerprint(),
    }


def info_fields(auth, uid: bytes) -> list:
    """``[(label_key, value)]`` ready for an information screen."""
    i = credential_info(auth, uid)
    return [
        ("fido2.rp", i["rp_id"]),
        ("fido2.user", i["user_name"] or i["display_name"] or "-"),
        ("fido2.protection", i18n.t(i["protect_key"])),
        ("fido2.algorithm", i["algorithm"]),
        ("fido2.created", str(i["created"])),
        ("fido2.backup", i18n.t(i["backup_key"])),
        ("fido2.fingerprint", i["fingerprint"]),
    ]


def _purge_large_blobs(auth, cred) -> None:
    key = cred.large_blob_key()
    if key is None:
        return
    entries = auth.large_blobs.entries()
    kept = [e for e in entries if not entry_belongs_to(e, key)]
    if len(kept) != len(entries):
        auth.large_blobs.write_entries(kept)


async def delete_credential(auth, ui, uid: bytes) -> bool:
    """Delete one discoverable credential after a DANGER confirmation."""
    cred = _get(auth, uid)
    ok = await ui.confirm(
        Prompt(
            "fido2.local.delete",
            "fido2.title.delete",
            (
                ("fido2.rp", cred.rp_id),
                ("fido2.user", cred.label()),
                ("fido2.warning", i18n.t("fido2.delete.warning")),
            ),
            DANGER,
            fingerprint=cred.fingerprint(),
        )
    )
    if not ok:
        return False
    auth.store.delete(cred.uid)
    _purge_large_blobs(auth, cred)
    return True


async def wipe_all(auth, ui) -> bool:
    """Erase all FIDO2 data after a DANGER confirmation."""
    ok = await ui.confirm(
        Prompt(
            "fido2.local.wipe",
            "fido2.title.wipe",
            (("fido2.warning", i18n.t("fido2.wipe.warning")), ("fido2.accounts", str(auth.store.count()))),
            DANGER,
        )
    )
    if not ok:
        return False
    auth.wipe()
    return True


def pin_status(auth) -> tuple:
    """``(pin_is_set, remaining_retries)``."""
    return auth.state.pin_is_set(), auth.state.pin_retries


def set_pin(auth, pin: str) -> None:
    """Set the FIDO PIN (raises PolicyDenied if one exists, InvalidInput on
    a PIN violating the rules: 4..63 bytes / ≥ 4 code points)."""
    auth.pin.local_set_pin(pin)


def change_pin(auth, old_pin: str, new_pin: str) -> None:
    """Change the FIDO PIN (PinInvalid(retries) / PinBlocked on failure)."""
    auth.pin.local_change_pin(old_pin, new_pin)
