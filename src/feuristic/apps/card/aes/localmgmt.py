# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""On-device management of AES keys and RNG information (spec §7 "créer,
nommer, désactiver et supprimer les clés AES", §9 "AES (clés / paramètres /
supprimer / exporter QR)", "Aléa (RNG : état / informations)").

The UI glue collects names / choices on the device and calls these
functions. Destructive ones confirm through the injected ``ui`` and raise
:class:`~feuristic.core.errors.UserCancelled` on refusal. No key material is
ever returned (export goes through the backup provider and QR display).
"""

from ....core.errors import NotFound, UserCancelled
from ....core.i18n import t
from ....core.interaction import DANGER, Prompt
from . import keys as _keys
from . import rng as _rng
from . import strings

strings.register()

POLICY_KEYS = {_keys.POLICY_EVERY: "aes.policy.every", _keys.POLICY_SESSION: "aes.policy.session"}
RNG_STATE_KEYS = {
    _rng.STATE_UNTESTED: "rng.state.untested",
    _rng.STATE_OK: "rng.state.ok",
    _rng.STATE_FAILED: "rng.state.failed",
}


def _store(store):
    return _keys.default() if store is None else store


class KeyInfo:
    def __init__(self, k) -> None:
        self.kid = k.kid
        self.name = k.name
        self.enabled = k.enabled
        self.policy = k.policy
        self.policy_key = POLICY_KEYS[k.policy]
        self.fingerprint = k.fingerprint()

    def __repr__(self) -> str:
        return f"KeyInfo(#{self.kid} {self.name!r})"


def list_keys(store=None) -> list:
    return [KeyInfo(k) for k in _store(store).entries()]


def key_info(kid: int, store=None) -> KeyInfo:
    k = _store(store).get(_keys.check_kid(kid))
    if k is None:
        raise NotFound
    return KeyInfo(k)


def free_ids(store=None) -> list:
    return _store(store).free_ids()


def create_key(name: str, policy: int = _keys.POLICY_EVERY, kid=None, store=None, rng=None) -> KeyInfo:
    """Generate a new key on the device (health-checked strong RNG).

    Raises ``InvalidInput`` (name/id), ``StorageFull`` (16 keys) or
    :class:`~feuristic.apps.card.aes.rng.RngHealthError` (glue: ``rng.error``).
    """
    if rng is None:
        rng = _rng.default().health.random_bytes
    return KeyInfo(_store(store).create(name, policy, kid, rng))


def rename_key(kid: int, name: str, store=None) -> None:
    _store(store).rename(kid, name)


def set_enabled(kid: int, enabled: bool, store=None) -> None:
    _store(store).set_enabled(kid, enabled)


def set_policy(kid: int, policy: int, store=None) -> None:
    _store(store).set_policy(kid, policy)


def delete_prompt(info: KeyInfo) -> Prompt:
    fields = [
        ("aes.field.key", f"#{info.kid} {info.name}"),
        ("aes.field.fingerprint", info.fingerprint),
        ("aes.field.warning", t("aes.warn.delete")),
    ]
    return Prompt("aes.delete", "aes.prompt.delete", fields, DANGER)


async def delete_key(kid: int, ui, store=None) -> bool:
    s = _store(store)
    k = s.get(_keys.check_kid(kid))
    if k is None:
        return False
    if not await ui.confirm(delete_prompt(KeyInfo(k))):
        raise UserCancelled
    return s.delete(kid)


async def delete_all(ui, store=None) -> None:
    p = Prompt("aes.wipe", "aes.prompt.wipe", [("aes.field.warning", t("aes.warn.wipe"))], DANGER)
    if not await ui.confirm(p):
        raise UserCancelled
    _store(store).wipe()


# -- RNG screen -------------------------------------------------------------------


def rng_status(service=None) -> dict:
    """Status dict (see :meth:`RngService.status`) plus ``state_key`` (i18n)."""
    svc = _rng.default() if service is None else service
    st = svc.status()
    st["state_key"] = RNG_STATE_KEYS[st["state"]]
    return st


def rng_fields(service=None) -> list:
    """Display fields for "Aléa → état / informations"."""
    st = rng_status(service)
    fields = [
        ("rng.status", t(st["state_key"])),
        ("rng.field.source", t("rng.source")),
        ("rng.field.tested", str(st["bytes_tested"])),
        ("rng.field.delivered", str(st["bytes_delivered"])),
        ("rng.field.requests", str(st["requests"])),
        ("rng.field.rct", str(st["rct_failures"])),
        ("rng.field.apt", str(st["apt_failures"])),
        ("rng.field.rate_limited", str(st["rate_limited"])),
    ]
    if st["last_failure"] is not None:
        fields.append(("rng.field.last_failure", st["last_failure"].upper()))
    return fields


def rng_retest(service=None) -> bool:
    """Run a new start-up test; clears a latched failure if it passes."""
    svc = _rng.default() if service is None else service
    return svc.health.retest()
