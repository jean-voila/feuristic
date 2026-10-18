# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""On-device management of the PIV application (spec §9 "PIV (identités /
certificats / signatures / exporter QR)", §6.2 "clés générées et gérées sur
l'appareil", §10.10).

These functions back the device menus; they never talk to the host. The UI
glue collects values on the device (PIN entry, algorithm choice, ...) and
calls them; functions that destroy or replace keys take the injected ``ui``
and ask for a confirmation themselves (raising
:class:`~feuristic.core.errors.UserCancelled` on refusal).

PIN/PUK decision (documented in docs/protocols/piv.md §5): the PIV
application starts with the PIV factory defaults (PIN ``123456``, PUK
``12345678``, AES-192 administration key ``0102…08``×3) so that the device
is usable with standard tools even if the user skipped the PIV set-up step.
:func:`warnings` reports every default still in use; the PIV menu must show
them (``piv.warn.default_*``) until the user calls :func:`init_identity` /
:func:`set_pin` / :func:`set_puk` / :func:`generate_mgmt_key`. Values set
on the device are digits only (two-button entry); the host may set any
printable ASCII PIN through CHANGE REFERENCE DATA.
"""

from ....core.errors import InvalidInput, UserCancelled
from ....core.i18n import t
from ....core.interaction import DANGER, Prompt
from ....platform import crypto
from . import consts as pc
from . import storage, strings, x509
from .applet import generate_prompt, generate_slot_key, reset_prompt

strings.register()

PIN_POLICY_KEYS = {
    pc.PIN_POLICY_NEVER: "piv.pin_policy.never",
    pc.PIN_POLICY_ONCE: "piv.pin_policy.once",
    pc.PIN_POLICY_ALWAYS: "piv.pin_policy.always",
}


def _store(store):
    return storage.default() if store is None else store


class SlotStatus:
    """What the "PIV → identités" list shows for one slot."""

    def __init__(self, slot: int, data) -> None:
        self.slot = slot
        self.role_key = pc.SLOT_ROLE_KEYS[slot]
        self.has_key = data is not None and data.has_key
        self.has_cert = data is not None and data.cert is not None
        self.alg = data.alg if self.has_key else None
        self.alg_name = pc.ALG_NAME.get(self.alg, "")
        self.fingerprint = data.fingerprint() if self.has_key else ""
        self.pin_policy = data.pin_policy if data is not None else pc.DEFAULT_PIN_POLICY[slot]
        self.origin = data.origin if self.has_key else None
        if self.has_key and self.has_cert:
            self.status_key = "piv.slot.key_cert"
        elif self.has_key:
            self.status_key = "piv.slot.key_only"
        elif self.has_cert:
            self.status_key = "piv.slot.cert_only"
        else:
            self.status_key = "piv.slot.empty"

    def __repr__(self) -> str:
        return f"SlotStatus({self.slot:02X}, {self.status_key})"


def slots_status(store=None) -> list:
    s = _store(store)
    return [SlotStatus(slot, s.get_slot(slot)) for slot in pc.KEY_SLOTS]


def warnings(store=None) -> list:
    """i18n keys of the warnings the PIV menu must display."""
    s = _store(store)
    flags = s.creds().flags
    out = []
    if flags & storage.FLAG_PIN_DEFAULT:
        out.append("piv.warn.default_pin")
    if flags & storage.FLAG_PUK_DEFAULT:
        out.append("piv.warn.default_puk")
    if flags & storage.FLAG_MGMT_DEFAULT:
        out.append("piv.warn.default_mgmt")
    if s.is_blocked(pc.REF_PIN):
        out.append("piv.warn.pin_blocked")
    if s.is_blocked(pc.REF_PUK):
        out.append("piv.warn.puk_blocked")
    return out


def _check_slot(slot: int) -> None:
    if slot not in pc.KEY_SLOTS:
        raise InvalidInput("PIV slot")


async def generate(slot: int, alg: int, ui, store=None, keepalive=None, progress=None) -> SlotStatus:
    """Confirm, then generate a new key for ``slot`` (replaces key and certificate)."""
    _check_slot(slot)
    if alg not in pc.ASYM_ALGS:
        raise InvalidInput("PIV algorithm")
    s = _store(store)
    existing = s.get_slot(slot)
    if not await ui.confirm(generate_prompt(slot, alg, existing)):
        raise UserCancelled
    policy = existing.pin_policy if existing is not None else pc.DEFAULT_PIN_POLICY[slot]
    new = await generate_slot_key(slot, alg, policy, keepalive, progress)
    s.put_slot(new)
    return SlotStatus(slot, new)


def delete_prompt(slot: int) -> Prompt:
    fields = [
        ("piv.field.slot", f"{t(pc.SLOT_ROLE_KEYS[slot])} ({slot:02X})"),
        ("piv.field.warning", t("piv.warn.delete")),
    ]
    p = Prompt("piv.delete", "piv.prompt.delete", fields, DANGER)
    p.slot = slot
    return p


async def delete_slot(slot: int, ui, store=None) -> bool:
    """Confirm, then delete the key and certificate of ``slot``. False if empty."""
    _check_slot(slot)
    s = _store(store)
    if s.get_slot(slot) is None:
        return False
    if not await ui.confirm(delete_prompt(slot)):
        raise UserCancelled
    return s.delete_slot(slot)


def certificate(slot: int, store=None):
    """``(der, certinfo)`` of ``slot`` or ``None``."""
    _check_slot(slot)
    d = _store(store).get_slot(slot)
    if d is None or d.cert is None:
        return None
    return d.cert, d.certinfo


def cert_summary(slot: int, store=None):
    """``(summary, status_key)`` for the "PIV → certificats" screen.

    ``summary`` is a :class:`~feuristic.apps.card.piv.x509.CertSummary` or
    ``None``; ``status_key`` is ``None`` on success, otherwise one of
    ``piv.no_cert``, ``piv.cert.compressed``, ``piv.cert.unreadable``.
    """
    c = certificate(slot, store)
    if c is None:
        return None, "piv.no_cert"
    der, info = c
    if info != 0:
        return None, "piv.cert.compressed"
    try:
        return x509.summarize(der), None
    except InvalidInput:
        return None, "piv.cert.unreadable"


def cert_fields(summary) -> list:
    """Display fields (label key, value) of a certificate summary."""
    return [
        ("piv.field.subject", summary.subject_cn),
        ("piv.field.issuer", summary.issuer_cn),
        ("piv.field.valid_from", summary.not_before),
        ("piv.field.valid_to", summary.not_after),
        ("piv.field.serial", summary.serial_hex),
        ("piv.field.fingerprint", summary.sha256_hex),
    ]


# -- credentials ---------------------------------------------------------------


def _device_pin(value, min_len: int = storage.PIN_MIN) -> bytes:
    if isinstance(value, str):
        value = value.encode()
    value = bytes(value)
    if not min_len <= len(value) <= storage.PIN_LEN:
        raise InvalidInput("PIN length")
    for b in value:
        if not 0x30 <= b <= 0x39:
            raise InvalidInput("PIN digits")
    return storage.pad_pin(value)


def set_pin(pin, store=None) -> None:
    """Set the PIV PIN (6–8 digits) and clear its retry counter."""
    _store(store).set_secret(pc.REF_PIN, _device_pin(pin))


def set_puk(puk, store=None) -> None:
    """Set the PIV PUK (6–8 digits; 8 recommended) and clear its retry counter."""
    _store(store).set_secret(pc.REF_PUK, _device_pin(puk))


def init_identity(pin, puk, store=None) -> None:
    """PIV set-up step: replace the default PIN and PUK (spec §6.1/§9)."""
    if pin == puk:
        raise InvalidInput("PIN and PUK must differ")
    set_pin(pin, store)
    set_puk(puk, store)


def generate_mgmt_key(alg: int = pc.ALG_AES192, store=None) -> bytes:
    """Store a fresh random administration key and return it for on-screen display.

    The glue shows it (hex / QR) so the user can configure host tools
    (``yubico-piv-tool -k``, ``piv-tool -A``); it is never sent over USB.
    """
    n = pc.MGMT_ALGS.get(alg)
    if n is None:
        raise InvalidInput("management key algorithm")
    key = crypto.random_bytes(n)
    _store(store).set_mgmt_key(alg, key)
    return key


def reset_mgmt_key_default(store=None) -> None:
    _store(store).set_mgmt_key(pc.DEFAULT_MGMT_ALG, pc.DEFAULT_MGMT_KEY)


def mgmt_key_info(store=None) -> tuple:
    """``(algorithm name, is_default)`` of the administration key."""
    c = _store(store).creds()
    return pc.MGMT_ALG_NAME[c.mgmt_alg], bool(c.flags & storage.FLAG_MGMT_DEFAULT)


def retries(store=None) -> dict:
    """``{"pin": (remaining, max), "puk": (remaining, max)}``."""
    s = _store(store)
    return {
        "pin": (s.retries_remaining(pc.REF_PIN), s.max_retries(pc.REF_PIN)),
        "puk": (s.retries_remaining(pc.REF_PUK), s.max_retries(pc.REF_PUK)),
    }


def set_pin_policy(slot: int, policy: int, store=None) -> None:
    """Make the PIN policy of a slot stricter (never weaker than the product default)."""
    _check_slot(slot)
    if policy not in PIN_POLICY_KEYS or policy < pc.DEFAULT_PIN_POLICY[slot]:
        raise InvalidInput("PIN policy")
    s = _store(store)
    d = s.get_slot(slot)
    if d is None or not d.has_key:
        raise InvalidInput("empty slot")
    d.pin_policy = policy
    s.put_slot(d)


async def reset(ui, store=None) -> None:
    """Confirm, then erase all PIV keys, certificates, objects and credentials."""
    if not await ui.confirm(reset_prompt()):
        raise UserCancelled
    _store(store).wipe()
