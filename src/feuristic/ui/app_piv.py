# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Local PIV identities, certificate inspection and credentials."""

from trezor import loop

from ..apps.card.piv import consts as pc
from ..apps.card.piv import localmgmt as mgmt
from ..core.i18n import t
from ..core.secure import wipe
from . import management, screens
from .interaction import InlineInteraction


async def _yield() -> None:
    await loop.sleep(0)


def _slot_label(status):
    return f"{status.slot:02X} {t(status.role_key)}"


def _status(slot):
    return next(s for s in mgmt.slots_status() if s.slot == slot)


async def _slot_info(slot) -> None:
    st = _status(slot)
    await management.info(
        _slot_label(st),
        [
            ("piv.field.slot", f"{slot:02X}"),
            ("manage.status", t(st.status_key)),
            ("piv.field.algorithm", st.alg_name or "-"),
            ("piv.field.fingerprint", st.fingerprint or "-"),
            ("piv.field.pin_policy", t(mgmt.PIN_POLICY_KEYS[st.pin_policy])),
        ],
    )


async def _certificate(slot) -> None:
    summary, error = mgmt.cert_summary(slot)
    if error:
        await screens.show_info(t("piv.certificates"), t(error), close_others=False)
        return
    await management.info(t("piv.certificates"), mgmt.cert_fields(summary))


async def _generate(slot) -> None:
    from ..fw import pin

    algorithms = pc.ASYM_ALGS
    choice = await screens.menu(
        t("piv.generate"),
        [pc.ALG_NAME[a] for a in algorithms],
        close_others=False,
    )
    if choice is None or not await pin.reauthenticate():
        return

    # localmgmt asks the DANGER replacement confirmation before generation.
    # Start progress only after confirmation so it cannot obscure the dialog.
    class GenerationUI(InlineInteraction):
        async def confirm(self, prompt):
            approved = await super().confirm(prompt)
            if approved:
                progress.append(screens.Progress(t("piv.generate")))
            return approved

    progress = []
    try:
        await mgmt.generate(
            slot,
            algorithms[choice],
            GenerationUI(),
            keepalive=_yield,
            progress=lambda value: progress[0].report(value) if progress else None,
        )
    finally:
        for item in progress:
            item.stop()
    await management.done()
    await _slot_info(slot)


async def _set_policy(slot) -> None:
    from ..fw import pin

    st = _status(slot)
    if not st.has_key:
        await screens.show_info(t("piv.slot.empty"), close_others=False)
        return
    policies = [p for p in mgmt.PIN_POLICY_KEYS if p >= pc.DEFAULT_PIN_POLICY[slot]]
    choice = await screens.menu(
        t("manage.policy"),
        [t(mgmt.PIN_POLICY_KEYS[p]) for p in policies],
        policies.index(st.pin_policy),
        close_others=False,
    )
    if choice is None or not await pin.reauthenticate():
        return
    if not await management.confirm("manage.policy", mgmt.PIN_POLICY_KEYS[policies[choice]]):
        return
    mgmt.set_pin_policy(slot, policies[choice])
    await management.done()


async def _delete(slot):
    from ..fw import pin

    if await pin.reauthenticate() and await mgmt.delete_slot(slot, InlineInteraction()):
        await management.done("manage.deleted")
        return True
    return False


async def _slot_menu(slot) -> None:
    cur = 0
    while True:
        st = _status(slot)
        cur = await screens.menu(
            _slot_label(st),
            [
                t("manage.info"),
                t("piv.generate"),
                t("piv.certificates"),
                t("manage.policy"),
                t("piv.export_qr"),
                t("piv.delete"),
            ],
            cur,
            close_others=False,
        )
        if cur is None:
            return
        if cur == 0:
            await _slot_info(slot)
        elif cur == 1:
            await management.run(_generate(slot))
        elif cur == 2:
            await _certificate(slot)
        elif cur == 3:
            await management.run(_set_policy(slot))
        elif cur == 4:
            from ..apps.card.piv.storage import slot_uid
            from . import app_backup

            await app_backup.export_record("piv", slot_uid(slot))
        elif await management.run(_delete(slot)):
            return


async def _slots(certificates=False) -> None:
    cur = 0
    while True:
        slots = mgmt.slots_status()
        cur = await screens.menu(
            t("piv.certificates" if certificates else "piv.identities"),
            [_slot_label(st) for st in slots],
            cur,
            close_others=False,
        )
        if cur is None:
            return
        await management.run((_certificate if certificates else _slot_menu)(slots[cur].slot))


async def _set_pin(puk=False) -> None:
    from ..fw import pin

    title = "piv.set_puk" if puk else "piv.set_pin"
    if not await pin.reauthenticate():
        return
    value = await management.new_pin(title, 6, 8)
    if value is None:
        return
    try:
        if puk:
            mgmt.set_puk(value)
        else:
            mgmt.set_pin(value)
    finally:
        wipe(value)
    await management.done()


async def _show_management_key(key) -> None:
    """Display the newly generated admin secret only locally and with a timeout."""
    try:
        while True:
            choice = await screens.menu(
                t("piv.mgmt_key"),
                ["QR", "Hex"],
                timeout_ms=management.TIMEOUT_MS,
                close_others=False,
            )
            if choice is None:
                return
            text = key.hex().upper()
            if choice == 0:
                await screens.show_qr(t("piv.mgmt_key"), text)
            else:
                await screens.show_info(
                    t("piv.mgmt_key"),
                    text,
                    timeout_ms=management.TIMEOUT_MS,
                    close_others=False,
                )
            text = None
    finally:
        wipe(key)


async def _management_key() -> None:
    from ..fw import pin

    while True:
        algorithm, is_default = mgmt.mgmt_key_info()
        choice = await screens.menu(
            t("piv.mgmt_key"),
            [
                t("piv.mgmt_key.generate"),
                t("piv.mgmt_key.default"),
                algorithm + " / " + t("manage.piv.default" if is_default else "manage.piv.custom"),
            ],
            close_others=False,
        )
        if choice is None:
            return
        if choice == 2:
            await _settings_info()
            continue
        if choice == 0:
            algorithms = (pc.ALG_AES192, pc.ALG_AES128, pc.ALG_AES256, pc.ALG_3DES)
            selected = await screens.menu(
                t("piv.mgmt_key.generate"),
                [pc.MGMT_ALG_NAME[a] for a in algorithms],
                close_others=False,
            )
            if selected is None or not await pin.reauthenticate():
                continue
            if not await management.confirm("piv.mgmt_key.generate", "manage.piv.mgmt_warning"):
                continue
            key = bytearray(mgmt.generate_mgmt_key(algorithms[selected]))
            await _show_management_key(key)
        elif await pin.reauthenticate() and await management.confirm(
            "piv.mgmt_key.default",
            "manage.piv.default_warning",
        ):
            mgmt.reset_mgmt_key_default()
            await management.done()


async def _settings_info() -> None:
    retries = mgmt.retries()
    algorithm, is_default = mgmt.mgmt_key_info()
    text = t("manage.piv.retries", *retries["pin"], *retries["puk"])
    text += "\n" + algorithm + " / " + t("manage.piv.default" if is_default else "manage.piv.custom")
    for key in mgmt.warnings():
        text += "\n" + t(key)
    await screens.show_info(t("piv.settings"), text, close_others=False)


async def _reset() -> None:
    from ..fw import pin

    if await pin.reauthenticate():
        await mgmt.reset(InlineInteraction())
        await management.done()


async def _settings() -> None:
    while True:
        choice = await screens.menu(
            t("piv.settings"),
            [t("piv.set_pin"), t("piv.set_puk"), t("piv.mgmt_key"), t("manage.info"), t("piv.reset")],
            close_others=False,
        )
        if choice is None:
            return
        if choice == 0:
            await management.run(_set_pin())
        elif choice == 1:
            await management.run(_set_pin(True))
        else:
            await management.run((_management_key, _settings_info, _reset)[choice - 2]())


async def menu() -> None:
    warnings = mgmt.warnings()
    if warnings:
        await screens.show_info(t("piv.title"), "\n".join(t(key) for key in warnings), close_others=False)
    cur = 0
    while True:
        cur = await screens.menu(
            t("piv.title"),
            [t("piv.identities"), t("piv.certificates"), t("piv.signatures"), t("piv.settings")],
            cur,
            close_others=False,
        )
        if cur is None:
            return
        if cur == 0:
            await management.run(_slots())
        elif cur == 1:
            await management.run(_slots(True))
        elif cur == 2:
            await screens.show_info(t("piv.signatures"), t("manage.piv.info"), close_others=False)
        else:
            await management.run(_settings())
