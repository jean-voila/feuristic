# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""AES key lifecycle and hardware RNG information, entirely on-device."""

from ..apps.card.aes import keys
from ..apps.card.aes import localmgmt as mgmt
from ..apps.card.aes.rng import RngHealthError
from ..core.i18n import t
from . import management, screens
from .interaction import InlineInteraction


async def _policy(current=keys.POLICY_EVERY):
    policies = (keys.POLICY_EVERY, keys.POLICY_SESSION)
    choice = await screens.menu(
        t("aes.field.policy"),
        [t(mgmt.POLICY_KEYS[p]) for p in policies],
        policies.index(current),
        close_others=False,
    )
    if choice is None:
        return None
    policy = policies[choice]
    if policy == keys.POLICY_SESSION and not await management.confirm(
        "aes.policy.session",
        "aes.session_note",
    ):
        return None
    return policy


async def _create() -> None:
    from ..fw import pin

    free = mgmt.free_ids()
    if not free:
        await screens.show_error(t("aes.full"))
        return
    selected = await screens.menu(
        t("manage.aes.id"),
        [f"#{kid}" for kid in free],
        close_others=False,
    )
    if selected is None:
        return
    name = await screens.request_text(t("manage.aes.name"), keys.NAME_MAX)
    if name is None:
        return
    keys.check_name(name)
    policy = await _policy()
    if policy is None or not await pin.reauthenticate():
        return
    fields = [
        ("aes.field.key", f"#{free[selected]} {name}"),
        ("aes.field.policy", t(mgmt.POLICY_KEYS[policy])),
    ]
    if not await screens.confirm_fields(
        t("aes.create"),
        [(t(k), v, False) for k, v in fields],
        timeout_ms=management.TIMEOUT_MS,
        close_others=False,
    ):
        return
    try:
        info = mgmt.create_key(name, policy, free[selected])
    except RngHealthError:
        await screens.show_error(t("rng.error"))
        return
    await management.done("aes.created")
    await _key_menu(info.kid)


async def _rename(kid) -> None:
    from ..fw import pin

    name = await screens.request_text(t("manage.aes.name"), keys.NAME_MAX)
    if name is None:
        return
    keys.check_name(name)
    if await pin.reauthenticate():
        mgmt.rename_key(kid, name)
        await management.done()


async def _set_policy(kid) -> None:
    from ..fw import pin

    policy = await _policy(mgmt.key_info(kid).policy)
    if policy is not None and await pin.reauthenticate():
        mgmt.set_policy(kid, policy)
        await management.done()


async def _toggle(kid) -> None:
    from ..fw import pin

    info = mgmt.key_info(kid)
    title = "aes.disable" if info.enabled else "aes.enable"
    if await pin.reauthenticate() and await management.confirm(title, hold=False):
        mgmt.set_enabled(kid, not info.enabled)
        await management.done()


async def _delete(kid):
    from ..fw import pin

    if await pin.reauthenticate() and await mgmt.delete_key(kid, InlineInteraction()):
        await management.done("manage.deleted")
        return True
    return False


async def _key_menu(kid) -> None:
    cur = 0
    while True:
        info = mgmt.key_info(kid)
        cur = await screens.menu(
            f"AES #{kid} {info.name}",
            [
                t("manage.info"),
                t("aes.rename"),
                t("aes.field.policy"),
                t("aes.disable" if info.enabled else "aes.enable"),
                t("aes.export_qr"),
                t("aes.delete"),
            ],
            cur,
            close_others=False,
        )
        if cur is None:
            return
        if cur == 0:
            await management.info(
                t("aes.title"),
                [
                    ("aes.field.key", f"#{kid} {info.name}"),
                    ("manage.aes.state", t("aes.enabled" if info.enabled else "aes.disabled")),
                    ("aes.field.policy", t(info.policy_key)),
                    ("aes.field.fingerprint", info.fingerprint),
                ],
            )
        elif cur == 1:
            await management.run(_rename(kid))
        elif cur == 2:
            await management.run(_set_policy(kid))
        elif cur == 3:
            await management.run(_toggle(kid))
        elif cur == 4:
            from ..apps.card.aes.provider import _uid
            from . import app_backup

            await app_backup.export_record("aes", _uid(kid))
        elif await management.run(_delete(kid)):
            return


async def _keys_menu() -> None:
    cur = 0
    while True:
        entries = mgmt.list_keys()
        if not entries:
            await screens.show_info(t("aes.empty"), close_others=False)
            return
        cur = await screens.menu(
            t("aes.keys"),
            [f"#{i.kid} {i.name}" for i in entries],
            cur,
            close_others=False,
        )
        if cur is None:
            return
        await management.run(_key_menu(entries[cur].kid))


async def _delete_all() -> None:
    from ..fw import pin

    if await pin.reauthenticate():
        await mgmt.delete_all(InlineInteraction())
        await management.done("manage.deleted")


async def menu() -> None:
    cur = 0
    while True:
        cur = await screens.menu(
            t("aes.title"),
            [t("aes.keys"), t("aes.create"), t("aes.prompt.wipe")],
            cur,
            close_others=False,
        )
        if cur is None:
            return
        await management.run((_keys_menu, _create, _delete_all)[cur]())


async def _retest() -> None:
    from ..fw import pin

    if not await pin.reauthenticate() or not await management.confirm("rng.retest", hold=False):
        return
    screens.show_busy(t("rng.retest"))
    if mgmt.rng_retest():
        await management.done("manage.rng.test_ok")
    else:
        await screens.show_error(t("rng.error"))


async def rng_menu() -> None:
    while True:
        choice = await screens.menu(
            t("rng.title"),
            [t("rng.status"), t("rng.info"), t("rng.retest")],
            close_others=False,
        )
        if choice is None:
            return
        if choice == 0:
            await management.info(t("rng.title"), mgmt.rng_fields())
        elif choice == 1:
            await screens.show_info(
                t("rng.info"), t("rng.source") + "\n" + t("rng.limits"), close_others=False
            )
        else:
            await management.run(_retest())
