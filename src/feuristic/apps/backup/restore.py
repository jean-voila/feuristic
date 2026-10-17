# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Restore orchestration (spec §3.3, §8.2 "Pour restaurer", §10.6).

Input: the complete envelopes produced by the import session
(:class:`feuristic.apps.importer.session.ImportSession`) once **every**
frame of every backup sequence has been received and CRC-verified.

Phases — nothing is written before phase 5:

1. parse every header (bounded, canonical, fixed schema);
2. group envelopes by salt (one group = one export session) and, per group,
   ask the passphrase and derive the key once; a wrong passphrase is
   reported and may be retried (``max_attempts``); exhausting the attempts
   raises :class:`AuthenticationFailed` with **no storage change**;
3. authenticate + decrypt + validate **all** envelopes, then validate every
   item with its provider (unknown type → :class:`UnsupportedItem`);
4. confirmations: incomplete full-export set (NORMAL), restore summary
   (SENSITIVE, shows label + fingerprint for a single identity);
5. per item: if it already exists, show its name and fingerprint and ask a
   specific DANGER overwrite confirmation (refusal skips only that item);
   then ``provider.restore_identity`` — atomic per identity. On the first
   failure the remaining items are not attempted; already restored
   identities stay (spec: "atomique par identité").
"""

from micropython import const

from ...core.errors import FeuristicError, InvalidInput, UserCancelled
from ...core.interaction import DANGER, NORMAL, SENSITIVE, Prompt
from ...core.secure import wipe
from . import envelope
from . import provider as registry
from .errors import AuthenticationFailed, PlaintextError
from .export import PURPOSE_RESTORE, PassphraseRequest, acquire_passphrase, category_name

#: wrong-passphrase attempts per envelope group before giving up
DEFAULT_MAX_ATTEMPTS = const(3)
#: envelopes accepted in one restore (a full export of the maximal set)
MAX_ENVELOPES = envelope.MAX_SET_COUNT


class RestoreItem:
    """One validated item ready to be restored."""

    def __init__(self, prov, obj, label, fingerprint, backup_id) -> None:
        self.provider = prov
        self.obj = obj
        self.type = prov.TYPE
        self.label = label
        self.fingerprint = fingerprint
        self.backup_id = backup_id


class RestoreReport:
    """Outcome shown by the UI after a restore."""

    def __init__(self) -> None:
        self.restored = []  # [(type, label, uid)]
        self.skipped = []  # [(type, label)] overwrite refused
        self.failed = None  # (type, label, exception) or None
        self.not_attempted = []  # [(type, label)] after a failure
        self.incomplete_sets = []  # [(present, count)] full exports missing identities

    @property
    def ok(self) -> bool:
        return self.failed is None


def _validate_item(obj, backup_id) -> RestoreItem:
    p = registry.get(obj.get("type"))
    validate = getattr(p, "validate", None)
    if validate is not None:
        validate(obj)
    else:  # duck-typed provider without validate(): generic checks only
        registry.check_item_common(obj, p.TYPE)
    desc = p.describe(obj)
    if not isinstance(desc, tuple) or len(desc) != 2:
        raise InvalidInput("provider describe()")
    label = registry.check_label(desc[0])
    fp = registry.check_fingerprint(desc[1])
    return RestoreItem(p, obj, label, fp, backup_id)


async def _open_group(ui, group, get_passphrase, set_index, set_count, max_attempts, progress, yield_fn):
    """Return the Contents of every envelope of a same-salt group."""
    first_env, first_hdr = group[0]
    attempt = 1
    while True:
        req = PassphraseRequest(PURPOSE_RESTORE, attempt, set_index, set_count)
        pw = await acquire_passphrase(ui, get_passphrase, req)
        try:
            key = await envelope.derive_key(pw, first_hdr.salt, progress, yield_fn)
        finally:
            if isinstance(pw, bytearray):
                wipe(pw)
        try:
            try:
                first = envelope.open_with_key(first_env, key, first_hdr)
            except AuthenticationFailed:
                if attempt >= max_attempts:
                    raise
                attempt += 1
                await ui.notify("backup.wrong_passphrase", "backup.wrong_passphrase.title")
                continue
            # same key: any further failure means an altered envelope
            out = [first]
            for env, hdr in group[1:]:
                out.append(envelope.open_with_key(env, key, hdr))
            return out
        finally:
            wipe(key)


async def restore(
    ui,
    envelopes,
    get_passphrase,
    progress=None,
    yield_fn=None,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> RestoreReport:
    """Restore the identities contained in ``envelopes`` (list of bytes)."""
    if not envelopes:
        raise InvalidInput("no backup to restore")
    if len(envelopes) > MAX_ENVELOPES:
        raise InvalidInput("too many backups")

    # phase 1: headers (deduplicate byte-identical envelopes)
    parsed = []
    seen = []
    for raw in envelopes:
        env = bytes(raw)
        if env in seen:
            continue
        seen.append(env)
        parsed.append((env, envelope.parse_header(env)))

    # phase 2: group by salt, preserving first-appearance order
    groups = []
    for env, hdr in parsed:
        for g in groups:
            if g[0][1].salt == hdr.salt:
                g.append((env, hdr))
                break
        else:
            groups.append([(env, hdr)])

    contents = []
    for gi in range(len(groups)):
        contents.extend(
            await _open_group(
                ui, groups[gi], get_passphrase, gi + 1, len(groups), max_attempts, progress, yield_fn
            )
        )

    # phase 3: validate every item before any write
    items = []
    for c in contents:
        for obj in c.items:
            items.append(_validate_item(obj, c.backup_id))

    report = RestoreReport()

    # phase 4a: full-export completeness, per salt
    sets = []  # [(salt, count, [seq...])]
    for c in contents:
        if c.kind != envelope.KIND_FULL:
            continue
        for s in sets:
            if s[0] == c.header.salt:
                if s[1] != c.count:
                    raise PlaintextError("inconsistent full export set")
                if c.seq not in s[2]:
                    s[2].append(c.seq)
                break
        else:
            sets.append((c.header.salt, c.count, [c.seq]))
    for _, count, seqs in sets:
        if len(seqs) < count:
            report.incomplete_sets.append((len(seqs), count))
    for present, count in report.incomplete_sets:
        prompt = Prompt(
            "backup.restore_incomplete",
            "backup.restore_incomplete.title",
            (("backup.field.present", f"{present}/{count}"),),
            severity=NORMAL,
        )
        if not await ui.confirm(prompt):
            raise UserCancelled("incomplete full export refused")

    # phase 4b: summary confirmation (preview of the identity, spec §3.3)
    fields = [("backup.field.count", str(len(items)))]
    fp = None
    if len(items) == 1:
        it = items[0]
        fields.append(("backup.field.identity", it.label))
        fields.append(("backup.field.category", category_name(it.provider)))
        fp = it.fingerprint or None
    if not await ui.confirm(
        Prompt("backup.restore", "backup.restore.title", fields, severity=SENSITIVE, fingerprint=fp)
    ):
        raise UserCancelled("restore refused")

    # phase 5: per-identity atomic writes
    for i in range(len(items)):
        it = items[i]
        try:
            exists = bool(it.provider.exists(it.obj))
            if exists:
                prompt = Prompt(
                    "backup.overwrite",
                    "backup.overwrite.title",
                    (
                        ("backup.field.identity", it.label),
                        ("backup.field.category", category_name(it.provider)),
                    ),
                    severity=DANGER,
                    fingerprint=it.fingerprint or None,
                )
                if not await ui.confirm(prompt):
                    report.skipped.append((it.type, it.label))
                    continue
            uid = it.provider.restore_identity(it.obj, exists)
            report.restored.append((it.type, it.label, uid))
        except FeuristicError as e:
            report.failed = (it.type, it.label, e)
            for rest in items[i + 1 :]:
                report.not_attempted.append((rest.type, rest.label))
            break

    await ui.notify(
        "backup.restore_done",
        "backup.restore_done.title",
        (
            ("backup.field.restored", str(len(report.restored))),
            ("backup.field.skipped", str(len(report.skipped))),
            ("backup.field.failed", "0" if report.failed is None else str(1 + len(report.not_attempted))),
        ),
    )
    return report
