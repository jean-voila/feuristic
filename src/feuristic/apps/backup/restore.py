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

from ...core.errors import FeuristicError, InvalidInput, PolicyDenied, UserCancelled
from ...core.interaction import DANGER, NORMAL, SENSITIVE, Prompt
from ...core.secure import wipe
from ...platform import crypto
from . import envelope
from . import provider as registry
from .errors import AuthenticationFailed, FrameConflict, PlaintextError, RestoreLimitExceeded
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


class RecentReceipts:
    """Exact total plus the last four public receipts, independent of set size.

    ``len`` is the total. Iteration exposes the retained examples only, so a
    full-device restore does not keep hundreds of long labels in the heap.
    """

    def __init__(self) -> None:
        self.total = 0
        self.recent = []

    def append(self, receipt) -> None:
        self.total += 1
        if len(self.recent) == 4:
            self.recent.pop(0)
        self.recent.append(receipt)

    def __len__(self) -> int:
        return self.total

    def __iter__(self):
        return iter(self.recent)


class StreamingRestore:
    """Restore complete envelopes one at a time while the MSC volume stays up.

    The wire format and authentication checks are identical to ``restore``.
    Every item in the current envelope is authenticated and validated before
    any of its items are written. Earlier, explicitly approved identities
    remain restored if a later envelope is missing, refused or damaged.
    Only derived keys, public progress and receipts survive between envelopes;
    ciphertext and decoded identity objects are never cached here.
    """

    def __init__(
        self,
        ui,
        get_passphrase,
        progress=None,
        yield_fn=None,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        max_envelopes: int = MAX_ENVELOPES,
        max_sets: int = MAX_ENVELOPES,
    ) -> None:
        if not isinstance(max_envelopes, int) or not 1 <= max_envelopes <= MAX_ENVELOPES:
            raise InvalidInput("restore envelope limit")
        if not isinstance(max_sets, int) or not 1 <= max_sets <= MAX_ENVELOPES:
            raise InvalidInput("restore set limit")
        self.max_envelopes = max_envelopes
        self.max_sets = max_sets
        self._salts = []  # accepted export salts; bounded independently of the four-key cache
        self.ui = ui
        self.get_passphrase = get_passphrase
        self.progress = progress
        self.yield_fn = yield_fn
        self.max_attempts = max_attempts
        self.report = RestoreReport()
        self.report.restored = RecentReceipts()
        self.report.skipped = RecentReceipts()
        self._keys = []  # at most four (public salt, wipeable derived key)
        self._sets = []  # [salt, count, bitset of accepted envelope sequence numbers]
        self._seen = bytearray()  # fixed-width public backup id(8) + envelope SHA-256(32)
        self._closed = False
        self.last_duplicate = False

    def _already_seen(self, raw, header) -> bool:
        digest = crypto.sha256(raw)
        for offset in range(0, len(self._seen), 40):
            if self._seen[offset : offset + 8] == header.backup_id:
                if self._seen[offset + 8 : offset + 40] != digest:
                    raise FrameConflict("completed backup id reused with different content")
                return True
        return False

    async def _open(self, raw, header):
        for salt, key in self._keys:
            if salt == header.salt:
                return envelope.open_with_key(raw, key, header)
        for attempt in range(1, self.max_attempts + 1):
            request = PassphraseRequest(PURPOSE_RESTORE, attempt, len(self._keys) + 1, len(self._keys) + 1)
            pw = await acquire_passphrase(self.ui, self.get_passphrase, request)
            try:
                key = await envelope.derive_key(pw, header.salt, self.progress, self.yield_fn)
            finally:
                if isinstance(pw, bytearray):
                    wipe(pw)
            keep = False
            try:
                try:
                    contents = envelope.open_with_key(raw, key, header)
                except AuthenticationFailed:
                    if attempt >= self.max_attempts:
                        raise
                    await self.ui.notify("backup.wrong_passphrase", "backup.wrong_passphrase.title")
                    continue
                if len(self._keys) == 4:
                    _, old_key = self._keys.pop(0)
                    wipe(old_key)
                self._keys.append((header.salt, key))
                keep = True
                return contents
            finally:
                if not keep:
                    wipe(key)
        raise AuthenticationFailed("authentication failed")

    def _full_set(self, contents):
        if contents.kind != envelope.KIND_FULL:
            return None
        for entry in self._sets:
            if entry[0] == contents.header.salt:
                if entry[1] != contents.count:
                    raise PlaintextError("inconsistent full export count")
                bit = contents.seq - 1
                if entry[2][bit // 8] & (1 << (bit % 8)):
                    raise FrameConflict("full export sequence reused with a different backup id")
                return entry
        if len(self._sets) >= self.max_sets:
            raise InvalidInput("too many full export sets")
        return [contents.header.salt, contents.count, bytearray((contents.count + 7) // 8)]

    def incomplete_sets(self) -> list:
        """Public progress: (accepted envelopes, expected envelopes) per set."""
        incomplete = []
        for _, count, bits in self._sets:
            present = 0
            for bit in range(count):
                if bits[bit // 8] & (1 << (bit % 8)):
                    present += 1
            if present != count:
                incomplete.append((present, count))
        return incomplete

    async def restore_envelope(self, raw) -> RestoreReport:
        if self._closed:
            raise PolicyDenied("restore session closed")
        if self.report.failed is not None:
            raise PolicyDenied("restore session has a failed identity")
        header = envelope.parse_header(raw)
        self.last_duplicate = self._already_seen(raw, header)
        if self.last_duplicate:
            return self.report
        if len(self._seen) // 40 >= self.max_envelopes:
            raise RestoreLimitExceeded("restore session limit reached; finish and reopen import")
        if header.salt not in self._salts and len(self._salts) >= self.max_sets:
            raise RestoreLimitExceeded("restore set limit reached; finish and reopen import")
        contents = await self._open(raw, header)
        # No mutation, including partial restore of a multi-item envelope,
        # takes place before every authenticated item has passed validation.
        items = [_validate_item(obj, contents.backup_id) for obj in contents.items]
        full_set = self._full_set(contents)
        if (
            full_set is not None
            and full_set not in self._sets
            and contents.count > 1
            and not await self.ui.confirm(
                Prompt(
                    "backup.restore_incomplete",
                    "backup.restore_incomplete.title",
                    (("backup.field.present", "1/" + str(contents.count)),),
                    severity=NORMAL,
                )
            )
        ):
            raise UserCancelled("incremental full export refused")
        fields = [("backup.field.count", str(len(items)))]
        fingerprint = None
        if len(items) == 1:
            fields.extend(
                (
                    ("backup.field.identity", items[0].label),
                    ("backup.field.category", category_name(items[0].provider)),
                )
            )
            fingerprint = items[0].fingerprint or None
        if not await self.ui.confirm(
            Prompt(
                "backup.restore", "backup.restore.title", fields, severity=SENSITIVE, fingerprint=fingerprint
            )
        ):
            raise UserCancelled("restore refused")
        for index in range(len(items)):
            item = items[index]
            try:
                exists = bool(item.provider.exists(item.obj))
                if exists and not await self.ui.confirm(
                    Prompt(
                        "backup.overwrite",
                        "backup.overwrite.title",
                        (
                            ("backup.field.identity", item.label),
                            ("backup.field.category", category_name(item.provider)),
                        ),
                        severity=DANGER,
                        fingerprint=item.fingerprint or None,
                    )
                ):
                    self.report.skipped.append((item.type, item.label))
                    continue
                uid = item.provider.restore_identity(item.obj, exists)
                self.report.restored.append((item.type, item.label, uid))
            except FeuristicError as exc:
                self.report.failed = (item.type, item.label, exc)
                for remaining in items[index + 1 :]:
                    self.report.not_attempted.append((remaining.type, remaining.label))
                break
        if self.report.failed is None:
            if header.salt not in self._salts:
                self._salts.append(header.salt)
            self._seen.extend(header.backup_id)
            self._seen.extend(crypto.sha256(raw))
            if full_set is not None:
                if full_set not in self._sets:
                    self._sets.append(full_set)
                bit = contents.seq - 1
                full_set[2][bit // 8] |= 1 << (bit % 8)
        self.report.incomplete_sets = self.incomplete_sets()
        return self.report

    def close(self) -> None:
        for _, key in self._keys:
            wipe(key)
        self._keys = []
        self._closed = True
