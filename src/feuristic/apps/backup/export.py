# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Export orchestration: "Exporter une identité" and "Export complet"
(spec §8.2, §9 menu "Sauvegarde", §10.3, §10.10).

Flow (identical for both modes, see format doc §8 and ADR-0004):

1. DANGER confirmation on the device, with the mandatory warning that the
   backup makes the keys recoverable by anyone holding the images and the
   passphrase, and that such keys are therefore **not** non-exportable.
2. Optional re-authentication hook (device PIN, spec §9 "réauthentification
   pour export de secrets"); the UI glue passes it.
3. Passphrase acquisition through the UI-glue callback (never stored, never
   sent to the host); policy enforced here.
4. One random salt and **one** PBKDF2 derivation per export session.
5. For each identity: provider export → envelope (own backup id, own random
   nonce) → QR frames → ``provider.on_exported(uid)``.

A full export is exposed as an :class:`ExportSession` that builds one
identity at a time, so the firmware never holds all frame texts in RAM
(T2B1 heap ≈ 120 KiB).
"""

from micropython import const

from ...core import cbor, i18n
from ...core.errors import NotFound, PolicyDenied, UserCancelled
from ...core.interaction import DANGER, Prompt
from ...core.secure import wipe
from ...platform import crypto
from . import envelope, frames
from . import provider as registry
from . import strings as _strings
from .errors import WeakPassphrase

_strings.register()

PURPOSE_EXPORT = "export"
PURPOSE_RESTORE = "restore"

#: passphrase entries violating the policy before giving up
MAX_POLICY_ATTEMPTS = const(3)


class PassphraseRequest:
    """Argument of the UI-glue ``get_passphrase`` callback.

    ``purpose`` is :data:`PURPOSE_EXPORT` (the glue **must** ask twice and
    compare with :func:`envelope.passphrases_match`) or :data:`PURPOSE_RESTORE`.
    ``attempt`` is 1-based; ``set_index``/``set_count`` identify which group
    of envelopes (distinct salts) a restore passphrase is for.
    """

    def __init__(self, purpose: str, attempt: int = 1, set_index: int = 1, set_count: int = 1) -> None:
        self.purpose = purpose
        self.attempt = attempt
        self.set_index = set_index
        self.set_count = set_count

    def __repr__(self) -> str:
        return f"PassphraseRequest({self.purpose!r}, attempt={self.attempt})"


async def acquire_passphrase(ui, get_passphrase, request):
    """Call ``await get_passphrase(request)`` until it returns a passphrase
    satisfying the policy. ``None`` → :class:`UserCancelled`; more than
    :data:`MAX_POLICY_ATTEMPTS` policy violations → :class:`WeakPassphrase`."""
    for _ in range(MAX_POLICY_ATTEMPTS):
        pw = await get_passphrase(request)
        if pw is None:
            raise UserCancelled("passphrase entry cancelled")
        try:
            envelope.check_passphrase(pw)
        except WeakPassphrase:
            if isinstance(pw, bytearray):
                wipe(pw)
            await ui.notify("backup.passphrase_policy", "backup.passphrase_policy.title")
            continue
        return pw
    raise WeakPassphrase("passphrase policy not met")


def category_name(p) -> str:
    key = getattr(p, "LABEL_KEY", "") or ""
    return i18n.t(key) if key else p.TYPE


class ExportedBackup:
    """Result of one envelope: what the UI displays as one QR sequence."""

    def __init__(
        self, item_type, uid, label, backup_id, frame_texts, envelope_len, profile, seq, count
    ) -> None:
        self.type = item_type
        self.uid = uid
        self.label = label
        self.backup_id = backup_id
        #: frame texts in display order ("FB1:..."), shown as "i/total"
        self.frames = frame_texts
        self.envelope_len = envelope_len
        self.profile = profile
        self.seq = seq  # 1-based position in the export session
        self.count = count  # identities in the export session


def _identity_label(p, uid):
    lookup = getattr(p, "identity_label", None)
    return lookup(uid) if lookup is not None else registry.BackupProvider.identity_label(p, uid)


class ExportSession:
    """Holds the derived key of one export session (one salt).

    Call :meth:`build` for each index ``0 .. len(session)-1`` (in any order,
    possibly more than once — every call produces a fresh envelope with a new
    backup id and nonce) and :meth:`close` at the end; ``close`` wipes the key.
    """

    def __init__(self, entries, key, salt, kind, profile, created) -> None:
        self.entries = entries  # [(provider, uid, label)]
        self.kind = kind
        self.profile = profile
        self.created = created
        self.salt = salt
        self._key = key

    def __len__(self) -> int:
        return len(self.entries)

    def label(self, i: int) -> tuple:
        p, uid, label = self.entries[i]
        if label is None:
            label = registry.check_label(_identity_label(p, uid))
        return p.TYPE, label

    def build(self, i: int) -> ExportedBackup:
        if self._key is None:
            raise PolicyDenied("export session closed")
        p, uid, label = self.entries[i]
        if label is None:
            label = registry.check_label(_identity_label(p, uid))
        obj = p.export_identity(uid)
        registry.check_item_common(obj, p.TYPE)
        # the item must stay decodable by the restore-side bounds
        cbor.decode(
            cbor.encode(obj),
            canonical=True,
            max_depth=6,
            max_items=envelope.MAX_ITEM_CBOR_ITEMS,
        )
        count = len(self.entries)
        seq = i + 1
        backup_id = crypto.random_bytes(envelope.BACKUP_ID_LEN)
        if self.kind == envelope.KIND_FULL:
            env = envelope.seal(self._key, self.salt, self.kind, [obj], backup_id, seq, count, self.created)
        else:
            env = envelope.seal(self._key, self.salt, self.kind, [obj], backup_id, created=self.created)
        texts = frames.split(env, backup_id, self.profile)
        # record the export (e.g. WebAuthn BS flag) before anything is shown;
        # if this fails, no frame is returned (fail closed)
        p.on_exported(uid)
        return ExportedBackup(p.TYPE, uid, label, backup_id, texts, len(env), self.profile, seq, count)

    def close(self) -> None:
        if self._key is not None:
            wipe(self._key)
            self._key = None


def _snapshot(providers) -> list:
    entries = []
    for p in providers:
        iterate = getattr(p, "iter_uids", None)
        uids = iterate() if iterate is not None else registry.BackupProvider.iter_uids(p)
        for candidate in uids:
            uid = registry.check_uid(candidate)
            registry.check_label(_identity_label(p, uid))
            entries.append((p, uid, None))
            if len(entries) > envelope.MAX_SET_COUNT:
                raise PolicyDenied("too many identities for one export")
    return entries


async def _begin(ui, entries, kind, prompt, get_passphrase, profile, progress, yield_fn, reauth, created):
    if profile not in frames.PROFILES:
        raise ValueError("unknown frame profile")
    if not await ui.confirm(prompt):
        raise UserCancelled("export refused")
    if reauth is not None and not await reauth():
        raise PolicyDenied("re-authentication failed")
    pw = await acquire_passphrase(ui, get_passphrase, PassphraseRequest(PURPOSE_EXPORT))
    try:
        salt = crypto.random_bytes(envelope.SALT_LEN)
        key = await envelope.derive_key(pw, salt, progress, yield_fn)
    finally:
        if isinstance(pw, bytearray):
            wipe(pw)
    return ExportSession(entries, key, salt, kind, profile, created)


def _warning_field() -> tuple:
    return ("backup.field.warning", i18n.t("backup.warn.recoverable"))


async def begin_identity_export(
    ui,
    item_type,
    uid,
    get_passphrase,
    profile=frames.PROFILE_DENSE,
    progress=None,
    yield_fn=None,
    reauth=None,
    created=None,
) -> ExportSession:
    """Confirm, authenticate, ask the passphrase and derive the key for the
    export of a single identity. Returns a one-entry :class:`ExportSession`."""
    p = registry.get(item_type)
    uid = registry.check_uid(uid)
    label = registry.check_label(_identity_label(p, uid))
    prompt = Prompt(
        "backup.export",
        "backup.export.title",
        (
            ("backup.field.identity", label),
            ("backup.field.category", category_name(p)),
            _warning_field(),
        ),
        severity=DANGER,
    )
    return await _begin(
        ui,
        [(p, uid, label)],
        envelope.KIND_IDENTITY,
        prompt,
        get_passphrase,
        profile,
        progress,
        yield_fn,
        reauth,
        created,
    )


async def export_identity(
    ui,
    item_type,
    uid,
    get_passphrase,
    profile=frames.PROFILE_DENSE,
    progress=None,
    yield_fn=None,
    reauth=None,
    created=None,
) -> ExportedBackup:
    """Exporter une identité: return the frames of one identity."""
    session = await begin_identity_export(
        ui, item_type, uid, get_passphrase, profile, progress, yield_fn, reauth, created
    )
    try:
        return session.build(0)
    finally:
        session.close()


async def begin_full_export(
    ui,
    get_passphrase,
    profile=frames.PROFILE_DENSE,
    progress=None,
    yield_fn=None,
    reauth=None,
    created=None,
    providers=None,
) -> ExportSession:
    """Export complet: snapshot every identity of every registered provider
    (registration order), confirm once, derive the key once."""
    entries = _snapshot(registry.all() if providers is None else providers)
    if not entries:
        raise NotFound("nothing to export")
    prompt = Prompt(
        "backup.export_full",
        "backup.export_full.title",
        (("backup.field.count", str(len(entries))), _warning_field()),
        severity=DANGER,
    )
    return await _begin(
        ui,
        entries,
        envelope.KIND_FULL,
        prompt,
        get_passphrase,
        profile,
        progress,
        yield_fn,
        reauth,
        created,
    )


async def export_full(
    ui,
    get_passphrase,
    profile=frames.PROFILE_DENSE,
    progress=None,
    yield_fn=None,
    reauth=None,
    created=None,
    providers=None,
) -> list:
    """Convenience wrapper building every envelope of a full export at once
    (host tools/tests; the firmware iterates an :class:`ExportSession`)."""
    session = await begin_full_export(
        ui, get_passphrase, profile, progress, yield_fn, reauth, created, providers
    )
    try:
        return [session.build(i) for i in range(len(session))]
    finally:
        session.close()
