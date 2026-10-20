# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""State of one "Importer un QR" / "Restaurer" MSC session (spec §3.3, §8.2).

Pure logic: the firmware glue drives USB/MSC, decodes one QR per image and
feeds each payload to :meth:`ImportSession.add_payload`, which returns an
:class:`ImportEvent` for the screen. The session

* accepts several files in a row without leaving the mode (multi-fragment
  backups, spec §3.3), in any order, ignoring exact duplicates;
* can collect several backup sequences at once (one per identity of a full
  export); it is *ready* only when **every** sequence seen is complete — any
  missing frame blocks the restore (spec §8.2). The UI may
  :meth:`~ImportSession.discard` an incomplete sequence explicitly;
* holds at most one ``otpauth://`` URI. **Mixing rule:** an ``otpauth://``
  image while backup frames are being collected, or a backup frame while an
  OTP import is pending, is rejected (``REJECTED_MIXED``) and leaves the
  current state untouched; the user finishes or cancels the current import
  first, then starts a new session;
* never writes storage: :meth:`~ImportSession.action` returns what to do,
  the glue performs it (OTP import / :func:`feuristic.apps.backup.restore.restore`)
  after on-device confirmation, then calls :meth:`~ImportSession.finish`
  and requests the SCSI eject. :meth:`~ImportSession.abort` (cable removed,
  failure) purges everything.

Copying a file, analysing it and writing the secret are three separate
operations (spec §3.3 "règle d'intégrité"): this module is the middle one.
"""

from micropython import const

from ...core.secure import wipe
from ...platform import crypto
from ..backup import frames
from ..backup.errors import (
    FrameChecksumError,
    FrameConflict,
    FrameError,
    FrameLimitExceeded,
    FrameTotalMismatch,
)
from . import payload as _payload
from . import strings as _strings

_strings.register()

# --- event statuses ---------------------------------------------------------
OTP_READY = const(1)  # otpauth URI accepted; an OTP action is available
FRAME_ADDED = const(2)  # new backup frame stored
BACKUP_COMPLETE = const(3)  # new frame stored and its sequence is now complete
DUPLICATE = const(4)  # identical frame / URI already received (ignored)
REJECTED_UNSUPPORTED = const(10)  # not otpauth:// nor FB1: (spec §3.3)
REJECTED_TOO_LARGE = const(11)
REJECTED_BACKUP_VERSION = const(12)  # FB<n>: with n != 1
REJECTED_FRAME_INVALID = const(13)  # bad Base45 / length / index range
REJECTED_CHECKSUM = const(14)
REJECTED_CONFLICT = const(15)  # same id+index, different content
REJECTED_TOTAL_MISMATCH = const(16)
REJECTED_LIMIT = const(17)  # too many frames / bytes / backups
REJECTED_MIXED = const(18)  # OTP and backup in the same session
REJECTED_OTP_PENDING = const(19)  # a different otpauth URI is already pending
REJECTED_FINISHED = const(20)  # session finished or aborted

ACTION_OTP = const(1)
ACTION_RESTORE = const(2)

#: distinct backup sequences per session (a full export of every identity)
MAX_BACKUPS = const(192)
#: envelope bytes kept in RAM per session (all sequences together); the
#: firmware may pass a lower bound on T2B1
MAX_SESSION_BYTES = const(96 * 1024)
# Device import processes one native identity at a time. Every currently
# exported provider identity fits this envelope bound (tested with maximum
# metadata, three OpenPGP RSA keys, PIV certificates and FIDO largeBlobs).
# The public v1 envelope/parser bounds remain unchanged for host decoders.
DEVICE_MAX_BYTES = const(12 * 1024)
DEVICE_MAX_BACKUPS = const(1)
DEVICE_MAX_ENVELOPES = const(192)
DEVICE_MAX_SETS = const(4)
#: missing indices reported per sequence in progress snapshots
MISSING_REPORT_LIMIT = const(16)

_STATUS_KEYS = {
    OTP_READY: "importer.status.otp_ready",
    FRAME_ADDED: "importer.status.frame_added",
    BACKUP_COMPLETE: "importer.status.backup_complete",
    DUPLICATE: "importer.status.duplicate",
    REJECTED_UNSUPPORTED: "importer.err.unsupported",
    REJECTED_TOO_LARGE: "importer.err.too_large",
    REJECTED_BACKUP_VERSION: "importer.err.backup_version",
    REJECTED_FRAME_INVALID: "importer.err.frame_invalid",
    REJECTED_CHECKSUM: "importer.err.checksum",
    REJECTED_CONFLICT: "importer.err.conflict",
    REJECTED_TOTAL_MISMATCH: "importer.err.total",
    REJECTED_LIMIT: "importer.err.limit",
    REJECTED_MIXED: "importer.err.mixed",
    REJECTED_OTP_PENDING: "importer.err.otp_pending",
    REJECTED_FINISHED: "importer.err.finished",
}


class ImportEvent:
    """Outcome of one payload, for the screen.

    ``key`` is the i18n key of the message. For frame events ``backup_id``,
    ``index``, ``total``, ``received`` and ``missing`` (first indices) describe
    the affected sequence."""

    def __init__(
        self, status: int, key=None, backup_id=None, index=None, total=None, received=None, missing=None
    ):
        self.status = status
        self.key = key if key is not None else _STATUS_KEYS.get(status)
        self.backup_id = backup_id
        self.index = index
        self.total = total
        self.received = received
        self.missing = missing if missing is not None else []

    @property
    def accepted(self) -> bool:
        return self.status in (OTP_READY, FRAME_ADDED, BACKUP_COMPLETE, DUPLICATE)

    def __repr__(self) -> str:
        return f"ImportEvent({self.status}, {self.key!r})"


class BackupProgress:
    """Snapshot of one sequence."""

    def __init__(self, backup_id, received, total, missing, complete) -> None:
        self.backup_id = backup_id
        self.received = received
        self.total = total
        self.missing = missing
        self.complete = complete


class Action:
    """What the glue must do once the session is ready.

    * ``ACTION_OTP``: ``otp_uri`` (``bytearray``, valid until
      :meth:`ImportSession.finish`/``abort`` wipe it) → OTP import flow.
    * ``ACTION_RESTORE``: ``envelopes`` (list of bytes, one per sequence) →
      :func:`feuristic.apps.backup.restore.restore`.
    """

    def __init__(self, kind: int, otp_uri=None, envelopes=None) -> None:
        self.kind = kind
        self.otp_uri = otp_uri
        self.envelopes = envelopes


class ImportSession:
    def __init__(
        self, max_backups: int = MAX_BACKUPS, max_bytes: int = MAX_SESSION_BYTES, compact=False
    ) -> None:
        self.max_backups = max_backups
        self.max_bytes = max_bytes
        self.compact = compact
        self._backups = []  # [frames.Reassembler] in arrival order
        self._otp = None  # bytearray
        self._finished = False
        self.files_seen = 0
        self.files_rejected = 0

    # -- feeding ------------------------------------------------------------
    def add_payload(self, data) -> ImportEvent:
        """Process the decoded QR payload of one imported image."""
        self.files_seen += 1
        ev = self._add(data)
        if not ev.accepted:
            self.files_rejected += 1
        return ev

    def _add(self, data) -> ImportEvent:
        if self._finished:
            return ImportEvent(REJECTED_FINISHED)
        p = _payload.classify(data)
        if p.kind == _payload.KIND_OTPAUTH:
            return self._add_otp(p.data)
        if p.kind == _payload.KIND_BACKUP_FRAME:
            return self._add_frame(p.data)
        if p.kind == _payload.KIND_TOO_LARGE:
            return ImportEvent(REJECTED_TOO_LARGE)
        if p.kind == _payload.KIND_BACKUP_UNSUPPORTED_VERSION:
            return ImportEvent(REJECTED_BACKUP_VERSION)
        return ImportEvent(REJECTED_UNSUPPORTED, p.reason)

    def _add_otp(self, uri: bytes) -> ImportEvent:
        if self._backups:
            return ImportEvent(REJECTED_MIXED)
        if self._otp is not None:
            if crypto.ct_equal(bytes(self._otp), uri):
                return ImportEvent(DUPLICATE)
            return ImportEvent(REJECTED_OTP_PENDING)
        self._otp = bytearray(uri)
        return ImportEvent(OTP_READY)

    def _find(self, backup_id):
        for r in self._backups:
            if r.backup_id == backup_id:
                return r
        return None

    def _frame_event(self, status, r, index) -> ImportEvent:
        return ImportEvent(
            status,
            backup_id=r.backup_id,
            index=index,
            total=r.total,
            received=r.received,
            missing=r.missing(MISSING_REPORT_LIMIT),
        )

    def _add_frame(self, text: bytes) -> ImportEvent:
        if self._otp is not None:
            return ImportEvent(REJECTED_MIXED)
        try:
            f = frames.parse_frame(text)
        except FrameChecksumError:
            return ImportEvent(REJECTED_CHECKSUM)
        except FrameError:
            return ImportEvent(REJECTED_FRAME_INVALID)
        r = self._find(f.backup_id)
        is_new = r is None
        if is_new:
            if len(self._backups) >= self.max_backups:
                return ImportEvent(REJECTED_LIMIT, backup_id=f.backup_id)
            reassembler = frames.PackedReassembler if self.compact else frames.Reassembler
            r = reassembler(f.backup_id)
        # remaining session budget for this sequence (duplicates are detected first)
        others = self.bytes_used() - (0 if is_new else r.bytes_received)
        budget = self.max_bytes - others
        r.max_bytes = budget if budget < frames.MAX_TOTAL_BYTES else frames.MAX_TOTAL_BYTES
        try:
            added = r.add(f)
        except FrameConflict:
            return ImportEvent(REJECTED_CONFLICT, backup_id=f.backup_id, index=f.index, total=r.total)
        except FrameTotalMismatch:
            return ImportEvent(REJECTED_TOTAL_MISMATCH, backup_id=f.backup_id, index=f.index, total=r.total)
        except FrameLimitExceeded:
            return ImportEvent(REJECTED_LIMIT, backup_id=f.backup_id, index=f.index, total=f.total)
        if is_new:
            self._backups.append(r)
        if not added:
            return self._frame_event(DUPLICATE, r, f.index)
        return self._frame_event(BACKUP_COMPLETE if r.is_complete() else FRAME_ADDED, r, f.index)

    # -- state ----------------------------------------------------------------
    def bytes_used(self) -> int:
        n = 0
        for r in self._backups:
            n += r.bytes_received
        return n

    def has_backup(self) -> bool:
        return bool(self._backups)

    def has_otp(self) -> bool:
        return self._otp is not None

    @property
    def finished(self) -> bool:
        return self._finished

    def progress(self) -> list:
        """One :class:`BackupProgress` per sequence, in arrival order."""
        return [
            BackupProgress(r.backup_id, r.received, r.total, r.missing(MISSING_REPORT_LIMIT), r.is_complete())
            for r in self._backups
        ]

    def counts(self) -> tuple:
        """``(complete_sequences, incomplete_sequences)``."""
        done = 0
        for r in self._backups:
            if r.is_complete():
                done += 1
        return done, len(self._backups) - done

    def is_ready(self) -> bool:
        """True when an action can be offered: a pending OTP URI, or at
        least one backup sequence and every sequence complete."""
        if self._finished:
            return False
        if self._otp is not None:
            return True
        done, missing = self.counts()
        return done > 0 and missing == 0

    def action(self):
        """The action to perform, or None if not ready. Non-destructive: may
        be called again (e.g. after a wrong passphrase)."""
        if not self.is_ready():
            return None
        if self._otp is not None:
            return Action(ACTION_OTP, otp_uri=self._otp)
        return Action(ACTION_RESTORE, envelopes=[r.assemble() for r in self._backups])

    def take_complete(self):
        """Consume one complete identity envelope without ending USB import.

        Firmware pauses its image decoder before calling this method. The
        reassembler's chunk list is released immediately, so authentication
        does not retain both all QR chunks and every assembled envelope.
        Incomplete identities remain pending and are never returned. The
        caller must authenticate and validate the complete envelope before
        making any persistent change.
        """
        if self._finished or self._otp is not None:
            return None
        for r in self._backups:
            if r.is_complete():
                raw = r.assemble()
                self._backups.remove(r)
                return raw
        return None

    def discard(self, backup_id) -> bool:
        """Drop one sequence (user decision for an incomplete sequence)."""
        r = self._find(bytes(backup_id))
        if r is None:
            return False
        self._backups.remove(r)
        return True

    def _purge(self) -> None:
        if self._otp is not None:
            wipe(self._otp)
            self._otp = None
        self._backups = []

    def finish(self) -> None:
        """Action done (or declined): purge and refuse further payloads."""
        self._purge()
        self._finished = True

    def abort(self) -> None:
        """Cable removed / failure: purge everything (spec §3.3)."""
        self.finish()
