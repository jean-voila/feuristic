# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Persistent FIDO2 authenticator state (namespace ``FIDO_STATE``, see
docs/architecture.md §6.1 and docs/protocols/fido2.md "Storage layout").

* **State blob** (keys ``FIDO_STATE_CLIENTPIN`` A/B = 0x00/0x01, written
  atomically through :class:`feuristic.core.store.Blob`)::

      version(1)=1 | seed(32) | pinRetries(1) | flags(1) | pinHash(16) | minPinLen(1)

  ``seed`` is a random 32-byte *reset epoch* mixed into every key-wrapping
  key (non-discoverable credential IDs and U2F key handles). The device
  master secret is shared by all applications and cannot be rotated by a
  CTAP ``authenticatorReset``; regenerating the seed instead invalidates
  every credential ever issued, as required by CTAP 2.1 §6.6.
  ``pinHash`` is ``LEFT(SHA-256(PIN), 16)`` (CTAP 2.1 §6.5.5.5).

* **Signature counter** (keys 0x04/0x05): one *global* counter shared by
  CTAP2 and U2F, kept in a :class:`~feuristic.core.counters.RedundantCounter`
  and handed out through a :class:`~feuristic.core.counters.NonceAllocator`
  (one flash write pair per :data:`COUNTER_BLOCK` signatures). Values only
  ever increase, also across power cuts. Trade-off: a global counter lets
  colluding relying parties estimate the activity at other sites; per
  credential counters would require rewriting a 400-byte record on every
  assertion (flash wear on a 64 KiB norcow sector) and cannot exist for
  stateless non-discoverable credentials.
"""

from micropython import const

from ...core import namespaces
from ...core.counters import NonceAllocator, RedundantCounter
from ...core.store import Blob
from ...platform import crypto

STATE_VERSION = const(1)
MAX_PIN_RETRIES = const(8)
DEFAULT_MIN_PIN_LENGTH = const(4)
COUNTER_BLOCK = const(32)

# keys inside FIDO_STATE not (yet) declared in core.namespaces
FIDO_STATE_SIGN_COUNTER_A = const(0x04)
FIDO_STATE_SIGN_COUNTER_B = const(0x05)

_FLAG_PIN_SET = const(0x01)
_STATE_LEN = const(52)


class FidoState:
    """Cached view of the persistent FIDO2 state (seed, PIN, counter)."""

    def __init__(self) -> None:
        self._blob = Blob(
            namespaces.FIDO_STATE,
            namespaces.FIDO_STATE_CLIENTPIN,
            namespaces.FIDO_STATE_CLIENTPIN + 1,
            64,
        )
        self._counter = RedundantCounter(
            namespaces.FIDO_STATE, FIDO_STATE_SIGN_COUNTER_A, FIDO_STATE_SIGN_COUNTER_B, public=False
        )
        self._alloc = NonceAllocator(self._counter, COUNTER_BLOCK)
        self._seed = None
        self._retries = MAX_PIN_RETRIES
        self._pin_hash = None
        self._min_pin_len = DEFAULT_MIN_PIN_LENGTH

    # -- persistence -----------------------------------------------------------
    def _load(self) -> None:
        if self._seed is not None:
            return
        raw = self._blob.get()
        if raw is not None and len(raw) == _STATE_LEN and raw[0] == STATE_VERSION:
            self._seed = bytes(raw[1:33])
            self._retries = min(raw[33], MAX_PIN_RETRIES)
            self._pin_hash = bytes(raw[35:51]) if raw[34] & _FLAG_PIN_SET else None
            self._min_pin_len = max(raw[51], DEFAULT_MIN_PIN_LENGTH)
            return
        # first use (or unrecoverable corruption): fresh epoch, no PIN
        self._seed = crypto.random_bytes(32)
        self._retries = MAX_PIN_RETRIES
        self._pin_hash = None
        self._min_pin_len = DEFAULT_MIN_PIN_LENGTH
        self._save()

    def _save(self) -> None:
        flags = _FLAG_PIN_SET if self._pin_hash is not None else 0
        raw = (
            bytes((STATE_VERSION,))
            + self._seed
            + bytes((self._retries, flags))
            + (self._pin_hash if self._pin_hash is not None else bytes(16))
            + bytes((self._min_pin_len,))
        )
        self._blob.set(raw)

    # -- accessors -------------------------------------------------------------
    @property
    def seed(self) -> bytes:
        self._load()
        return self._seed

    @property
    def pin_retries(self) -> int:
        self._load()
        return self._retries

    @property
    def pin_hash(self):
        """``LEFT(SHA-256(PIN), 16)`` or ``None`` when no PIN is set."""
        self._load()
        return self._pin_hash

    def pin_is_set(self) -> bool:
        return self.pin_hash is not None

    @property
    def min_pin_length(self) -> int:
        self._load()
        return self._min_pin_len

    def set_pin_retries(self, retries: int) -> None:
        """Persist the retry counter (callers decrement *before* verifying)."""
        self._load()
        retries = max(0, min(retries, MAX_PIN_RETRIES))
        if retries != self._retries:
            self._retries = retries
            self._save()

    def set_pin_hash(self, pin_hash: bytes) -> None:
        """Store a new PIN hash and reset the retry counter to the maximum."""
        if len(pin_hash) != 16:
            raise ValueError("pin hash")
        self._load()
        self._pin_hash = bytes(pin_hash)
        self._retries = MAX_PIN_RETRIES
        self._save()

    def regenerate(self) -> None:
        """authenticatorReset: new epoch seed, no PIN, retries reset (one
        atomic write)."""
        self._load()
        self._seed = crypto.random_bytes(32)
        self._pin_hash = None
        self._retries = MAX_PIN_RETRIES
        self._min_pin_len = DEFAULT_MIN_PIN_LENGTH
        self._save()

    # -- signature counter -----------------------------------------------------
    def next_signature_counter(self) -> int:
        """Next value of the global signature counter (always ≥ 1)."""
        return (self._alloc.allocate() + 1) & 0xFFFFFFFF

    def signature_counter(self) -> int:
        """Lower bound of every counter value handed out so far (backups)."""
        return self._counter.get()

    def raise_signature_counter(self, value: int) -> None:
        """Make every future counter strictly greater than ``value``."""
        value = min(int(value), 0xFFFFFFF0)
        if value > self._counter.get():
            self._counter.advance_to(value)
            self._alloc = NonceAllocator(self._counter, COUNTER_BLOCK)
