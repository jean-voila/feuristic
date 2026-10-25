# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Device-wide state: language, initialisation flag, master secret, USB serial."""

from micropython import const

from ..core import i18n
from ..core import namespaces as ns
from ..platform import crypto, kv

SCHEMA_VERSION = const(1)
AUTOLOCK_MS = const(5 * 60 * 1000)  # spec §9: lock after 5 minutes of inactivity

_ms_cache = None


def language() -> int:
    raw = kv.get(ns.SYS_PUBLIC, ns.SYS_PUB_LANGUAGE, True)
    if raw and raw[0] == i18n.FR:
        return i18n.FR
    return i18n.EN


def apply_language(lang: int) -> None:
    """Switch both the feuristic string tables and the Rust layout strings."""
    import trezortranslate

    i18n.set_language(lang)
    try:
        trezortranslate.set_embedded_french(lang == i18n.FR)
    except Exception:
        # A running layout holds the translations; they will switch at the
        # next attempt (callers apply the language between layouts).
        pass


def set_language(lang: int) -> None:
    kv.set(ns.SYS_PUBLIC, ns.SYS_PUB_LANGUAGE, bytes((lang,)), True)
    apply_language(lang)


def is_initialized() -> bool:
    return kv.get(ns.SYS_PUBLIC, ns.SYS_PUB_INITIALIZED, True) == b"\x01"


def schema_supported() -> bool:
    """False if the storage was written by a newer, incompatible schema.

    Every feuristic image carries the same bootloader header version, so the
    bootloader keeps storage when an older feuristic is installed over a newer
    one. An older firmware must then refuse the data rather than reinterpret
    it. The value is public, so it can be checked before the PIN is asked.
    """
    raw = kv.get(ns.SYS_PUBLIC, ns.SYS_PUB_SCHEMA, True)
    return raw is None or len(raw) != 1 or raw[0] <= SCHEMA_VERSION


def initialize() -> None:
    """Create the master secret and mark the device initialised (storage unlocked).

    A valid master secret that is already stored is kept. It can exist without
    the public initialised flag only after an interrupted onboarding or a lost
    flag; replacing it would silently invalidate every U2F key handle and
    non-discoverable credential derived from it. A device wipe (menu, too
    many PIN attempts, bootloader) erases it, so a wiped device still gets a
    fresh secret.
    """
    global _ms_cache
    ms = kv.get(ns.SYS, ns.SYS_MASTER_SECRET)
    if ms is None or len(ms) != 32:
        ms = crypto.random_bytes(32, True)
        kv.set(ns.SYS, ns.SYS_MASTER_SECRET, ms)
    kv.set(ns.SYS_PUBLIC, ns.SYS_PUB_SCHEMA, bytes((SCHEMA_VERSION,)), True)
    kv.set(ns.SYS_PUBLIC, ns.SYS_PUB_INITIALIZED, b"\x01", True)
    _ms_cache = ms


def master_secret() -> bytes:
    """The 32-byte master secret (storage must be unlocked)."""
    global _ms_cache
    if _ms_cache is None:
        ms = kv.get(ns.SYS, ns.SYS_MASTER_SECRET)
        if ms is None or len(ms) != 32:
            raise RuntimeError("master secret missing")
        _ms_cache = ms
    return _ms_cache


def forget_master_secret() -> None:
    """Drop the cached master secret (on lock)."""
    global _ms_cache
    _ms_cache = None


def usb_serial() -> str:
    """USB serial number: 24 hex chars, random per device, regenerated after a
    wipe (stored public so that USB can start before the storage is unlocked)."""
    raw = kv.get(ns.SYS_PUBLIC, ns.SYS_PUB_USB_SERIAL, True)
    if raw is None or len(raw) != 12:
        raw = crypto.random_bytes(12, False)
        kv.set(ns.SYS_PUBLIC, ns.SYS_PUB_USB_SERIAL, raw, True)
    return bytes(raw).hex().upper()
