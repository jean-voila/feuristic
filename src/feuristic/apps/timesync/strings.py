# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""English / French strings of the CDC-ACM time synchronisation (spec §3.2, §4, §9)."""

STRINGS = {
    "timesync.title": ("TOTP time", "Heure TOTP"),
    "timesync.sync_usb": ("Sync over USB", "Synchroniser par USB"),
    "timesync.waiting": (
        "Waiting for the computer. Send: TIME 1 <unix-seconds>",
        "En attente de l'ordinateur. Envoyer : TIME 1 <secondes-unix>",
    ),
    "timesync.not_set": ("Not set", "Non réglée"),
    "timesync.confirm_backward.title": ("Move the clock back?", "Reculer l'heure ?"),
    "timesync.confirm_forward.title": ("Move the clock forward?", "Avancer l'heure ?"),
    "timesync.confirm_first.title": ("Set this time?", "Régler cette heure ?"),
    "timesync.field.current": ("Current (UTC)", "Actuelle (UTC)"),
    "timesync.field.new": ("New (UTC)", "Nouvelle (UTC)"),
    "timesync.field.delta": ("Change", "Écart"),
    "timesync.done": ("Time set until power-off", "Heure réglée jusqu'à la mise hors tension"),
    "timesync.refused": ("Time change refused", "Changement d'heure refusé"),
    "timesync.cancelled": ("Time sync cancelled", "Synchronisation annulée"),
}


def register() -> None:
    """Register the time-sync strings in :mod:`feuristic.core.i18n` (idempotent)."""
    from ...core import i18n

    i18n.register(STRINGS)
