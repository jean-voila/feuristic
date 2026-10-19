# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Create short-lived backup providers without retaining USB protocol servers."""


def create(kind):
    if kind == "otp":
        from ..apps.otp.provider import OtpBackupProvider

        return OtpBackupProvider()
    if kind == "openpgp":
        from ..apps.card.openpgp.provider import OpenPgpBackupProvider
        from ..apps.card.openpgp.storage import default

        return OpenPgpBackupProvider(default())
    if kind == "piv":
        from ..apps.card.piv.provider import PivBackupProvider

        return PivBackupProvider()
    if kind == "aes":
        from ..apps.card.aes.provider import AesBackupProvider

        return AesBackupProvider()
    if kind == "fido2":
        from ..apps.fido2.provider import Fido2BackupProvider
        from . import transports, usbmodes

        # Export in NORMAL must update the live credential index/backup flags.
        # During IMPORT the suspended HID server has been released completely.
        if usbmodes.current() == usbmodes.NORMAL:
            server = transports.fido_server()
            if server is not None:
                return Fido2BackupProvider(server.app.auth)
        return Fido2BackupProvider(_StoredFido())
    raise ValueError("unknown backup provider")


class _StoredFido:
    """Only the protected stores needed by FIDO backup, with no CTAP/HID state."""

    def __init__(self):
        from ..apps.fido2.credentials import CredentialStore
        from ..apps.fido2.largeblobs import LargeBlobs
        from ..apps.fido2.state import FidoState
        from . import device

        self.state = FidoState()
        self.store = CredentialStore(self.state, device.master_secret())
        # Direct entries()/write_entries() bypass transport authentication;
        # their caller is the authenticated, locally confirmed backup flow.
        self.large_blobs = LargeBlobs(None, 7545)
