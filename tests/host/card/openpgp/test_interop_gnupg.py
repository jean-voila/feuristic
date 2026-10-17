# SPDX-License-Identifier: GPL-3.0-only
"""GnuPG against the feuristic emulator (spec R09) — skeleton.

Enabled only with ``FEURISTIC_INTEROP=1`` and the tooling below. Scenario:

1. ``make emu MODEL=T3B1`` and unlock the emulated device (debuglink);
2. ``tools/vpcd_bridge.py`` connects the emulator's CCID UDP port
   (``TREZOR_UDP_PORT + 7``) to ``pcscd`` through vsmartcard's ``vpcd``;
3. a throw-away ``GNUPGHOME`` with ``scdaemon.conf``::

       pcsc-shared
       disable-ccid

4. ``gpg --card-status`` must show *Version 3.4*, manufacturer *unmanaged
   S/N range*, the serial derived from the device master secret, key
   attributes ``ed25519 cv25519 ed25519`` and *UIF permanent*;
5. ``gpg --card-edit`` → ``admin`` → ``generate`` (PW3 ``12345678``, device
   confirmations answered through debuglink), then sign/verify a file,
   encrypt/decrypt to the card key and ``gpg --card-edit`` →
   ``factory-reset``.
"""

import os
import shutil

import pytest

pytestmark = [
    pytest.mark.interop,
    pytest.mark.skipif(os.environ.get("FEURISTIC_INTEROP") != "1", reason="set FEURISTIC_INTEROP=1"),
]


def test_gpg_card_status_against_emulator(tmp_path):
    if shutil.which("gpg") is None:
        pytest.skip("gpg not installed")
    pytest.skip("emulator + vpcd bridge harness not implemented yet (tests/functional/interop)")
