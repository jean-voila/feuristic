# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""OpenPGP Card application v3.4 (product spec F03, §6.1).

* :mod:`.applet` — :class:`OpenPgpApplet`, plugged into the card dispatcher;
* :mod:`.storage` — identity model and power-loss-safe persistence;
* :mod:`.keys` — algorithms, public key DOs, v4 fingerprints;
* :mod:`.localmgmt` — device-menu functions (generate / view / delete / PINs);
* :mod:`.provider` — backup provider ``TYPE = "openpgp"``;
* :mod:`.strings` — EN/FR strings.

See docs/protocols/openpgp.md.
"""
