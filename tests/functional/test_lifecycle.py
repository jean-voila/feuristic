# SPDX-License-Identifier: GPL-3.0-only
"""Locked public reader promotes to private applets after a manual unlock."""

from contextlib import closing

from conftest import enter_pin
from harness.ccid import CcidClient
from harness.emulator import PORT_CCID


def test_public_rng_then_manual_unlock_preserves_powered_reader(ready, emu):
    d = ready
    with closing(CcidClient(emu.port(PORT_CCID))) as card:
        card.power_on()
        select_openpgp = bytes.fromhex("00A4040006D27600012401")
        assert card.transmit(select_openpgp)[1] == 0x9000
        d.select("Lock")
        d.wait_for(lambda screen: screen.component and screen.title != "feuristic")
        card.power_on()
        data, sw = card.transmit(bytes.fromhex("0084000020"))
        assert sw == 0x9000 and len(data) == 32
        d.both()
        enter_pin(d)
        d.wait_title("feuristic")
        # No second POWER ON: promotion must preserve this powered CCID
        # reader and its host sequence while replacing its dispatcher.
        assert card.transmit(select_openpgp)[1] == 0x9000
        aid, sw = card.transmit(bytes.fromhex("00CA004F00"))
        assert sw == 0x9000 and aid.startswith(bytes.fromhex("D27600012401"))
        assert card.transmit(bytes.fromhex("00A4040005A000000308"))[1] == 0x9000
