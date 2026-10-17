# SPDX-License-Identifier: GPL-3.0-only
"""Card object: CCID packets in, dispatcher, packets out, WTX, abort."""

from feuristic.apps.card import apdu, ccid
from feuristic.apps.card.applet import Applet
from feuristic.apps.card.card import Card
from feuristic.apps.card.ccid import build_command as cmd

from ..aio import run

AID = bytes.fromhex("A0000005272101")


class Big(Applet):
    AID = AID
    NAME = "big"

    def __init__(self):
        super().__init__(None)
        self.resets = 0

    async def select(self, c):
        return apdu.Response()

    def reset(self):
        self.resets += 1

    async def process(self, c):
        if c.ins == 0x01:
            return apdu.Response(c.data)
        return apdu.Response(bytes(i & 0xFF for i in range(c.p1p2)))


def decode(packets):
    """Reassemble bulk-IN packets into messages (ZLP markers end transfers)."""
    msgs = []
    buf = b""
    for p in packets:
        buf += p
        if len(p) < 64:
            msgs.append(buf)
            buf = b""
    assert buf == b""
    return msgs


def send(card, message):
    out = []
    for i in range(0, len(message), 64):
        out.extend(card.receive(message[i : i + 64]))
    if len(message) % 64 == 0:
        out.extend(card.receive(b""))
    return out


def xfr(card, seq, raw):
    out = send(card, cmd(ccid.PC_TO_RDR_XFR_BLOCK, seq, raw))
    assert out == []
    assert card.pending is not None
    return decode(run(card.process_pending()))


def test_power_on_select_and_extended_exchange():
    app = Big()
    card = Card([app])
    (atr_msg,) = decode(send(card, cmd(ccid.PC_TO_RDR_ICC_POWER_ON, 0)))
    assert atr_msg[10:] == ccid.atr()
    assert app.resets == 1
    (m,) = xfr(card, 1, apdu.build(0, 0xA4, 4, 0, AID))
    assert m[10:] == b"\x90\x00"
    (m,) = xfr(card, 2, b"\x00\x02\x0f\x00\x00\x00\x00")  # 3840 bytes, extended Le
    assert m[6] == 2 and m[10:-2] == bytes(i & 0xFF for i in range(0xF00)) and m[-2:] == b"\x90\x00"
    # response length is a multiple of 64 → explicit ZLP marker
    n = 64 * 10 - 10 - 2
    packets = run(_xfr_packets(card, 3, b"\x00\x02" + n.to_bytes(2, "big") + b"\x00\x00\x00"))
    assert packets[-1] == b""
    assert len(b"".join(packets)) == 640


async def _xfr_packets(card, seq, raw):
    assert send(card, cmd(ccid.PC_TO_RDR_XFR_BLOCK, seq, raw)) == []
    return await card.process_pending()


def test_large_command_via_xfr_chaining():
    app = Big()
    card = Card([app])
    send(card, cmd(ccid.PC_TO_RDR_ICC_POWER_ON, 0))
    xfr(card, 1, apdu.build(0, 0xA4, 4, 0, AID))
    big = apdu.build(0, 0x01, 0, 0, bytes(range(256)) * 16, 65536)  # 4105 bytes
    assert len(big) > ccid.MAX_DATA_LENGTH
    (m,) = decode(send(card, cmd(ccid.PC_TO_RDR_XFR_BLOCK, 2, big[:4096], b8=0x01)))
    assert m[9] == 0x10
    assert send(card, cmd(ccid.PC_TO_RDR_XFR_BLOCK, 3, big[4096:], b8=0x02)) == []
    (m,) = decode(run(card.process_pending()))
    assert m[6] == 3
    # the response (4098 bytes) exceeds one block: chained with bChainParameter 1
    assert m[9] == 0x01 and len(m) == 10 + 4096
    (m2,) = decode(send(card, cmd(ccid.PC_TO_RDR_XFR_BLOCK, 4, b"", b8=0x10)))
    assert m2[9] == 0x02 and m[10:] + m2[10:] == bytes(range(256)) * 16 + b"\x90\x00"


def test_time_extension_and_busy_while_pending():
    card = Card([Big()])
    send(card, cmd(ccid.PC_TO_RDR_ICC_POWER_ON, 0))
    send(card, cmd(ccid.PC_TO_RDR_XFR_BLOCK, 7, b"\x00\x02\x00\x10\x10"))
    (w,) = decode(card.time_extension())
    assert w[0] == 0x80 and w[6] == 7 and w[7] == 0x80 and w[8] == ccid.WTX_MULTIPLIER
    (b,) = decode(send(card, cmd(ccid.PC_TO_RDR_GET_SLOT_STATUS, 8)))
    assert b[7] == 0x40 and b[8] == ccid.ERR_CMD_SLOT_BUSY
    (m,) = decode(run(card.process_pending()))
    assert m[6] == 7
    assert card.time_extension() == []


def test_abort_drops_late_response():
    card = Card([Big()])
    send(card, cmd(ccid.PC_TO_RDR_ICC_POWER_ON, 0))
    send(card, cmd(ccid.PC_TO_RDR_XFR_BLOCK, 7, b"\x00\x02\x00\x10\x10"))
    coro = card.process_pending()
    r1, r2 = decode(send(card, cmd(ccid.PC_TO_RDR_ABORT, 8)))
    assert r1[8] == ccid.ERR_CMD_ABORTED and r2[6] == 8
    assert run(coro) == []


def test_process_pending_idle():
    card = Card([Big()])
    assert run(card.process_pending()) == []


def test_handle_message_whole():
    app = Big()
    card = Card([app])
    (m,) = run(card.handle_message(cmd(ccid.PC_TO_RDR_ICC_POWER_ON, 1)))
    assert m[10:] == ccid.atr()
    (m,) = run(card.handle_message(cmd(ccid.PC_TO_RDR_XFR_BLOCK, 2, apdu.build(0, 0xA4, 4, 0, AID))))
    assert m[10:] == b"\x90\x00" and m[6] == 2
    assert run(card.handle_message(b"\x6f")) == []
    (m,) = run(card.handle_message(cmd(ccid.PC_TO_RDR_XFR_BLOCK, 3, b"abc")[:-1]))
    assert m[7] == 0x40 and m[8] == 1
    (m,) = run(card.handle_message(cmd(ccid.PC_TO_RDR_XFR_BLOCK, 4, bytes(5000))))
    assert m[8] == 1


def test_usb_reset_powers_off_and_resets_applets():
    app = Big()
    card = Card([app])
    send(card, cmd(ccid.PC_TO_RDR_ICC_POWER_ON, 0))
    xfr(card, 1, apdu.build(0, 0xA4, 4, 0, AID))
    assert card.dispatcher.selected is app
    card.usb_reset()
    assert card.dispatcher.selected is None and not card.ccid.powered
    (m,) = decode(send(card, cmd(ccid.PC_TO_RDR_XFR_BLOCK, 2, b"\x00\x00\x00\x00")))
    assert m[8] == ccid.ERR_ICC_MUTE


def test_power_off_resets_dispatcher():
    app = Big()
    card = Card([app])
    send(card, cmd(ccid.PC_TO_RDR_ICC_POWER_ON, 0))
    xfr(card, 1, apdu.build(0, 0xA4, 4, 0, AID))
    send(card, cmd(ccid.PC_TO_RDR_ICC_POWER_OFF, 2))
    assert card.dispatcher.selected is None
    assert Card.notify_slot_change() == b"\x50\x03"
    card.control_abort(0, 1)
    assert run(card.transmit(b"\x00\x01\x00\x00")) == b"\x6d\x00"
