# SPDX-License-Identifier: GPL-3.0-only
"""OpenPGP through the whole reader: CCID packets → dispatcher → applet."""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from feuristic.apps.card import apdu, ccid
from feuristic.apps.card.card import Card
from feuristic.apps.card.ccid import build_command as cmd
from feuristic.apps.card.openpgp.applet import OpenPgpApplet
from feuristic.core.interaction import ScriptedInteraction

from ...aio import run
from .conftest import MS, find_do, public_from_7f49


class Reader:
    def __init__(self):
        self.ui = ScriptedInteraction()
        self.applet = OpenPgpApplet(self.ui, MS)
        self.card = Card([self.applet])
        self.seq = 0

    def message(self, mtype, data=b"", **kw):
        self.seq = (self.seq + 1) & 0xFF
        raw = cmd(mtype, self.seq, data, **kw)
        out = []
        for i in range(0, len(raw), 64):
            out.extend(self.card.receive(raw[i : i + 64]))
        if self.card.pending is not None:
            assert out == []
            assert self.card.time_extension()  # glue would send these while waiting
            out = run(self.card.process_pending())
        msg = b"".join(out)
        assert int.from_bytes(msg[1:5], "little") == len(msg) - 10
        assert msg[6] == self.seq
        return msg

    def apdu(self, raw):
        m = self.message(ccid.PC_TO_RDR_XFR_BLOCK, raw)
        assert m[7] == 0 and m[9] == 0
        return m[10:-2], int.from_bytes(m[-2:], "big")


def test_gnupg_session_over_ccid():
    r = Reader()
    atr = r.message(ccid.PC_TO_RDR_ICC_POWER_ON)
    assert atr[10:] == ccid.atr()
    assert r.apdu(bytes.fromhex("00A4040006D27600012401")) == (b"", 0x9000)
    data, sw = r.apdu(bytes.fromhex("00CA006E000000"))  # extended Le
    assert sw == 0x9000 and find_do(data, 0x4F) == r.applet.AID
    assert r.apdu(apdu.build(0, 0x20, 0, 0x83, b"12345678"))[1] == 0x9000
    data, sw = r.apdu(bytes.fromhex("00478000000002B6000000"))
    assert sw == 0x9000
    pub = public_from_7f49(data)[0x86]
    assert r.apdu(apdu.build(0, 0x20, 0, 0x81, b"123456"))[1] == 0x9000
    sig, sw = r.apdu(bytes.fromhex("002A9E9A000020") + bytes(32) + b"\x00\x00")
    assert sw == 0x9000
    Ed25519PublicKey.from_public_bytes(pub).verify(sig, bytes(32))
    # card reset drops the PIN verification
    r.message(ccid.PC_TO_RDR_ICC_POWER_OFF)
    r.message(ccid.PC_TO_RDR_ICC_POWER_ON)
    r.apdu(bytes.fromhex("00A4040006D27600012401"))
    assert r.apdu(bytes.fromhex("0020008100"))[1] == 0x63C3


def test_large_certificate_put_and_get_over_ccid():
    r = Reader()
    r.message(ccid.PC_TO_RDR_ICC_POWER_ON)
    r.apdu(bytes.fromhex("00A4040006D27600012401"))
    r.apdu(apdu.build(0, 0x20, 0, 0x83, b"12345678"))
    cert = b"\x30\x82\x07\xfc" + bytes(range(256)) * 7 + bytes(252)
    assert len(cert) == 2048
    assert r.apdu(apdu.build(0, 0xDA, 0x7F, 0x21, cert))[1] == 0x9000
    data, sw = r.apdu(bytes.fromhex("00CA7F21000000"))
    assert sw == 0x9000 and data == cert
    # short APDUs + command chaining (cards without extended support in the host)
    r.apdu(apdu.build(0x10, 0xDA, 0x7F, 0x21, cert[:255]))
    for i in range(255, 2040, 255):
        r.apdu(apdu.build(0x10, 0xDA, 0x7F, 0x21, cert[i : i + 255]))
    assert r.apdu(apdu.build(0x00, 0xDA, 0x7F, 0x21, cert[2040:]))[1] == 0x9000
    data, sw = r.apdu(bytes.fromhex("00CA7F2100"))
    got = data
    while sw >> 8 == 0x61:
        data, sw = r.apdu(bytes.fromhex("00C0000000"))
        got += data
    assert sw == 0x9000 and got == cert
