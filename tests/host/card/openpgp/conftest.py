# SPDX-License-Identifier: GPL-3.0-only
"""Fixtures for the OpenPGP card tests: an applet behind the real dispatcher."""

import pytest

from feuristic.apps.card import apdu
from feuristic.apps.card.dispatcher import Dispatcher
from feuristic.apps.card.openpgp.applet import OpenPgpApplet
from feuristic.apps.card.openpgp.storage import IdentityStore
from feuristic.core import tlv
from feuristic.core.interaction import ScriptedInteraction

from ...aio import run

MS = bytes(range(32))
OPENPGP_SELECT = bytes.fromhex("00A4040006D27600012401")


class Env:
    """An OpenPGP applet behind a dispatcher, with a scripted device UI."""

    def __init__(self, ms=MS, answers=(), default=True):
        self.ms = ms
        self.ui = ScriptedInteraction(answers, default)
        self.store = IdentityStore()
        self.applet = OpenPgpApplet(self.ui, ms, self.store)
        self.disp = Dispatcher([self.applet])
        self.disp.raise_unexpected = True

    def reboot(self):
        """Simulate a power cycle: new store/applet objects on the same KV."""
        self.store = IdentityStore()
        self.applet = OpenPgpApplet(self.ui, self.ms, self.store)
        self.disp = Dispatcher([self.applet])
        self.disp.raise_unexpected = True
        return self

    def raw(self, b):
        r = run(self.disp.transmit(b))
        return r[:-2], int.from_bytes(r[-2:], "big")

    def tx(self, ins, p1=0, p2=0, data=b"", ne=0, cla=0x00):
        """Send a command; follow 61xx with GET RESPONSE like scdaemon."""
        out, sw = self.raw(apdu.build(cla, ins, p1, p2, data, ne))
        while sw >> 8 == 0x61:
            more, sw = self.raw(b"\x00\xc0\x00\x00" + bytes((sw & 0xFF,)))
            out += more
        return out, sw

    def ok(self, ins, p1=0, p2=0, data=b"", ne=0):
        out, sw = self.tx(ins, p1, p2, data, ne)
        assert sw == 0x9000, hex(sw)
        return out

    def select(self):
        return self.raw(OPENPGP_SELECT)

    def get(self, tag, ne=256):
        return self.tx(0xCA, tag >> 8, tag & 0xFF, ne=ne)

    def verify(self, p2, pin):
        return self.tx(0x20, 0, p2, pin)[1]

    def put(self, tag, data):
        return self.tx(0xDA, tag >> 8, tag & 0xFF, data)[1]

    def admin(self, pin=b"12345678"):
        assert self.verify(0x83, pin) == 0x9000

    def generate(self, role_tag):
        return self.tx(0x47, 0x80, 0x00, bytes((role_tag, 0x00)), ne=256)

    def read_public(self, role_tag):
        return self.tx(0x47, 0x81, 0x00, bytes((role_tag, 0x00)), ne=256)


def find_do(data, tag):
    """Depth-first search of a BER-TLV tree for ``tag``."""
    for t, v in tlv.parse(data):
        if t == tag:
            return v
        if tlv.is_constructed(t):
            found = find_do(v, tag)
            if found is not None:
                return found
    return None


def public_from_7f49(data):
    outer = tlv.parse(data)
    assert len(outer) == 1 and outer[0][0] == 0x7F49
    return dict(tlv.parse(outer[0][1]))


@pytest.fixture
def env():
    e = Env()
    assert e.select() == (b"", 0x9000)
    return e
