# SPDX-License-Identifier: GPL-3.0-only
"""Virtual card dispatcher: selection, CLA checks, chaining, GET RESPONSE."""

import pytest

from feuristic.apps.card import apdu
from feuristic.apps.card.applet import Applet
from feuristic.apps.card.dispatcher import Dispatcher
from feuristic.core.errors import InvalidInput, PinBlocked, StorageFull, UserCancelled, UserTimeout

from ..aio import run


class Dummy(Applet):
    """INS 01: echo data; INS 02: return P1P2 bytes; INS 03: raise given error."""

    def __init__(self, aid, name, select_sw=apdu.SW_OK, fci=b"\x6f\x00"):
        super().__init__(None)
        self.AID = aid
        self.NAME = name
        self.select_sw = select_sw
        self.fci = fci
        self.commands = []
        self.deselects = 0
        self.resets = 0
        self.error = None

    async def select(self, cmd):
        return apdu.Response(self.fci, self.select_sw)

    def deselect(self):
        self.deselects += 1

    def reset(self):
        self.resets += 1
        super().reset()

    async def process(self, cmd):
        self.commands.append(cmd)
        if cmd.ins == 0x01:
            return apdu.Response(cmd.data)
        if cmd.ins == 0x02:
            return apdu.Response(bytes(i & 0xFF for i in range(cmd.p1p2)))
        if cmd.ins == 0x03:
            raise self.error
        if cmd.ins == 0x04:
            return None
        if cmd.ins == 0x05:
            return apdu.Response(b"\xaa" * cmd.p1p2, 0x6282)
        raise apdu.ApduError(apdu.SW_INS_NOT_SUPPORTED)


AID_A = bytes.fromhex("A000000527200101")
AID_B = bytes.fromhex("A0000003080000100001")


@pytest.fixture
def env():
    a = Dummy(AID_A, "a")
    b = Dummy(AID_B, "b")
    d = Dispatcher([a, b])
    d.raise_unexpected = True
    return d, a, b


def tx(d, raw):
    r = run(d.transmit(raw))
    return r[:-2], int.from_bytes(r[-2:], "big")


def select(d, aid, p2=0x00):
    return tx(d, apdu.build(0x00, 0xA4, 0x04, p2, aid))


# --- selection ----------------------------------------------------------------


def test_select_full_and_partial(env):
    d, a, b = env
    assert select(d, AID_A) == (b"\x6f\x00", 0x9000)
    assert d.selected is a
    assert select(d, AID_B[:5]) == (b"\x6f\x00", 0x9000)  # partial: A0 00 00 03 08
    assert d.selected is b
    assert a.deselects == 1


def test_select_p2_0c_suppresses_data(env):
    d, a, _ = env
    assert select(d, AID_A, 0x0C) == (b"", 0x9000)
    assert select(d, AID_A, 0x04) == (b"\x6f\x00", 0x9000)


def test_select_errors_keep_selection(env):
    d, a, _ = env
    select(d, AID_A)
    assert select(d, bytes.fromhex("D276000124")) == (b"", 0x6A82)
    assert d.selected is a and a.deselects == 0
    assert tx(d, apdu.build(0, 0xA4, 0x00, 0x0C, b"\x3f\x00")) == (b"", 0x6A82)  # by FID: no MF
    assert select(d, AID_A, 0x02) == (b"", 0x6A86)
    assert tx(d, b"\x00\xa4\x04\x00") == (b"", 0x6700)  # no AID
    assert select(d, bytes(17)) == (b"", 0x6700)
    assert d.selected is a


def test_reselect_same_applet_keeps_state(env):
    d, a, _ = env
    select(d, AID_A)
    select(d, AID_A)
    assert a.deselects == 0


def test_select_warning_keeps_applet_selected():
    a = Dummy(AID_A, "a", select_sw=apdu.SW_FILE_TERMINATED, fci=b"")
    d = Dispatcher([a])
    assert select(d, AID_A) == (b"", 0x6285)
    assert d.selected is a
    assert tx(d, b"\x00\x01\x00\x00\x01\x55") == (b"\x55", 0x9000)


def test_select_failure_deselects_current():
    a = Dummy(AID_A, "a")
    d = Dispatcher([a])
    select(d, AID_A)
    a.select_sw = apdu.SW_CONDITIONS_NOT_SATISFIED
    assert select(d, AID_A)[1] == 0x6985
    assert d.selected is None and a.deselects == 1


def test_nothing_selected(env):
    d, _, _ = env
    assert tx(d, b"\x00\x84\x00\x00\x08") == (b"", 0x6D00)


def test_fallback_applet():
    a = Dummy(AID_A, "a")
    rng = Dummy(b"\xf0\x00\x00\x00\x01", "rng")
    d = Dispatcher([a], fallback=rng)
    assert tx(d, b"\x00\x01\x00\x00\x02\x01\x02") == (b"\x01\x02", 0x9000)
    assert len(rng.commands) == 1
    select(d, AID_A)
    tx(d, b"\x00\x01\x00\x00\x01\x09")
    assert len(rng.commands) == 1 and len(a.commands) == 1
    d.reset()
    assert rng.resets == 1


def test_public_rng_after_app_selection_preserves_selection():
    from feuristic.apps.card.aes.rng import RngApplet

    a = Dummy(AID_A, "a")
    d = Dispatcher([a], fallback=RngApplet())
    select(d, AID_A)
    data, sw = tx(d, b"\x00\x84\x00\x00\x20")
    assert sw == 0x9000 and len(data) == 32
    assert d.selected is a and a.deselects == 0
    assert tx(d, b"\x00\x84\x00\x00\x21") == (b"", 0x6C20)
    assert tx(d, b"\x00\x01\x00\x00\x01\x09") == (b"\x09", 0x9000)


# --- CLA / malformed -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("cla", "sw"),
    [
        (0x01, 0x6881),
        (0x03, 0x6881),
        (0x04, 0x6882),
        (0x08, 0x6882),
        (0x0C, 0x6882),
        (0x0D, 0x6881),
        (0x40, 0x6881),
        (0x7F, 0x6881),
        (0x20, 0x6E00),
        (0x3F, 0x6E00),
        (0xFF, 0x6E00),
        (0x84, 0x6882),
        (0x81, 0x6881),
    ],
)
def test_cla_checks(env, cla, sw):
    d, a, _ = env
    select(d, AID_A)
    assert tx(d, bytes((cla, 0x01, 0, 0, 1, 0x55))) == (b"", sw)
    assert a.commands == []


def test_proprietary_class_forwarded(env):
    d, a, _ = env
    select(d, AID_A)
    assert tx(d, b"\x80\x01\x00\x00\x01\x55") == (b"\x55", 0x9000)
    assert a.commands[-1].cla == 0x80


@pytest.mark.parametrize(
    "raw", [b"", b"\x00", b"\x00\x01\x00", b"\x00\x01\x00\x00\x05\x01", b"\x00\x01\x00\x00\x00\x00"]
)
def test_malformed_apdus(env, raw):
    d, _, _ = env
    select(d, AID_A)
    assert tx(d, raw) == (b"", 0x6700)


def test_unknown_ins_from_applet(env):
    d, _, _ = env
    select(d, AID_A)
    assert tx(d, b"\x00\x77\x00\x00") == (b"", 0x6D00)


# --- command chaining ----------------------------------------------------------------


def test_command_chaining(env):
    d, a, _ = env
    select(d, AID_A)
    assert tx(d, apdu.build(0x10, 0x01, 0, 0, b"\x01" * 200)) == (b"", 0x9000)
    assert tx(d, apdu.build(0x10, 0x01, 0, 0, b"\x02" * 200)) == (b"", 0x9000)
    data, sw = tx(d, apdu.build(0x00, 0x01, 0, 0, b"\x03" * 10, 256))
    assert len(a.commands) == 1
    c = a.commands[0]
    assert c.cla == 0x00 and len(c.data) == 410
    assert c.data == b"\x01" * 200 + b"\x02" * 200 + b"\x03" * 10
    assert data == c.data[:256] and sw == 0x6100 | (410 - 256)


def test_chaining_mismatch_aborts(env):
    d, a, _ = env
    select(d, AID_A)
    tx(d, apdu.build(0x10, 0x01, 0, 0, b"\x01"))
    assert tx(d, apdu.build(0x00, 0x02, 0, 0, b"\x01")) == (b"", 0x6883)
    assert a.commands == []
    # the chain is gone: a fresh command works
    assert tx(d, apdu.build(0x00, 0x01, 0, 0, b"\x07")) == (b"\x07", 0x9000)
    tx(d, apdu.build(0x10, 0x01, 0, 0, b"\x01"))
    assert tx(d, apdu.build(0x00, 0x01, 1, 0, b"\x01")) == (b"", 0x6883)  # P1 differs
    tx(d, apdu.build(0x10, 0x01, 0, 0, b"\x01"))
    assert tx(d, b"\x00\xc0\x00\x00\x00") == (b"", 0x6883)  # GET RESPONSE mid-chain
    tx(d, apdu.build(0x10, 0x01, 0, 0, b"\x01"))
    assert tx(d, apdu.build(0x00, 0xA4, 4, 0, AID_A))[1] == 0x6883


def test_chaining_overflow(env):
    d, _, _ = env
    select(d, AID_A)
    assert tx(d, apdu.build(0x10, 0x01, 0, 0, bytes(4000)))[1] == 0x9000
    assert tx(d, apdu.build(0x10, 0x01, 0, 0, bytes(200)))[1] == 0x6700
    assert tx(d, apdu.build(0x00, 0x01, 0, 0, bytes(1)))[1] == 0x9000  # chain dropped
    assert tx(d, apdu.build(0x10, 0x01, 0, 0, bytes(4097)))[1] == 0x6700


def test_oversized_extended_command(env):
    d, _, _ = env
    select(d, AID_A)
    assert tx(d, apdu.build(0x00, 0x01, 0, 0, bytes(4097)))[1] == 0x6700
    data, sw = tx(d, apdu.build(0x00, 0x01, 0, 0, bytes(4096), 65536))
    assert sw == 0x9000 and len(data) == 4096


# --- response chaining -----------------------------------------------------------------


def test_get_response_flow(env):
    d, _, _ = env
    select(d, AID_A)
    data, sw = tx(d, b"\x00\x02\x02\x58\x00")  # 600 bytes, Le=00
    assert len(data) == 256 and sw == 0x6100  # >= 256 remaining
    got = data
    data, sw = tx(d, b"\x00\xc0\x00\x00\x00")
    assert len(data) == 256 and sw == 0x6100 | 88
    got += data
    data, sw = tx(d, b"\x00\xc0\x00\x00\x40")  # smaller Le
    assert len(data) == 64 and sw == 0x6100 | 24
    got += data
    data, sw = tx(d, b"\x00\xc0\x00\x00\x00")
    assert len(data) == 24 and sw == 0x9000
    got += data
    assert got == bytes(i & 0xFF for i in range(600))
    assert tx(d, b"\x00\xc0\x00\x00\x00") == (b"", 0x6985)


def test_get_response_final_sw_preserved(env):
    d, _, _ = env
    select(d, AID_A)
    data, sw = tx(d, b"\x00\x05\x01\x00\x80")  # 256 bytes + 6282, Le=128
    assert len(data) == 128 and sw == 0x6180
    data, sw = tx(d, b"\x00\xc0\x00\x00\x00")
    assert len(data) == 128 and sw == 0x6282


def test_get_response_errors_and_drop(env):
    d, _, _ = env
    select(d, AID_A)
    tx(d, b"\x00\x02\x02\x00\x00")
    assert tx(d, b"\x00\xc0\x01\x00\x00") == (b"", 0x6A86)
    assert tx(d, b"\x00\xc0\x00\x00\x00") == (b"", 0x6985)  # dropped by the error
    tx(d, b"\x00\x02\x02\x00\x00")
    tx(d, b"\x00\x01\x00\x00\x01\x55")  # any other command drops the rest
    assert tx(d, b"\x00\xc0\x00\x00\x00") == (b"", 0x6985)
    tx(d, b"\x00\x02\x02\x00\x00")
    assert tx(d, b"\x00\xc0\x00\x00\x01\x00\x00")[1] == 0x6700


def test_le_absent_means_256(env):
    d, _, _ = env
    select(d, AID_A)
    data, sw = tx(d, b"\x00\x02\x01\x40")  # case 1, 320 bytes available
    assert len(data) == 256 and sw == 0x6140


def test_exact_le(env):
    d, _, _ = env
    select(d, AID_A)
    data, sw = tx(d, b"\x00\x02\x00\x10\x10")
    assert len(data) == 16 and sw == 0x9000


def test_extended_le_returns_everything(env):
    d, _, _ = env
    select(d, AID_A)
    data, sw = tx(d, b"\x00\x02\x09\x00\x00\x00\x00")  # Le=0000 → 65536
    assert len(data) == 0x900 and sw == 0x9000
    data, sw = tx(d, b"\x00\x02\x09\x00\x00\x01\x00")  # Le=0100 → 256
    assert len(data) == 256 and sw == 0x6100
    data, sw = tx(d, b"\x00\xc0\x00\x00\x00\x08\x00")  # extended GET RESPONSE
    assert len(data) == 0x800 and sw == 0x9000


def test_extended_case3_without_le(env):
    d, _, _ = env
    select(d, AID_A)
    data, sw = tx(d, b"\x00\x02\x05\x00\x00\x00\x01\x00")
    assert len(data) == 0x500 and sw == 0x9000


def test_none_response_is_9000(env):
    d, _, _ = env
    select(d, AID_A)
    assert tx(d, b"\x00\x04\x00\x00") == (b"", 0x9000)


# --- reset / errors ------------------------------------------------------------------------


def test_reset(env):
    d, a, b = env
    select(d, AID_A)
    tx(d, b"\x00\x02\x02\x00\x00")
    tx(d, apdu.build(0x10, 0x01, 0, 0, b"\x01"))
    d.reset()
    assert d.selected is None and a.resets == 1 and b.resets == 1
    assert tx(d, b"\x00\xc0\x00\x00\x00") == (b"", 0x6985)  # pending response dropped
    assert tx(d, b"\x00\x01\x00\x00\x01\x01") == (b"", 0x6D00)  # nothing selected, chain dropped


@pytest.mark.parametrize(
    ("exc", "sw"),
    [
        (apdu.ApduError(0x6A88), 0x6A88),
        (InvalidInput("x"), 0x6A80),
        (UserCancelled(), 0x6985),
        (UserTimeout(), 0x6985),
        (StorageFull(), 0x6A84),
        (PinBlocked(), 0x6983),
    ],
)
def test_error_mapping(env, exc, sw):
    d, a, _ = env
    select(d, AID_A)
    a.error = exc
    assert tx(d, b"\x00\x03\x00\x00") == (b"", sw)


def test_unexpected_exception(env):
    d, a, _ = env
    select(d, AID_A)
    a.error = ZeroDivisionError()
    with pytest.raises(ZeroDivisionError):
        tx(d, b"\x00\x03\x00\x00")
    d.raise_unexpected = False
    assert tx(d, b"\x00\x03\x00\x00") == (b"", 0x6F00)
