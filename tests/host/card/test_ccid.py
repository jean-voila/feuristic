# SPDX-License-Identifier: GPL-3.0-only
"""CCID Rev 1.1 message layer: framing, commands, status codes, chaining, WTX."""

import pytest

from feuristic.apps.card import ccid
from feuristic.apps.card.ccid import build_command as cmd

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def hdr(msg):
    """Decode an RDR_to_PC message header."""
    return {
        "type": msg[0],
        "len": int.from_bytes(msg[1:5], "little"),
        "slot": msg[5],
        "seq": msg[6],
        "status": msg[7],
        "error": msg[8],
        "specific": msg[9],
        "data": msg[10:],
    }


def split(message, size=64):
    return [message[i : i + size] for i in range(0, len(message), size)] or [b""]


class Resets:
    def __init__(self):
        self.calls = []

    def __call__(self, powered):
        self.calls.append(powered)


@pytest.fixture
def slot():
    return ccid.CcidSlot(on_reset=Resets())


def feed_all(s, message):
    out = []
    for p in split(message):
        out.extend(s.feed(p))
    return out


def power_on(s, seq=0):
    (rsp,) = s.handle(ccid.parse_message(cmd(ccid.PC_TO_RDR_ICC_POWER_ON, seq)))
    return rsp


# ---------------------------------------------------------------------------
# ATR, descriptor, packets
# ---------------------------------------------------------------------------


def test_atr_structure_and_tck():
    atr = ccid.atr()
    assert atr[0] == 0x3B  # direct convention
    t0 = atr[1]
    k = t0 & 0x0F
    assert k == len(ccid.HISTORICAL_BYTES)
    # walk the interface bytes (ISO 7816-3 §8.2.3)
    pos = 2
    y = t0 >> 4
    protocols = []
    tds = []
    while True:
        for bit in (1, 2, 4):  # TA, TB, TC
            if y & bit:
                pos += 1
        if not y & 8:
            break
        td = atr[pos]
        pos += 1
        tds.append(td)
        protocols.append(td & 0x0F)
        y = td >> 4
    assert protocols[:2] == [1, 1]  # T=1 offered
    assert 15 in protocols
    assert atr[pos : pos + k] == ccid.HISTORICAL_BYTES
    assert len(atr) == pos + k + 1  # TCK present
    x = 0
    for b in atr[1:]:
        x ^= b
    assert x == 0  # TCK makes the XOR of T0..TCK zero
    assert len(atr) <= 33


def test_historical_bytes_advertise_extended_length_and_chaining():
    h = ccid.HISTORICAL_BYTES
    assert h[0] == 0x00  # category indicator, status in the last 3 bytes
    i = h.index(0x73)  # card capabilities (compact TLV tag 7, len 3)
    caps = h[i + 1 : i + 4]
    assert caps[2] & 0x40  # extended Lc/Le
    assert caps[2] & 0x80  # command chaining
    assert caps[2] & 0x07 == 0  # no logical channels
    assert caps[0] & 0xC0 == 0xC0  # selection by full/partial DF name
    assert h[-3:] == b"\x05\x90\x00"


def test_class_descriptor_mirrors_constants():
    raw = ccid.class_descriptor_bytes()
    assert len(raw) == 54 == raw[0]
    assert raw[1] == 0x21
    assert raw[2:4] == b"\x10\x01"  # bcdCCID 1.10
    assert raw[4] == 0  # bMaxSlotIndex
    fields = {name: value for name, _size, value in ccid.class_descriptor()}
    assert fields["dwProtocols"] == 2  # T=1
    assert fields["dwFeatures"] == 0x000400FE
    assert fields["dwMaxCCIDMessageLength"] == 4096 + 10
    assert fields["bClassGetResponse"] == 0xFF
    assert fields["bClassEnvelope"] == 0xFF
    assert fields["wLcdLayout"] == 0
    assert fields["bPINSupport"] == 0
    assert fields["bMaxCCIDBusySlots"] == 1
    assert fields["dwMaxIFSD"] == 254
    assert sum(size for _n, size, _v in ccid.class_descriptor()) == 54
    # dwMaxCCIDMessageLength at offset 44 (little-endian)
    assert int.from_bytes(raw[44:48], "little") == ccid.MAX_MESSAGE_LENGTH
    assert int.from_bytes(raw[40:44], "little") == ccid.FEATURES


@pytest.mark.parametrize(
    ("n", "packets", "zlp"),
    [(10, 1, False), (63, 1, False), (64, 2, True), (65, 2, False), (128, 3, True), (4106, 65, False)],
)
def test_packetize(n, packets, zlp):
    msg = bytes(range(256)) * 17
    msg = msg[:n]
    out = ccid.packetize(msg)
    assert len(out) == packets
    assert (out[-1] == b"") == zlp
    assert b"".join(out) == msg
    assert all(len(p) <= 64 for p in out)


def test_notify_slot_change():
    assert ccid.notify_slot_change() == b"\x50\x03"
    assert ccid.notify_slot_change(True, False) == b"\x50\x01"
    assert ccid.notify_slot_change(False, True) == b"\x50\x02"


# ---------------------------------------------------------------------------
# assembler
# ---------------------------------------------------------------------------


def test_assembler_single_and_multi_packet():
    a = ccid.Assembler()
    m = a.feed(cmd(ccid.PC_TO_RDR_GET_SLOT_STATUS, 7))
    assert isinstance(m, ccid.Message) and m.seq == 7 and m.data == b""
    big = cmd(ccid.PC_TO_RDR_XFR_BLOCK, 9, bytes(range(200)))
    parts = split(big)
    assert len(parts) == 4
    for p in parts[:-1]:
        assert a.feed(p) is None
    m = a.feed(parts[-1])
    assert m.data == bytes(range(200)) and m.seq == 9


def test_assembler_exact_multiple_of_64_needs_no_zlp():
    a = ccid.Assembler()
    msg = cmd(ccid.PC_TO_RDR_XFR_BLOCK, 1, bytes(54 + 64))  # 128 bytes
    assert a.feed(msg[:64]) is None
    m = a.feed(msg[64:])
    assert isinstance(m, ccid.Message) and len(m.data) == 118
    assert a.idle
    assert a.feed(b"") is None  # a trailing host ZLP is ignored


def test_assembler_whole_message_datagram():
    a = ccid.Assembler()
    msg = cmd(ccid.PC_TO_RDR_XFR_BLOCK, 3, bytes(1000))
    m = a.feed(msg)
    assert isinstance(m, ccid.Message) and len(m.data) == 1000


def test_assembler_oversized_length_discards_rest_of_transfer():
    a = ccid.Assembler()
    header = bytes((0x6F,)) + (5000).to_bytes(4, "little") + bytes((0, 4, 0, 0, 0))
    first = header + bytes(54)
    r = a.feed(first)
    assert isinstance(r, ccid.FramingError) and r.error == 1 and r.seq == 4
    assert a.feed(bytes(64)) is None
    assert a.feed(bytes(64)) is None
    assert a.feed(bytes(10)) is None  # short packet ends the bad transfer
    assert a.idle
    assert isinstance(a.feed(cmd(ccid.PC_TO_RDR_GET_SLOT_STATUS, 5)), ccid.Message)


def test_assembler_huge_length_in_short_packet():
    a = ccid.Assembler()
    header = bytes((0x6F,)) + (0xFFFFFFFF).to_bytes(4, "little") + bytes((0, 4, 0, 0, 0))
    r = a.feed(header)
    assert isinstance(r, ccid.FramingError)
    assert a.idle


def test_assembler_truncated_transfer():
    a = ccid.Assembler()
    msg = cmd(ccid.PC_TO_RDR_XFR_BLOCK, 2, bytes(100))
    assert a.feed(msg[:64]) is None
    r = a.feed(msg[64:80])  # short packet but dwLength not reached
    assert isinstance(r, ccid.FramingError) and r.seq == 2
    assert a.idle


def test_assembler_extra_bytes_rejected():
    a = ccid.Assembler()
    msg = cmd(ccid.PC_TO_RDR_XFR_BLOCK, 2, bytes(5)) + b"\x00\x00"
    r = a.feed(msg)
    assert isinstance(r, ccid.FramingError)
    assert a.idle


def test_assembler_drops_runt_header():
    a = ccid.Assembler()
    assert a.feed(b"\x65\x00\x00") is None
    assert a.idle


# ---------------------------------------------------------------------------
# slot commands
# ---------------------------------------------------------------------------


def test_power_on_returns_atr_and_resets(slot):
    h = hdr(power_on(slot, seq=0x42))
    assert h["type"] == ccid.RDR_TO_PC_DATA_BLOCK
    assert h["seq"] == 0x42 and h["slot"] == 0
    assert h["status"] == 0x00 and h["error"] == 0
    assert h["data"] == ccid.atr() and h["len"] == len(ccid.atr())
    assert slot.on_reset.calls == [True]
    # warm reset
    power_on(slot, seq=0x43)
    assert slot.on_reset.calls == [True, True]


def test_power_on_bad_voltage_and_data(slot):
    (r,) = feed_all(slot, cmd(ccid.PC_TO_RDR_ICC_POWER_ON, 1, b7=4))
    h = hdr(r)
    assert h["status"] == 0x41 and h["error"] == 7
    (r,) = feed_all(slot, cmd(ccid.PC_TO_RDR_ICC_POWER_ON, 2, b"\x00"))
    assert hdr(r)["error"] == 1
    for v in (0, 1, 2, 3):
        (r,) = feed_all(slot, cmd(ccid.PC_TO_RDR_ICC_POWER_ON, 3, b7=v))
        assert hdr(r)["status"] == 0


def test_slot_status_and_power_off(slot):
    (r,) = feed_all(slot, cmd(ccid.PC_TO_RDR_GET_SLOT_STATUS, 1))
    h = hdr(r)
    assert h["type"] == ccid.RDR_TO_PC_SLOT_STATUS and h["status"] == ccid.ICC_INACTIVE
    power_on(slot)
    (r,) = feed_all(slot, cmd(ccid.PC_TO_RDR_GET_SLOT_STATUS, 2))
    assert hdr(r)["status"] == ccid.ICC_ACTIVE
    (r,) = feed_all(slot, cmd(ccid.PC_TO_RDR_ICC_POWER_OFF, 3))
    h = hdr(r)
    assert h["type"] == ccid.RDR_TO_PC_SLOT_STATUS and h["status"] == ccid.ICC_INACTIVE and h["seq"] == 3
    assert slot.on_reset.calls == [True, False]
    # power off twice: no second reset callback
    feed_all(slot, cmd(ccid.PC_TO_RDR_ICC_POWER_OFF, 4))
    assert slot.on_reset.calls == [True, False]


def test_xfr_block_when_unpowered_is_mute(slot):
    (r,) = feed_all(slot, cmd(ccid.PC_TO_RDR_XFR_BLOCK, 9, b"\x00\xa4\x04\x00"))
    h = hdr(r)
    assert h["type"] == ccid.RDR_TO_PC_DATA_BLOCK
    assert h["status"] == 0x41 and h["error"] == ccid.ERR_ICC_MUTE and h["seq"] == 9
    assert slot.pending is None


def test_bad_slot(slot):
    (r,) = feed_all(slot, cmd(ccid.PC_TO_RDR_GET_SLOT_STATUS, 1, slot=1))
    h = hdr(r)
    assert h["slot"] == 1 and h["status"] == 0x42 and h["error"] == 5
    (r,) = feed_all(slot, cmd(ccid.PC_TO_RDR_XFR_BLOCK, 2, b"\x00" * 4, slot=3))
    h = hdr(r)
    assert h["type"] == ccid.RDR_TO_PC_DATA_BLOCK and h["error"] == 5


@pytest.mark.parametrize(
    ("mtype", "rtype"),
    [
        (ccid.PC_TO_RDR_ESCAPE, ccid.RDR_TO_PC_ESCAPE),
        (ccid.PC_TO_RDR_ICC_CLOCK, ccid.RDR_TO_PC_SLOT_STATUS),
        (ccid.PC_TO_RDR_T0_APDU, ccid.RDR_TO_PC_SLOT_STATUS),
        (ccid.PC_TO_RDR_SECURE, ccid.RDR_TO_PC_DATA_BLOCK),
        (ccid.PC_TO_RDR_MECHANICAL, ccid.RDR_TO_PC_SLOT_STATUS),
        (0x99, ccid.RDR_TO_PC_SLOT_STATUS),
        (0x00, ccid.RDR_TO_PC_SLOT_STATUS),
    ],
)
def test_unsupported_commands(slot, mtype, rtype):
    power_on(slot)
    (r,) = feed_all(slot, cmd(mtype, 0x11, b"\x01\x02"))
    h = hdr(r)
    assert h["type"] == rtype and h["seq"] == 0x11
    assert h["status"] == 0x40 and h["error"] == ccid.ERR_CMD_NOT_SUPPORTED


def test_parameters(slot):
    (r,) = feed_all(slot, cmd(ccid.PC_TO_RDR_GET_PARAMETERS, 1))
    h = hdr(r)
    assert h["type"] == ccid.RDR_TO_PC_PARAMETERS and h["specific"] == 1
    assert h["data"] == ccid.DEFAULT_T1_PARAMETERS
    new = bytes((0x11, 0x10, 0xFF, 0x45, 0x00, 0x80, 0x00))
    (r,) = feed_all(slot, cmd(ccid.PC_TO_RDR_SET_PARAMETERS, 2, new, b7=1))
    h = hdr(r)
    assert h["status"] == ccid.ICC_INACTIVE and h["error"] == 0 and h["data"] == new
    (r,) = feed_all(slot, cmd(ccid.PC_TO_RDR_GET_PARAMETERS, 3))
    assert hdr(r)["data"] == new
    (r,) = feed_all(slot, cmd(ccid.PC_TO_RDR_RESET_PARAMETERS, 4))
    assert hdr(r)["data"] == ccid.DEFAULT_T1_PARAMETERS


@pytest.mark.parametrize(
    ("data", "b7", "err"),
    [
        (bytes(5), 0, 7),  # T=0 not supported
        (bytes(6), 1, 1),  # wrong length
        (bytes((0x11, 0x12, 0xFF, 0x75, 0, 0xFE, 0)), 1, 11),  # bmTCCKST1
        (bytes((0x11, 0x10, 0xFF, 0xA5, 0, 0xFE, 0)), 1, 13),  # BWI 10
        (bytes((0x11, 0x10, 0xFF, 0x75, 3, 0xFE, 0)), 1, 14),  # clock stop
        (bytes((0x11, 0x10, 0xFF, 0x75, 0, 0xFF, 0)), 1, 15),  # IFSC 255
        (bytes((0x11, 0x10, 0xFF, 0x75, 0, 0x00, 0)), 1, 15),  # IFSC 0
        (bytes((0x11, 0x10, 0xFF, 0x75, 0, 0xFE, 1)), 1, 16),  # NAD
    ],
)
def test_set_parameters_rejections(slot, data, b7, err):
    (r,) = feed_all(slot, cmd(ccid.PC_TO_RDR_SET_PARAMETERS, 5, data, b7=b7))
    h = hdr(r)
    assert h["type"] == ccid.RDR_TO_PC_PARAMETERS
    assert h["status"] & 0xC0 == 0x40 and h["error"] == err
    assert slot.parameters == bytearray(ccid.DEFAULT_T1_PARAMETERS)


def test_set_data_rate_and_clock(slot):
    (r,) = feed_all(slot, cmd(ccid.PC_TO_RDR_SET_DATA_RATE_AND_CLOCK, 6, bytes(8)))
    h = hdr(r)
    assert h["type"] == ccid.RDR_TO_PC_DATA_RATE_AND_CLOCK and h["status"] == ccid.ICC_INACTIVE
    assert int.from_bytes(h["data"][:4], "little") == ccid.DEFAULT_CLOCK_KHZ
    assert int.from_bytes(h["data"][4:], "little") == ccid.DATA_RATE_BPS
    (r,) = feed_all(slot, cmd(ccid.PC_TO_RDR_SET_DATA_RATE_AND_CLOCK, 7, bytes(4)))
    assert hdr(r)["error"] == 1


def test_framing_error_answered_with_right_type(slot):
    header = (
        bytes((ccid.PC_TO_RDR_GET_PARAMETERS,)) + (9000).to_bytes(4, "little") + bytes((0, 0x33, 0, 0, 0))
    )
    (r,) = slot.feed(header)
    h = hdr(r)
    assert h["type"] == ccid.RDR_TO_PC_PARAMETERS and h["seq"] == 0x33 and h["error"] == 1


# ---------------------------------------------------------------------------
# XfrBlock, busy, WTX, abort
# ---------------------------------------------------------------------------


def test_xfr_block_pending_and_complete(slot):
    power_on(slot)
    assert feed_all(slot, cmd(ccid.PC_TO_RDR_XFR_BLOCK, 0x20, b"\x00\xca\x00\x4f\x00")) == []
    assert slot.pending.seq == 0x20 and slot.pending.apdu == b"\x00\xca\x00\x4f\x00"
    (r,) = slot.complete(b"\x01\x02\x90\x00")
    h = hdr(r)
    assert h["type"] == ccid.RDR_TO_PC_DATA_BLOCK and h["seq"] == 0x20
    assert h["status"] == 0 and h["specific"] == 0 and h["data"] == b"\x01\x02\x90\x00"
    assert slot.pending is None
    assert slot.complete(b"\x90\x00") == []  # nothing pending


def test_busy_and_time_extension(slot):
    power_on(slot)
    feed_all(slot, cmd(ccid.PC_TO_RDR_XFR_BLOCK, 5, b"\x00\x2a\x9e\x9a\x01\x00"))
    (w,) = slot.time_extension()
    h = hdr(w)
    assert h["type"] == ccid.RDR_TO_PC_DATA_BLOCK and h["seq"] == 5
    assert h["status"] == 0x80 and h["error"] == ccid.WTX_MULTIPLIER and h["len"] == 0
    for t, rt in (
        (ccid.PC_TO_RDR_GET_SLOT_STATUS, ccid.RDR_TO_PC_SLOT_STATUS),
        (ccid.PC_TO_RDR_XFR_BLOCK, ccid.RDR_TO_PC_DATA_BLOCK),
        (ccid.PC_TO_RDR_ICC_POWER_OFF, ccid.RDR_TO_PC_SLOT_STATUS),
        (ccid.PC_TO_RDR_GET_PARAMETERS, ccid.RDR_TO_PC_PARAMETERS),
    ):
        (r,) = feed_all(slot, cmd(t, 6, b"\x00\x00\x00\x00" if t == ccid.PC_TO_RDR_XFR_BLOCK else b""))
        hh = hdr(r)
        assert hh["type"] == rt and hh["seq"] == 6
        assert hh["status"] == 0x40 and hh["error"] == ccid.ERR_CMD_SLOT_BUSY
    assert slot.powered and slot.pending.seq == 5
    (r,) = slot.complete(b"\x90\x00")
    assert hdr(r)["seq"] == 5
    assert slot.time_extension() == []


def test_abort_pending(slot):
    power_on(slot)
    feed_all(slot, cmd(ccid.PC_TO_RDR_XFR_BLOCK, 5, b"\x00\x2a\x9e\x9a\x01\x00"))
    pending = slot.pending
    slot.control_abort(0, 9)
    r1, r2 = feed_all(slot, cmd(ccid.PC_TO_RDR_ABORT, 9))
    h1, h2 = hdr(r1), hdr(r2)
    assert h1["type"] == ccid.RDR_TO_PC_DATA_BLOCK and h1["seq"] == 5
    assert h1["status"] == 0x40 and h1["error"] == ccid.ERR_CMD_ABORTED
    assert h2["type"] == ccid.RDR_TO_PC_SLOT_STATUS and h2["seq"] == 9 and h2["status"] == 0
    assert pending.aborted and slot.pending is None
    assert slot.time_extension() == []


def test_abort_idle(slot):
    (r,) = feed_all(slot, cmd(ccid.PC_TO_RDR_ABORT, 1))
    h = hdr(r)
    assert h["type"] == ccid.RDR_TO_PC_SLOT_STATUS and h["status"] == ccid.ICC_INACTIVE


def test_power_cycle_aborts_pending(slot):
    power_on(slot)
    feed_all(slot, cmd(ccid.PC_TO_RDR_XFR_BLOCK, 5, b"\x00\x00\x00\x00"))
    p = slot.pending
    slot.power_cycle(False)
    assert p.aborted and slot.pending is None and not slot.powered
    assert slot.on_reset.calls[-1] is False


def test_xfr_command_chaining(slot):
    power_on(slot)
    apdu = b"\x00\xda\x7f\x21\x00\x13\x00" + bytes(range(256)) * 19 + bytes(36)  # 4907 bytes? keep bounded
    apdu = apdu[: ccid.MAX_APDU_LENGTH]
    parts = [apdu[:4096], apdu[4096:4100], apdu[4100:]]
    (r,) = feed_all(slot, cmd(ccid.PC_TO_RDR_XFR_BLOCK, 1, parts[0], b8=0x01))
    h = hdr(r)
    assert h["specific"] == 0x10 and h["status"] == 0 and h["len"] == 0
    (r,) = feed_all(slot, cmd(ccid.PC_TO_RDR_XFR_BLOCK, 2, parts[1], b8=0x03))
    assert hdr(r)["specific"] == 0x10
    assert feed_all(slot, cmd(ccid.PC_TO_RDR_XFR_BLOCK, 3, parts[2], b8=0x02)) == []
    assert slot.pending.apdu == apdu and slot.pending.seq == 3


def test_xfr_chaining_errors(slot):
    power_on(slot)
    # continuation without a beginning
    (r,) = feed_all(slot, cmd(ccid.PC_TO_RDR_XFR_BLOCK, 1, b"\x00", b8=0x02))
    assert hdr(r)["error"] == 8
    (r,) = feed_all(slot, cmd(ccid.PC_TO_RDR_XFR_BLOCK, 1, b"\x00", b8=0x03))
    assert hdr(r)["error"] == 8
    # unknown level
    (r,) = feed_all(slot, cmd(ccid.PC_TO_RDR_XFR_BLOCK, 1, b"\x00", b8=0x04))
    assert hdr(r)["error"] == 8
    # new complete APDU while a chain is open
    feed_all(slot, cmd(ccid.PC_TO_RDR_XFR_BLOCK, 2, b"\x00" * 10, b8=0x01))
    (r,) = feed_all(slot, cmd(ccid.PC_TO_RDR_XFR_BLOCK, 3, b"\x00" * 4))
    assert hdr(r)["error"] == 8
    assert slot.pending is None
    # overflow
    feed_all(slot, cmd(ccid.PC_TO_RDR_XFR_BLOCK, 4, bytes(4096), b8=0x01))
    (r,) = feed_all(slot, cmd(ccid.PC_TO_RDR_XFR_BLOCK, 5, bytes(4096), b8=0x02))
    assert hdr(r)["error"] == 1
    # response continuation without chained response
    (r,) = feed_all(slot, cmd(ccid.PC_TO_RDR_XFR_BLOCK, 6, b"", b8=0x10, b9=0x00))
    assert hdr(r)["error"] == 8


def test_xfr_response_chaining(slot):
    power_on(slot)
    feed_all(slot, cmd(ccid.PC_TO_RDR_XFR_BLOCK, 1, b"\x00\xca\x7f\x21\x00\x00\x00"))
    response = bytes(range(256)) * 40 + b"\x90\x00"  # 10242 bytes
    (r,) = slot.complete(response)
    h = hdr(r)
    assert h["specific"] == 0x01 and len(h["data"]) == 4096
    got = h["data"]
    (r,) = feed_all(slot, cmd(ccid.PC_TO_RDR_XFR_BLOCK, 2, b"", b8=0x10))
    h = hdr(r)
    assert h["specific"] == 0x03 and h["seq"] == 2
    got += h["data"]
    (r,) = feed_all(slot, cmd(ccid.PC_TO_RDR_XFR_BLOCK, 3, b"", b8=0x10))
    h = hdr(r)
    assert h["specific"] == 0x02
    got += h["data"]
    assert got == response
    (r,) = feed_all(slot, cmd(ccid.PC_TO_RDR_XFR_BLOCK, 4, b"", b8=0x10))
    assert hdr(r)["error"] == 8


def test_parse_message():
    m = ccid.parse_message(cmd(ccid.PC_TO_RDR_XFR_BLOCK, 3, b"abc", b7=1, b8=2, b9=3))
    assert (m.msg_type, m.seq, m.b7, m.level, m.data) == (0x6F, 3, 1, 0x0302, b"abc")
    from feuristic.core.errors import InvalidInput

    with pytest.raises(InvalidInput):
        ccid.parse_message(b"\x6f\x00")
    with pytest.raises(InvalidInput):
        ccid.parse_message(cmd(ccid.PC_TO_RDR_XFR_BLOCK, 3, b"abc") + b"x")
