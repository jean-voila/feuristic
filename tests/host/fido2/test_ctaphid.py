# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""CTAPHID framing, channels, busy/timeout/cancel handling (CTAP 2.1 §11.2)."""

import threading

import pytest
from ctap_harness import (
    CDH,
    Device,
    SimUI,
    allocate_channel,
    cont_packet,
    frames,
    init_packet,
    make,
    open_hid,
    parse_response,
)
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2

from feuristic.apps.fido2 import ctaphid as hidmod

BCAST = 0xFFFFFFFF


def send(device, cid, cmd, data=b""):
    for p in frames(cid, cmd, data):
        device.write(p)
    return device.read_all()


def error_of(packets, cid):
    rcid, cmd, data = parse_response(packets)
    assert rcid == cid
    assert cmd == hidmod.CMD_ERROR, (cmd, data)
    return data[0]


def test_init_allocates_channels(device):
    a = allocate_channel(device)
    b = allocate_channel(device, b"abcdefgh")
    assert a != b and a not in (0, BCAST)
    device.write(init_packet(BCAST, hidmod.CMD_INIT, b"nonce123"))
    pkt = device.read()
    assert pkt[4] == 0x86 and pkt[5:7] == b"\x00\x11"
    assert pkt[19:24] == bytes((2, 0, 1, 0, hidmod.CAP_CBOR | hidmod.CAP_WINK))
    assert not pkt[23] & hidmod.CAP_NMSG and not pkt[23] & hidmod.CAP_LOCK


def test_capabilities_without_wink():
    dev = Device(SimUI(), wink=False)
    dev.write(init_packet(BCAST, hidmod.CMD_INIT, b"12345678"))
    assert dev.read()[23] == hidmod.CAP_CBOR
    cid = allocate_channel(dev)
    assert error_of(send(dev, cid, hidmod.CMD_WINK), cid) == 0x01


def test_init_errors(device):
    assert error_of(send(device, BCAST, hidmod.CMD_INIT, b"short"), BCAST) == 0x03
    assert error_of(send(device, 0, hidmod.CMD_INIT, b"12345678"), 0) == 0x0B
    assert error_of(send(device, 0x1234, hidmod.CMD_INIT, b"12345678"), 0x1234) == 0x0B


def test_invalid_channels(device):
    assert error_of(send(device, BCAST, hidmod.CMD_PING, b"x"), BCAST) == 0x0B
    assert error_of(send(device, 0, hidmod.CMD_PING, b"x"), 0) == 0x0B
    assert error_of(send(device, 0xDEADBEEF, hidmod.CMD_PING, b"x"), 0xDEADBEEF) == 0x0B


@pytest.mark.parametrize("size", [0, 1, 57, 58, 116, 117, 1000, 7609])
def test_ping_echo(device, size):
    cid = allocate_channel(device)
    data = bytes(i & 0xFF for i in range(size))
    out = send(device, cid, hidmod.CMD_PING, data)
    assert parse_response(out) == (cid, hidmod.CMD_PING, data)
    assert all(len(p) == 64 for p in out)


def test_python_fido2_ping_and_wink(device, hid):
    assert hid.ping(b"hello" * 300) == b"hello" * 300
    hid.wink()
    assert device.server.take_wink() is True
    assert device.server.take_wink() is False


def test_oversized_message(device):
    cid = allocate_channel(device)
    device.write(init_packet(cid, hidmod.CMD_PING, b"x" * 57, bcnt=7610))
    assert error_of(device.read_all(), cid) == 0x03


def test_bad_sequence(device):
    cid = allocate_channel(device)
    device.write(init_packet(cid, hidmod.CMD_PING, b"a" * 57, bcnt=200))
    device.write(cont_packet(cid, 0, b"b" * 59))
    device.write(cont_packet(cid, 2, b"c" * 59))
    assert error_of(device.read_all(), cid) == 0x04
    # channel usable again
    assert parse_response(send(device, cid, hidmod.CMD_PING, b"ok"))[2] == b"ok"


def test_continuation_timeout(device):
    cid = allocate_channel(device)
    device.write(init_packet(cid, hidmod.CMD_PING, b"a" * 57, bcnt=100))
    device.advance(499)
    assert device.read_all() == []
    device.advance(1)
    assert error_of(device.read_all(), cid) == 0x05
    device.write(cont_packet(cid, 0, b"late"))  # ignored now
    assert device.read_all() == []


def test_busy_while_assembling(device):
    a = allocate_channel(device)
    b = allocate_channel(device, b"bbbbbbbb")
    device.write(init_packet(a, hidmod.CMD_PING, b"a" * 57, bcnt=100))
    device.write(init_packet(b, hidmod.CMD_PING, b"x"))
    assert error_of(device.read_all(), b) == 0x06
    device.write(cont_packet(b, 0, b"ignored"))
    device.write(init_packet(b, hidmod.CMD_CANCEL))  # cancel from another channel: ignored
    assert device.read_all() == []
    device.write(cont_packet(a, 0, b"b" * 59))
    rcid, cmd, data = parse_response(device.read_all())
    assert (rcid, cmd, data) == (a, hidmod.CMD_PING, b"a" * 57 + b"b" * 43)


def test_same_channel_init_packet_during_assembly(device):
    a = allocate_channel(device)
    device.write(init_packet(a, hidmod.CMD_PING, b"a" * 57, bcnt=100))
    device.write(init_packet(a, hidmod.CMD_PING, b"again"))
    assert error_of(device.read_all(), a) == 0x04
    device.write(init_packet(a, hidmod.CMD_PING, b"a" * 57, bcnt=100))
    device.write(init_packet(a, hidmod.CMD_CANCEL))  # aborts silently
    assert device.read_all() == []


def test_init_resync_during_assembly(device):
    a = allocate_channel(device)
    device.write(init_packet(a, hidmod.CMD_PING, b"a" * 57, bcnt=100))
    device.write(init_packet(a, hidmod.CMD_INIT, b"resync!!"))
    out = device.read_all()
    assert len(out) == 1 and out[0][4] == 0x86 and out[0][15:19] == a.to_bytes(4, "big")
    device.write(cont_packet(a, 0, b"b" * 59))
    assert device.read_all() == []  # the aborted message is gone


def test_init_from_other_channel_while_busy(device):
    a = allocate_channel(device)
    device.write(init_packet(a, hidmod.CMD_PING, b"a" * 57, bcnt=100))
    device.write(init_packet(BCAST, hidmod.CMD_INIT, b"newchan!"))
    out = device.read_all()
    assert out[0][4] == 0x86
    device.write(cont_packet(a, 0, b"b" * 59))
    assert parse_response(device.read_all())[0] == a


def test_spurious_and_malformed_packets(device):
    cid = allocate_channel(device)
    device.write(cont_packet(cid, 0, b"x"))
    device.write(b"\x00\x01")  # too short
    device.write(b"\x00" * 65)  # too long
    assert device.read_all() == []
    short = cid.to_bytes(4, "big") + bytes((0x81, 0, 2)) + b"hi"  # zero padded
    device.write(short)
    assert parse_response(device.read_all())[2] == b"hi"


@pytest.mark.parametrize("cmd", [hidmod.CMD_LOCK, hidmod.CMD_KEEPALIVE, hidmod.CMD_ERROR, 0x40, 0x7F, 0x12])
def test_unsupported_commands(device, cmd):
    cid = allocate_channel(device)
    assert error_of(send(device, cid, cmd, b"\x05"), cid) == 0x01


def test_cbor_and_wink_lengths(device):
    cid = allocate_channel(device)
    assert error_of(send(device, cid, hidmod.CMD_CBOR, b""), cid) == 0x03
    assert error_of(send(device, cid, hidmod.CMD_WINK, b"x"), cid) == 0x03
    assert send(device, cid, hidmod.CMD_CANCEL) == []  # idle cancel ignored


def test_keepalive_busy_and_completion():
    ui = SimUI([("wait", 450, True)])
    dev = Device(ui)
    a = allocate_channel(dev)
    b = allocate_channel(dev, b"bbbbbbbb")
    req = b"\x0b"  # authenticatorSelection: waits for the user
    for p in frames(a, hidmod.CMD_CBOR, req):
        dev.write(p)
    dev.step()  # start processing
    dev.write(init_packet(b, hidmod.CMD_PING, b"x"))
    dev.write(init_packet(a, hidmod.CMD_PING, b"x"))
    out = dev.read_all()
    kinds = [(int.from_bytes(p[:4], "big"), p[4] & 0x7F, p[7]) for p in out]
    assert (b, hidmod.CMD_ERROR, 0x06) in kinds
    assert (a, hidmod.CMD_ERROR, 0x06) in kinds
    keepalives = [k for k in kinds if k[1] == hidmod.CMD_KEEPALIVE]
    assert len(keepalives) >= 4
    assert all(k[0] == a and k[2] == 2 for k in keepalives)  # STATUS_UPNEEDED
    assert kinds[-1] == (a, hidmod.CMD_CBOR, 0x00)


def test_cancel_during_user_presence_python_fido2():
    ui = SimUI(["hang"])
    dev = Device(ui)
    ctap2 = Ctap2(open_hid(dev))
    event = threading.Event()
    statuses = []

    def on_keepalive(status):
        statuses.append(status)
        event.set()

    with pytest.raises(CtapError) as e:
        ctap2.make_credential(
            CDH,
            {"id": "example.com"},
            {"id": b"u"},
            [{"type": "public-key", "alg": -7}],
            event=event,
            on_keepalive=on_keepalive,
        )
    assert e.value.code == CtapError.ERR.KEEPALIVE_CANCEL
    assert statuses == [2]
    assert dev.auth.store.count() == 0
    # device usable again
    make(ctap2)


def test_cancel_of_other_channel_ignored():
    ui = SimUI([("wait", 300, True)])
    dev = Device(ui)
    a = allocate_channel(dev)
    b = allocate_channel(dev, b"bbbbbbbb")
    for p in frames(a, hidmod.CMD_CBOR, b"\x0b"):
        dev.write(p)
    dev.step()
    dev.write(init_packet(b, hidmod.CMD_CANCEL))
    out = dev.read_all()
    assert parse_response([out[-1]]) == (a, hidmod.CMD_CBOR, b"\x00")


def test_init_on_processing_channel_drops_response():
    ui = SimUI([("wait", 300, True)])
    dev = Device(ui)
    a = allocate_channel(dev)
    for p in frames(a, hidmod.CMD_CBOR, b"\x0b"):
        dev.write(p)
    dev.step()
    dev.write(init_packet(a, hidmod.CMD_INIT, b"resync!!"))
    out = dev.read_all()
    cmds = [p[4] & 0x7F for p in out]
    assert hidmod.CMD_INIT in cmds and hidmod.CMD_CBOR not in cmds


def test_channel_eviction(device):
    first = allocate_channel(device)
    for i in range(hidmod.MAX_CHANNELS):
        allocate_channel(device, i.to_bytes(8, "big"))
    assert error_of(send(device, first, hidmod.CMD_PING, b"x"), first) == 0x0B


def test_stale_completion_and_oversized_response(device):
    hid = device.hid
    cid = allocate_channel(device)
    t = hidmod.Transaction(cid, hidmod.CMD_CBOR, b"\x04")
    hid.complete(t, hidmod.CMD_CBOR, b"\x00")  # not the current transaction
    assert hid.pop_packets() == []
    device.write(init_packet(cid, hidmod.CMD_CBOR, b"\x04"))
    txn = device.jobs.pop()  # do not run the app; complete by hand
    txn.close()
    cur = hid.current()
    hid.complete(cur, hidmod.CMD_CBOR, b"x" * 7610)
    assert error_of(hid.pop_packets(), cid) == 0x7F
    assert not hid.busy()


def test_keepalive_interval(device):
    hid = hidmod.CtapHid()
    hid.handle_packet(init_packet(BCAST, hidmod.CMD_INIT, b"12345678"), 0)
    cid = int.from_bytes(hid.pop_packets()[0][15:19], "big")
    hid.handle_packet(init_packet(cid, hidmod.CMD_CBOR, b"\x04"), 0)
    txn = hid.take_request()
    hid.poll(50)
    assert hid.pop_packets() == []
    hid.poll(100)
    assert [p[4] for p in hid.pop_packets()] == [0xBB]
    txn.set_status(2)
    hid.poll(150)
    assert hid.pop_packets() == []
    hid.poll(200)
    assert hid.pop_packets()[0][7] == 2
    hid.complete(txn, hidmod.CMD_CBOR, b"\x00")
    hid.poll(400)
    assert [p[4] for p in hid.pop_packets()] == [0x90]
