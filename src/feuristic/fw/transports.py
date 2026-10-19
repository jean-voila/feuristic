# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""USB transports of the NORMAL mode: FIDO HID and the CCID smart-card reader.

Two long-lived tasks (not workflows) shuttle packets between the USB
interfaces and the pure protocol state machines. The application objects
(which hold key material derived from the master secret) only exist while
the storage is unlocked: :func:`on_lock` drops them, and a request arriving
while locked first asks for the PIN on the device.
"""

import utime
from micropython import const
from trezor import config, io, log, loop, workflow

from ..platform import log as plog
from ..ui.interaction import DeviceInteraction
from . import device

FIDO_POLL_MS = const(50)
CCID_POLL_MS = const(100)
WTX_INTERVAL_MS = const(1000)
UNLOCK_TIMEOUT_MS = const(60_000)

_ui = DeviceInteraction()
_fido = None  # (HidServer)
_card = None  # Card
_tasks_started = False
_suspended = False
_pollers = []
_workers = []
_ccid_result = []


# -- application lifecycle ------------------------------------------------------


def _build_fido():
    from ..apps.fido2.app import Fido2App
    from ..apps.fido2.context import Context
    from ..apps.fido2.ctaphid import CtapHid, HidServer

    ctx = Context(device.master_secret(), _ui, power_up_ms=_POWER_UP_MS)
    return HidServer(CtapHid(wink=True), Fido2App(ctx))


def _build_card(public_only=False):
    from ..apps.card.aes.applet import AesApplet
    from ..apps.card.aes.rng import RngApplet
    from ..apps.card.card import Card
    from ..apps.card.openpgp.applet import OpenPgpApplet
    from ..apps.card.piv.applet import PivApplet

    applets = (
        []
        if public_only
        else [
            OpenPgpApplet(_ui, device.master_secret(), rsa_yield=_yield),
            PivApplet(_ui, master_secret=device.master_secret, keepalive=_yield),
            AesApplet(_ui, master_secret=device.master_secret),
        ]
    )
    # With no application selected, only GET CHALLENGE is answered (spec F06);
    # AES operations always require selecting the AES application first.
    return Card(applets, fallback=RngApplet())


async def _yield() -> None:
    await loop.sleep(0)


def on_lock() -> None:
    """Cancel in-flight operations before releasing their key material."""
    global _fido, _card
    # MicroPython's closed generators retain their code-state slots until
    # collected. Release the whole poller (and its local worker handles),
    # rather than leaving a stopped authenticator in a long-lived frame.
    for poller in list(_pollers):
        poller.close()
    del _pollers[:]
    _ui.cancel()
    for job in list(_workers):
        job.close()
    del _workers[:]
    del _ccid_result[:]
    if _card is not None:
        _card.usb_reset()
    _fido = None
    _card = None
    if _tasks_started and not _suspended:
        _start_pollers()


def suspend() -> None:
    """Stop normal-mode processing before detach or import allocation."""
    global _suspended
    _suspended = True
    on_lock()


def resume() -> None:
    global _suspended
    _suspended = False
    if _tasks_started:
        _start_pollers()


async def wait_suspended() -> None:
    """A suspended transport owns no poller frames or in-flight writes."""
    while _pollers:
        await loop.sleep(1)


def _worker_finished(job) -> None:
    if job in _workers:
        _workers.remove(job)


def _spawn_worker(coro):
    job = loop.spawn(coro)
    _workers.append(job)
    job.set_finalizer(_worker_finished)
    return job


async def _ensure_unlocked() -> bool:
    """Ask for the device PIN if a USB request arrives while locked."""
    if config.is_unlocked():
        return True
    from . import pin

    async def dialog():
        await pin.unlock()

    try:
        await loop.race(workflow.spawn(dialog()), loop.sleep(UNLOCK_TIMEOUT_MS))
    except Exception:
        return False
    if config.is_unlocked():
        from . import session

        session.after_unlock_from_usb()
        return True
    return False


def fido_server():
    global _fido
    if _fido is None and config.is_unlocked():
        _fido = _build_fido()
    return _fido


def _card_obj():
    global _card
    if _card is None:
        # GET CHALLENGE is public (F06) even while the device PIN is locked.
        # The locked reader has no applet capable of loading protected keys.
        _card = _build_card(public_only=not config.is_unlocked())
    elif config.is_unlocked() and not _card.dispatcher.applets:
        # A manual unlock may follow public RNG use. Preserve the powered
        # reader, host sequence and pending APDU while enabling its applets.
        _card.dispatcher = _build_card().dispatcher
    return _card


# -- FIDO HID --------------------------------------------------------------------


async def _write_hid(iface, packet) -> None:
    while not _suspended:
        try:
            await loop.wait(iface.iface_num() | io.POLL_WRITE, FIDO_POLL_MS)
        except loop.Timeout:
            continue
        if _suspended:
            return
        try:
            iface.write(packet)
            return
        except OSError:
            await loop.sleep(1)


async def fido_task() -> None:
    iface = io.USBIF(handle=io.USBIF_WEBAUTHN)
    buf = bytearray(64)
    req_job = None
    bg_job = None
    while True:
        if _suspended:
            await loop.sleep(FIDO_POLL_MS)
            continue
        try:
            await loop.wait(iface.iface_num() | io.POLL_READ, FIDO_POLL_MS)
            iface.read(buf, 0)
            packet = bytes(buf)
        except loop.Timeout:
            packet = None
        if _suspended:
            continue
        now = utime.ticks_ms()
        server = fido_server()
        if server is None:
            # locked: unlock first (the host retries / keeps polling)
            if packet is not None and await _ensure_unlocked():
                server = fido_server()
            if server is None:
                continue
        if packet is not None:
            workflow.idle_timer.touch()
            server.feed(packet, now)
        server.poll(now)
        if server.cancel_requested():
            _ui.cancel()
        for p in server.packets():
            await _write_hid(iface, p)
        if req_job is None or req_job.finished:
            txn = server.hid.take_request()
            if txn is not None:
                req_job = _spawn_worker(server._process(txn))
        if bg_job is None or bg_job.finished:
            job = server.app.background_job()
            if job is not None:
                bg_job = _spawn_worker(job)
        if server.take_wink():
            _ui.wink()


# -- CCID ------------------------------------------------------------------------

_EV_DATA = const(0x00)
_EV_RESET = const(0x01)


async def _write_frame(pipe, packet) -> None:
    frame = b"\x01" if not packet else b"\x00" + bytes(packet)
    while not _suspended:
        if pipe.write(frame) > 0:
            return
        try:
            await loop.wait(pipe.iface_num() | io.POLL_WRITE, CCID_POLL_MS)
        except loop.Timeout:
            pass


async def ccid_task() -> None:
    pipe = io.USBPipe(io.USBIF_CCID)
    buf = bytearray(65)
    worker = None
    result = _ccid_result
    last_wtx = 0

    async def work(card) -> None:
        out = await card.process_pending()
        result.extend(out)

    while True:
        if _suspended:
            await loop.sleep(CCID_POLL_MS)
            continue
        try:
            await loop.wait(pipe.iface_num() | io.POLL_READ, CCID_POLL_MS)
            n = pipe.read(buf)
        except loop.Timeout:
            n = 0
        if _suspended:
            continue
        card = _card_obj()
        if n > 0:
            workflow.idle_timer.touch()
            if card is None:
                if await _ensure_unlocked():
                    card = _card_obj()
                if card is None:
                    continue
            ev = buf[0]
            if ev == _EV_DATA:
                for p in card.receive(bytes(buf[1:n])):
                    await _write_frame(pipe, p)
            elif ev == _EV_RESET and n >= 3:
                card.control_abort(buf[1], buf[2])
        if card is None:
            continue
        if worker is not None and worker.finished:
            worker = None
            pkts = list(result)
            del result[:]
            for p in pkts:
                await _write_frame(pipe, p)
        if worker is None and card.pending is not None:
            if not config.is_unlocked():
                from ..apps.card import apdu

                try:
                    public = apdu.parse(card.pending.apdu).ins == 0x84
                except Exception:
                    public = True  # let the public dispatcher reject malformed APDUs
                if not public:
                    # Keep the pending CCID transport so the host's sequence
                    # remains valid, then install private applets after unlock.
                    if not await _ensure_unlocked():
                        card.usb_reset()
                        continue
                    card.dispatcher = _build_card().dispatcher
            worker = _spawn_worker(work(card))
            last_wtx = utime.ticks_ms()
        elif worker is not None and utime.ticks_diff(utime.ticks_ms(), last_wtx) >= WTX_INTERVAL_MS:
            last_wtx = utime.ticks_ms()
            for p in card.time_extension():
                await _write_frame(pipe, p)


# -- start -------------------------------------------------------------------------

_POWER_UP_MS = utime.ticks_ms()


def start() -> None:
    global _tasks_started
    if _tasks_started:
        return
    _tasks_started = True
    if not _suspended:
        _start_pollers()


def _start_pollers() -> None:
    if not _pollers:
        _pollers.extend((loop.spawn(_guard("fido", fido_task)), loop.spawn(_guard("ccid", ccid_task))))


async def _guard(name: str, task) -> None:
    """Restart a transport task after an unexpected error (never crash the device)."""
    while True:
        try:
            await task()
        except Exception as e:
            if __debug__:
                log.exception(__name__, e)
            plog.warning(__name__, "%s transport restarted", name)
            await loop.sleep(100)
