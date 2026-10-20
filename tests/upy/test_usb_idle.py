# SPDX-License-Identifier: GPL-3.0-only
"""USB PING/public RNG must not keep an unattended device unlocked."""

import ustruct
from trezor import config, loop, workflow
from upytest import raises, run, storage_setup, test

from feuristic.fw import device, transports


def drive(coro):
    errors = []

    async def wrapper():
        try:
            await coro
        except BaseException as exc:
            errors.append(exc)

    loop.schedule(wrapper())
    loop.run()
    if errors:
        raise errors[0]


@test
def public_usb_traffic_leaves_five_minute_idle_deadline_unchanged():
    assert config.change_pin("1234", None)
    device.initialize()

    class Clock:
        now = 0

        def ticks_ms(self):
            return self.now

        def ticks_add(self, value, delta):
            return value + delta

    class Scheduler:
        scheduled = []

        def schedule(self, task, value, deadline, reschedule=False):
            self.scheduled.append((task, deadline))

        def close(self, task):
            task.close()

    clock, scheduler = Clock(), Scheduler()
    fido = transports.fido_server()
    cid = fido.hid._allocate()
    ping = cid.to_bytes(4, "big") + b"\x81\x00\x04PING" + bytes(53)
    power_on = ustruct.pack("<BIBBBBB", 0x62, 0, 0, 0, 0, 0, 0)
    challenge = bytes.fromhex("0084000020")
    get_challenge = ustruct.pack("<BIBBBBB", 0x6F, len(challenge), 0, 1, 0, 0, 0) + challenge
    queues = [[ping] * 4, [b"\x00" + power_on, b"\x00" + get_challenge]]
    replies = [[], []]

    class Interface:
        def __init__(self, kind):
            self.kind = kind

        def iface_num(self):
            return self.kind

        def read(self, buf, *args):
            if not queues[self.kind]:
                raise loop.Timeout
            packet = queues[self.kind].pop(0)
            buf[: len(packet)] = packet
            clock.now += 60_000  # six packets model six idle minutes
            return len(packet)

    class IO:
        USBIF_WEBAUTHN = 0
        USBIF_CCID = 1
        POLL_READ = 0
        POLL_WRITE = 0

        def USBIF(self, handle):
            return Interface(handle)

        def USBPipe(self, handle):
            return Interface(handle)

    async def wait(*args):
        await loop.sleep(1)

    async def write_hid(iface, packet):
        replies[0].append(packet)

    async def write_frame(pipe, packet):
        replies[1].append(packet)

    old = (
        workflow.loop,
        workflow.utime,
        workflow.idle_timer,
        workflow.storage_cache.autolock_last_touch,
        transports.io,
        transports._write_hid,
        transports._write_frame,
        loop.wait,
        transports._suspended,
    )
    locked = []

    def lock():
        config.lock()
        locked.append(clock.now)

    async def scenario():
        workflow.loop, workflow.utime = scheduler, clock
        workflow.storage_cache.autolock_last_touch = None
        timer = workflow.IdleTimer()
        workflow.idle_timer = timer
        transports.io = IO()
        transports._write_hid, transports._write_frame = write_hid, write_frame
        transports._suspended = False
        loop.wait = wait
        timer.set(device.AUTOLOCK_MS, lock)
        jobs = [loop.spawn(transports.fido_task()), loop.spawn(transports.ccid_task())]
        try:
            await loop.sleep(30)
            assert not queues[0] and not queues[1]
            assert any(packet[4] == 0x81 and packet[7:11] == b"PING" for packet in replies[0])
            assert any(len(packet) == 44 and packet[-2:] == b"\x90\x00" for packet in replies[1])
            assert clock.now == 360_000 and config.is_unlocked()
            assert len(scheduler.scheduled) == 1  # no USB packet rearmed it
            task, deadline = scheduler.scheduled[-1]
            assert deadline == 300_000 and clock.now >= deadline
            raises(StopIteration, task.send, None)
            assert locked == [360_000] and not config.is_unlocked()
            assert config.unlock("1234", None)
            # The unchanged upstream physical-activity hook still extends it.
            timer.touch()
            assert scheduler.scheduled[-1][1] == 660_000
        finally:
            for job in jobs:
                job.close()
            for job in list(transports._workers):
                job.close()
            timer.clear()
            (
                workflow.loop,
                workflow.utime,
                workflow.idle_timer,
                workflow.storage_cache.autolock_last_touch,
                transports.io,
                transports._write_hid,
                transports._write_frame,
                loop.wait,
                transports._suspended,
            ) = old
            transports.on_lock()

    drive(scenario())


storage_setup()
run()
