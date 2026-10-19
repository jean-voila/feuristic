# SPDX-License-Identifier: GPL-3.0-only
"""USB detach recovery survives cancellation on the real MicroPython scheduler."""

from trezor import loop
from upytest import run, test

from feuristic.fw import device, session, timesync_mode, transports, usbmodes


class FakeBus:
    USB_MODE_DETACH_MS = 10

    def __init__(self):
        self.events = []
        self.mode = usbmodes.NORMAL

    def close(self):
        self.events.append("close")

    def usb_set_mode(self, mode, serial):
        assert serial == "TEST"
        self.mode = mode
        self.events.append(mode)

    def suspend(self):
        self.events.append("suspend")

    async def wait_suspended(self):
        self.events.append("paused")

    def resume(self):
        self.events.append("resume")

    def reload(self):
        self.events.append("reload")


class Patch:
    def __init__(self):
        self.old = []

    def set(self, obj, key, value):
        self.old.append((obj, key, getattr(obj, key)))
        setattr(obj, key, value)

    def __enter__(self):
        bus = FakeBus()
        self.set(usbmodes, "_bus", bus)
        self.set(usbmodes, "io", bus)
        self.set(usbmodes, "_switching", False)
        self.set(usbmodes, "_started", False)
        self.set(device, "usb_serial", lambda: "TEST")
        self.set(transports, "suspend", bus.suspend)
        self.set(transports, "wait_suspended", bus.wait_suspended)
        self.set(transports, "resume", bus.resume)
        self.set(session, "reload_stores", bus.reload)
        return bus

    def __exit__(self, *args):
        for obj, key, value in reversed(self.old):
            setattr(obj, key, value)


def drive(coro):
    result = []

    async def wrapper():
        try:
            await coro
        except BaseException as exc:
            result.append(exc)
        else:
            result.append(None)

    loop.schedule(wrapper())
    loop.run()
    assert result
    if result[0] is not None:
        raise result[0]


@test
def closing_a_temporary_workflow_still_restores_normal():
    with Patch() as bus:

        async def temporary():
            completed = False
            try:
                await usbmodes.switch(usbmodes.IMPORT)
                await loop.sleep(60000)
                completed = True
            finally:
                ticket = usbmodes.restore_normal()
                if completed:
                    await ticket

        async def scenario():
            job = loop.spawn(temporary())
            await loop.sleep(30)
            assert bus.mode == usbmodes.IMPORT
            job.close()
            assert job.finished
            await loop.sleep(30)
            assert bus.mode == usbmodes.NORMAL
            assert bus.events == [
                "suspend",
                "paused",
                "close",
                usbmodes.IMPORT,
                "close",
                usbmodes.NORMAL,
                "reload",
                "resume",
            ]
            assert not usbmodes._switching

        drive(scenario())


@test
def closing_the_cleanup_waiter_does_not_close_the_cleanup_task():
    with Patch() as bus:

        async def temporary():
            await usbmodes.switch(usbmodes.TIMESYNC)
            await usbmodes.restore_normal()

        async def scenario():
            job = loop.spawn(temporary())
            while len(bus.events) < 5:
                await loop.sleep(1)
            assert bus.events[-1] == "close" and bus.mode == usbmodes.TIMESYNC
            job.close()  # close while NORMAL's detach delay is running
            await loop.sleep(30)
            assert bus.mode == usbmodes.NORMAL and bus.events[-1] == "resume"
            assert not usbmodes._switching

        drive(scenario())


@test
def concurrent_switches_never_overlap_the_detach_window():
    with Patch() as bus:

        async def scenario():
            first = loop.spawn(usbmodes.switch(usbmodes.IMPORT))
            second = loop.spawn(usbmodes.switch(usbmodes.TIMESYNC))
            await first
            await second
            assert bus.events == [
                "suspend",
                "paused",
                "close",
                usbmodes.IMPORT,
                "suspend",
                "paused",
                "close",
                usbmodes.TIMESYNC,
            ]
            await usbmodes.restore_normal()
            assert bus.mode == usbmodes.NORMAL

        drive(scenario())


@test
def cancelling_the_real_time_sync_entry_restores_usb():
    patch = Patch()
    with patch as bus:

        async def waiting(protocol):
            await loop.sleep(60000)

        patch.set(timesync_mode, "_serve", waiting)

        async def scenario():
            job = loop.spawn(timesync_mode.run())
            await loop.sleep(30)
            assert bus.mode == usbmodes.TIMESYNC
            job.close()
            await loop.sleep(30)
            assert bus.mode == usbmodes.NORMAL and bus.events[-1] == "resume"

        drive(scenario())


run()
