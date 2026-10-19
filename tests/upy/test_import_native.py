# SPDX-License-Identifier: GPL-3.0-only
"""Actual native importer allocation failures, decoder pause and BOT refusal."""

import gc

import feuristic_import
from upytest import raises, run, test


def command(session, cdb, length=0, incoming=False):
    cbw = bytearray(31)
    cbw[:4] = b"USBC"
    cbw[4:8] = (1).to_bytes(4, "little")
    cbw[8:12] = length.to_bytes(4, "little")
    cbw[12] = 128 if incoming else 0
    cbw[14] = len(cdb)
    cbw[15 : 15 + len(cdb)] = cdb
    session.feed(b"\x00" + cbw)
    frames = []
    while True:
        frame = session.tx()
        if frame is None:
            break
        frames.append(frame)
        session.tx_done()
    return frames


def inquiry(session):
    frames = command(session, b"\x12\x00\x00\x00\x24\x00", 36, True)
    assert b"FEURISTIC-IMPORT" in frames[0]
    assert frames[-1][1:5] == b"USBS" and frames[-1][-1] == 0


@test
def paused_decoder_releases_ram_and_refuses_writes_without_losing_sectors():
    session = feuristic_import.Session(b"native test", 512, 1)
    try:
        command(session, b"\x00" * 6)  # consume power-on unit attention
        command(session, b"\x03\x00\x00\x00\x12\x00", 18, True)
        gc.collect()
        used = gc.mem_free()
        assert session.pause_decode()
        gc.collect()
        assert gc.mem_free() - used > 100000
        inquiry(session)  # MSC public reads work with all decoder RAM freed
        write = b"\x2a\x00\x00\x00\x00\x19\x00\x00\x01\x00"
        frames = command(session, write, 512)
        assert b"\x03" in frames  # OUT halt: the host must not send data
        status = frames[-1][1:]
        assert status[:4] == b"USBS" and status[-1] == 1
        assert int.from_bytes(status[8:12], "little") == 512
        session.feed(b"\x02\x01")  # host clears OUT halt
        sense = command(session, b"\x03\x00\x00\x00\x12\x00", 18, True)[0][1:]
        assert (sense[2] & 15, sense[12], sense[13]) == (2, 4, 7)
        assert session.resume_decode()
        inquiry(session)
        assert session.pause_decode()
        assert session.pause_decode()  # idempotent, no double free
    finally:
        session.close()
        session.close()


@test
def native_constructor_failures_release_owner_and_partial_buffers_immediately():
    # Each failure occurs after the object and context allocation, with
    # different scratch/bitmap allocation pressure. A delayed finalizer of
    # either failed object must never invalidate the next live session.
    for reserve in (65536, 131072):
        gc.collect()
        blocks = []
        while gc.mem_free() > reserve + 16384:
            blocks.append(bytearray(16384))
        failed = False
        try:
            unexpected = feuristic_import.Session(b"allocation failure", 1024, 2)
            unexpected.close()
        except MemoryError:
            failed = True
        blocks = None
        gc.collect()
        assert failed
        session = feuristic_import.Session(b"retry", 512, 3)
        try:
            gc.collect()  # run finalizers of the failed constructor now
            inquiry(session)
        finally:
            session.close()


@test
def native_context_has_one_owner_on_both_revisions():
    session = feuristic_import.Session(b"owner", 128, 1)
    try:
        raises(RuntimeError, feuristic_import.Session, b"second", 128, 2)
        gc.collect()
        inquiry(session)
    finally:
        session.close()
    replacement = feuristic_import.Session(b"replacement", 128, 3)
    replacement.close()


@test
def exact_readme_allocation_preserves_the_4096_byte_public_contract():
    raises(ValueError, feuristic_import.Session, b"X" * 4097, 128, 1)
    session = feuristic_import.Session(b"X" * 4096, 128, 1)
    try:
        command(session, b"\x00" * 6)
        root = command(session, b"\x28\x00\x00\x00\x00\x19\x00\x00\x01\x00", 512, True)
        sector = b"".join(frame[1:] for frame in root[:-1])
        for offset in range(0, len(sector), 32):
            if sector[offset : offset + 11] == b"README  TXT":
                assert int.from_bytes(sector[offset + 28 : offset + 32], "little") == 4096
                break
        else:
            raise AssertionError("README directory entry missing")
        inquiry(session)
    finally:
        session.close()


@test
def cancelling_real_import_closes_native_owner_and_restores_normal():
    from trezor import loop

    from feuristic.fw import device, import_mode, session, transports, usbmodes

    old = []

    def patch(obj, name, value):
        old.append((obj, name, getattr(obj, name)))
        setattr(obj, name, value)

    class Bus:
        USB_MODE_DETACH_MS = 5
        mode = usbmodes.NORMAL
        resumed = False

        def close(self):
            pass

        def usb_set_mode(self, mode, serial):
            self.mode = mode

        def suspend(self):
            self.resumed = False

        async def wait_suspended(self):
            pass

        def resume(self):
            self.resumed = True

    async def waiting(*args):
        await loop.sleep(60000)

    result = []
    bus = Bus()

    async def scenario():
        try:
            # Real native allocation and real import_mode.run, repeated to
            # catch a stale owner or a cancelled NORMAL cleanup task.
            for _ in range(2):
                job = loop.spawn(import_mode.run("backup"))
                while bus.mode != usbmodes.IMPORT:
                    await loop.sleep(1)
                job.close()
                assert job.finished
                replacement = feuristic_import.Session(b"owner was released", 128, 3)
                inquiry(replacement)
                replacement.close()
                await loop.sleep(20)
                assert bus.mode == usbmodes.NORMAL and bus.resumed
                assert not usbmodes._switching
            result.append(None)
        except BaseException as exc:
            result.append(exc)

    try:
        patch(usbmodes, "_bus", bus)
        patch(usbmodes, "io", bus)
        patch(usbmodes, "_switching", False)
        patch(usbmodes, "_started", False)
        patch(device, "usb_serial", lambda: "TEST")
        patch(session, "release_import_stores", lambda: None)
        patch(session, "reload_stores", lambda: None)
        patch(transports, "suspend", bus.suspend)
        patch(transports, "wait_suspended", bus.wait_suspended)
        patch(transports, "resume", bus.resume)
        patch(import_mode, "_controller", waiting)
        patch(import_mode, "_usb_task", waiting)
        loop.schedule(scenario())
        loop.run()
        assert result
        if result[0] is not None:
            raise result[0]
    finally:
        for obj, name, value in reversed(old):
            setattr(obj, name, value)


run()
