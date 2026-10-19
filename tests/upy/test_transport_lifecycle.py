# SPDX-License-Identifier: GPL-3.0-only
"""Real scheduler tests for private polling-frame lifetime at lock/import."""

from trezor import loop
from upytest import run, test

from feuristic.fw import transports


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
def lock_drops_poller_handles_and_suspend_cannot_restart_old_generators():
    started = []
    closed = []
    previous = (transports.fido_task, transports.ccid_task, transports._tasks_started, transports._suspended)

    async def holding_poller():
        # This object deliberately remains in a live generator local. The
        # production loops similarly own protocol servers and last replies.
        private_reference = object()
        started.append(private_reference)
        try:
            await loop.sleep(60_000)
        finally:
            closed.append(private_reference)

    async def scenario():
        transports.fido_task = holding_poller
        transports.ccid_task = holding_poller
        transports._tasks_started = False
        transports._suspended = False
        try:
            transports.start()
            await loop.sleep(1)
            assert len(started) == 2 and len(transports._pollers) == 2
            original = list(transports._pollers)
            transports._ccid_result.append(b"last confidential response")
            transports.on_lock()
            assert all(poller.finished for poller in original)
            assert len(closed) == 2 and not transports._ccid_result
            assert len(transports._pollers) == 2
            assert all(poller not in transports._pollers for poller in original)
            await loop.sleep(1)
            assert len(started) == 4
            replacement = list(transports._pollers)
            transports.suspend()
            await transports.wait_suspended()
            assert not transports._pollers and not transports._workers
            assert all(poller.finished for poller in replacement)
            await loop.sleep(1)
            assert len(started) == 4 and len(closed) == 4
            transports.resume()
            await loop.sleep(1)
            assert len(started) == 6 and len(transports._pollers) == 2
            assert all(poller not in transports._pollers for poller in original + replacement)
        finally:
            transports.suspend()
            transports.fido_task, transports.ccid_task, transports._tasks_started, transports._suspended = (
                previous
            )
        assert len(closed) == 6 and not transports._pollers

    drive(scenario())


run()
