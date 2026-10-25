# SPDX-License-Identifier: GPL-3.0-only
"""Backup phrase comparison must never spend a device PIN attempt."""

from trezor import config
from upytest import run, storage_setup, test

from feuristic.fw import pin
from feuristic.ui import screens


def drive(coro):
    try:
        while True:
            coro.send(None)
    except StopIteration as exc:
        return exc.value


@test
def phrase_distinctness_uses_verified_pin_without_spending_attempts():
    code = "123456789012"
    assert config.change_pin(code, None)
    original_input = screens.request_pin
    original_error = screens.show_error
    original_wipe = pin.wipe
    errors = []
    buffers = []

    async def enter(*args, **kwargs):
        return code

    async def error(message):
        errors.append(message)

    def wipe(buf):
        if buf is not None:
            buffers.append(buf)
        original_wipe(buf)

    try:
        screens.request_pin = enter
        screens.show_error = error
        pin.wipe = wipe
        retries = config.get_pin_rem()
        same = bytearray(code.encode())
        assert drive(pin.reauthenticate(distinct_from=same)) is False
        assert errors and config.get_pin_rem() == retries
        other = bytearray(b"098765432109")
        assert drive(pin.reauthenticate(distinct_from=other)) is True
        assert config.get_pin_rem() == retries
        assert same == code.encode() and other == b"098765432109"
        assert len(buffers) == 2 and all(buf == bytearray(len(code)) for buf in buffers)

        async def cancel(*args, **kwargs):
            return None

        screens.request_pin = cancel
        assert drive(pin.reauthenticate(distinct_from=other)) is False
        assert config.get_pin_rem() == retries
    finally:
        screens.request_pin = original_input
        screens.show_error = original_error
        pin.wipe = original_wipe


@test
def pin_reentry_shows_the_shared_attempt_budget():
    code = "123456789012"
    assert config.change_pin(code, None)
    original_input = screens.request_pin
    original_error = screens.show_error
    hints = []
    answers = ["000000", code]

    async def enter(prompt, attempts="", wrong=False, last=False, close_others=False):
        hints.append((attempts, last))
        return answers.pop(0)

    async def error(message):
        pass

    try:
        screens.request_pin = enter
        screens.show_error = error
        full = config.get_pin_rem()
        assert drive(pin.reauthenticate()) is False
        assert config.get_pin_rem() == full - 1
        assert drive(pin.reauthenticate()) is True
        assert config.get_pin_rem() == full
        assert hints[0] == ("", False)
        assert str(full - 1) in hints[1][0] and hints[1][1] is False
    finally:
        screens.request_pin = original_input
        screens.show_error = original_error


@test
def newer_storage_schema_is_refused_before_unlock():
    from feuristic.core import namespaces as ns
    from feuristic.fw import device
    from feuristic.platform import kv

    saved = kv.get(ns.SYS_PUBLIC, ns.SYS_PUB_SCHEMA, True)
    try:
        kv.set(ns.SYS_PUBLIC, ns.SYS_PUB_SCHEMA, bytes((device.SCHEMA_VERSION + 1,)), True)
        assert not device.schema_supported()
        kv.set(ns.SYS_PUBLIC, ns.SYS_PUB_SCHEMA, bytes((device.SCHEMA_VERSION,)), True)
        assert device.schema_supported()
    finally:
        if saved is None:
            kv.delete(ns.SYS_PUBLIC, ns.SYS_PUB_SCHEMA, True)
        else:
            kv.set(ns.SYS_PUBLIC, ns.SYS_PUB_SCHEMA, saved, True)


storage_setup()
run()
