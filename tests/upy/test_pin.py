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


storage_setup()
run()
