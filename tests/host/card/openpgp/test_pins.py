# SPDX-License-Identifier: GPL-3.0-only
"""OpenPGP PINs: VERIFY, CHANGE REFERENCE DATA, RESET RETRY COUNTER, retries,
power-loss safety of the try counters."""

import pytest

from feuristic.apps.card.openpgp import const as pgp
from feuristic.apps.card.openpgp import storage
from feuristic.platform import testing

from .conftest import Env


def tries(env):
    data, sw = env.get(0xC4)
    assert sw == 0x9000
    return data[4], data[5], data[6]  # PW1, RC, PW3


def test_verify_defaults(env):
    assert env.verify(0x81, b"123456") == 0x9000
    assert env.verify(0x82, b"123456") == 0x9000
    assert env.verify(0x83, b"12345678") == 0x9000
    assert tries(env) == (3, 0, 3)


def test_status_query(env):
    assert env.tx(0x20, 0, 0x81)[1] == 0x63C3
    assert env.tx(0x20, 0, 0x83)[1] == 0x63C3
    env.verify(0x81, b"123456")
    assert env.tx(0x20, 0, 0x81)[1] == 0x9000
    assert env.tx(0x20, 0, 0x82)[1] == 0x63C3  # 81 and 82 are distinct states
    env.verify(0x83, b"00000000")
    assert env.tx(0x20, 0, 0x83)[1] == 0x63C2


def test_verify_reset_with_p1_ff(env):
    env.verify(0x82, b"123456")
    assert env.tx(0x20, 0xFF, 0x82)[1] == 0x9000
    assert env.tx(0x20, 0, 0x82)[1] == 0x63C3
    assert env.tx(0x20, 0xFF, 0x82, b"1")[1] == 0x6700


def test_verify_bad_parameters(env):
    assert env.tx(0x20, 0, 0x84, b"123456")[1] == 0x6A86
    assert env.tx(0x20, 0x01, 0x81, b"123456")[1] == 0x6A86


def test_wrong_pin_counts_down_and_blocks(env):
    assert env.verify(0x81, b"654321") == 0x63C2
    assert env.verify(0x82, b"654321") == 0x63C1
    assert tries(env)[0] == 1
    assert env.verify(0x81, b"123456") == 0x9000  # success restores the counter
    assert tries(env)[0] == 3
    for expected in (0x63C2, 0x63C1, 0x63C0):
        assert env.verify(0x81, b"000000") == expected
    assert env.verify(0x81, b"123456") == 0x6983
    assert env.tx(0x20, 0, 0x81)[1] == 0x63C0
    assert tries(env)[0] == 0


def test_wrong_pin_clears_access(env):
    env.verify(0x81, b"123456")
    env.verify(0x82, b"123456")
    env.verify(0x81, b"000000")
    assert env.tx(0x20, 0, 0x81)[1] != 0x9000
    assert env.tx(0x20, 0, 0x82)[1] != 0x9000


@pytest.mark.parametrize(("p2", "pin"), [(0x81, b"12345"), (0x83, b"1234567"), (0x81, b"1" * 128)])
def test_out_of_bounds_length_does_not_consume(env, p2, pin):
    assert env.verify(p2, pin) == 0x6A80
    assert tries(env) == (3, 0, 3)


def test_change_pw1_and_pw3(env):
    assert env.tx(0x24, 0, 0x81, b"123456" + b"abcdefgh")[1] == 0x9000
    assert env.verify(0x81, b"123456") == 0x63C2
    assert env.verify(0x81, b"abcdefgh") == 0x9000
    assert env.tx(0x24, 0, 0x83, b"12345678" + b"admin-pin-2")[1] == 0x9000
    assert env.verify(0x83, b"admin-pin-2") == 0x9000


def test_change_errors(env):
    assert env.tx(0x24, 0, 0x81, b"654321" + b"abcdefgh")[1] == 0x63C2
    # valid old PIN, too short new PIN: rejected after verification, try restored
    assert env.tx(0x24, 0, 0x81, b"123456" + b"12")[1] == 0x6A80
    assert tries(env)[0] == 3
    assert env.verify(0x81, b"123456") == 0x9000
    assert env.tx(0x24, 0, 0x82, b"123456" + b"abcdefgh")[1] == 0x6A86
    assert env.tx(0x24, 1, 0x81, b"123456" + b"abcdefgh")[1] == 0x6A86
    assert env.tx(0x24, 0, 0x83, b"12345678" + b"short")[1] == 0x6A80


def test_change_resets_access_status(env):
    env.verify(0x82, b"123456")
    env.tx(0x24, 0, 0x81, b"123456" + b"abcdef")
    assert env.tx(0x20, 0, 0x82)[1] == 0x63C3


def test_reset_retry_counter_with_admin(env):
    for _ in range(3):
        env.verify(0x81, b"000000")
    assert env.verify(0x81, b"123456") == 0x6983
    assert env.tx(0x2C, 0x02, 0x81, b"newpin")[1] == 0x6982
    env.admin()
    assert env.tx(0x2C, 0x02, 0x81, b"short")[1] == 0x6A80
    assert env.tx(0x2C, 0x02, 0x81, b"newpin")[1] == 0x9000
    assert tries(env)[0] == 3
    assert env.verify(0x81, b"newpin") == 0x9000


def test_reset_retry_counter_with_resetting_code(env):
    assert env.tx(0x2C, 0x00, 0x81, b"rc-code-1" + b"newpin")[1] == 0x6983  # no RC set
    env.admin()
    assert env.put(0xD3, b"short") == 0x6A80
    assert env.put(0xD3, b"rc-code-1") == 0x9000
    assert tries(env) == (3, 3, 3)
    for _ in range(3):
        env.verify(0x81, b"000000")
    env.reboot().select()
    assert env.tx(0x2C, 0x00, 0x81, b"rc-code-X" + b"newpin")[1] == 0x63C2
    assert env.tx(0x2C, 0x00, 0x81, b"rc-code-1" + b"new")[1] == 0x6A80
    assert env.tx(0x2C, 0x00, 0x81, b"rc-code-1" + b"newpin")[1] == 0x9000
    assert tries(env) == (3, 3, 3)
    assert env.verify(0x81, b"newpin") == 0x9000
    # block the resetting code
    for _ in range(3):
        env.tx(0x2C, 0x00, 0x81, b"rc-code-X" + b"newpin")
    assert tries(env)[1] == 0
    assert env.tx(0x2C, 0x00, 0x81, b"rc-code-1" + b"newpin")[1] == 0x6983
    # removing the resetting code
    env.admin()
    assert env.put(0xD3, b"") == 0x9000
    assert tries(env)[1] == 0


def test_reset_retry_counter_bad_params(env):
    env.admin()
    assert env.tx(0x2C, 0x02, 0x82, b"newpin")[1] == 0x6A86
    assert env.tx(0x2C, 0x01, 0x81, b"newpin")[1] == 0x6A86


def test_pins_persist_and_counters_survive_reboot():
    e = Env()
    e.select()
    e.tx(0x24, 0, 0x81, b"123456" + b"persist1")
    e.verify(0x83, b"wrongpw3")
    e.reboot().select()
    assert e.verify(0x81, b"persist1") == 0x9000
    assert tries(e)[2] == 2
    assert e.tx(0x20, 0, 0x83)[1] == 0x63C2
    # access status is volatile
    e.reboot().select()
    assert e.tx(0x20, 0, 0x81)[1] == 0x63C3


def test_fresh_card_reboot_keeps_consumed_tries():
    e = Env()
    e.select()
    e.verify(0x81, b"000000")
    e.reboot().select()
    assert tries(e)[0] == 2


def test_pins_are_not_stored_in_clear(kv):
    e = Env()
    e.select()
    e.tx(0x24, 0, 0x81, b"123456" + b"SECRETPIN")
    for value in kv.data.values():
        assert b"SECRETPIN" not in value
        assert b"123456" not in value


def test_try_consumed_before_compare(monkeypatch):
    e = Env()
    e.select()
    seen = []
    orig = storage.PinRef.matches

    def spy(self, pin):
        seen.append(e.store.tries[pgp.PW1].used())
        return orig(self, pin)

    monkeypatch.setattr(storage.PinRef, "matches", spy)
    e.verify(0x81, b"123456")
    e.verify(0x81, b"999999")
    assert seen == [1, 1]  # the try was persisted before every comparison


def _ops_of(fn):
    testing.KV.ops = 0
    fn()
    return testing.KV.ops


@pytest.mark.parametrize("correct", [False, True])
def test_power_loss_never_restores_tries(correct):
    """Inject a power cut at every storage operation of a VERIFY."""
    pin = b"123456" if correct else b"000000"
    e = Env()
    e.select()
    e.admin()
    assert e.put(0x5B, b"Doe<<John") == 0x9000  # identity record persisted
    e.verify(0x81, b"999999")  # one failure recorded: 2 tries left
    snapshot = dict(testing.KV.data)
    n = _ops_of(lambda: e.verify(0x81, pin))
    assert n > 0
    for k in range(n):
        testing.KV.data = dict(snapshot)
        testing.KV.crash_after_ops = None
        e.reboot().select()
        testing.KV.ops = 0
        testing.KV.crash_after_ops = k
        with pytest.raises(testing.PowerLoss):
            e.verify(0x81, pin)
        testing.KV.crash_after_ops = None
        e.reboot().select()
        left = tries(e)[0]
        # a wrong PIN can never give tries back (2 before the attempt); only
        # a correct PIN may restore the counter to 3
        if correct:
            assert left in (1, 2, 3)
        else:
            assert left in (1, 2)
    testing.KV.data = dict(snapshot)
    e.reboot().select()
    e.verify(0x81, pin)
    assert tries(e)[0] == (3 if correct else 1)
