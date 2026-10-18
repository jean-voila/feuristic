# SPDX-License-Identifier: GPL-3.0-only
"""Minimal test runner for MicroPython (run inside the feuristic emulator)."""

_results = []


def storage_setup():
    """Initialise the emulator's (empty, temporary) storage and unlock it."""
    from trezor import config

    config.init()
    if not config.is_unlocked():
        config.unlock("", None)


def test(fn):
    _results.append(fn)
    return fn


def raises(exc, fn, *args):
    try:
        fn(*args)
    except exc:
        return
    raise AssertionError("expected " + exc.__name__)


def run():
    failed = 0
    for fn in _results:
        try:
            fn()
            print("PASS", fn.__name__)
        except Exception as e:
            failed += 1
            print("FAIL", fn.__name__, repr(e))
    print("UPYTEST", "OK" if not failed else "FAILED", len(_results) - failed, failed)
