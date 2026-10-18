# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""GET CHALLENGE, rate limiting and SP 800-90B-style health tests."""

import pytest

from feuristic.apps.card import apdu
from feuristic.apps.card.aes import localmgmt, rng
from feuristic.core.errors import StorageFull  # noqa: F401  (import check)
from feuristic.platform import testing

from ...aio import run
from .aesutil import challenge, tx


def gc(service, le=8, data=b"", p1=0, p2=0):
    return service.get_challenge(apdu.parse(apdu.build(0, 0x84, p1, p2, data, le)))


# -- GET CHALLENGE command ------------------------------------------------------------


@pytest.mark.parametrize("n", [1, 8, 16, 31, 32])
def test_lengths(service, n):
    r = gc(service, n)
    assert r.sw == 0x9000 and len(r.data) == n


def test_outputs_differ(service):
    assert gc(service, 32).data != gc(service, 32).data


@pytest.mark.parametrize("le", [33, 64, 255, 256])
def test_too_long(service, le):
    r = gc(service, le)
    assert (r.data, r.sw) == (b"", 0x6C20)


def test_le_00_means_256_and_is_refused(service):
    r = service.get_challenge(apdu.parse(bytes.fromhex("0084000000")))
    assert r.sw == 0x6C20


def test_no_le_or_with_data(service):
    assert service.get_challenge(apdu.parse(bytes.fromhex("00840000"))).sw == 0x6700
    assert gc(service, 8, data=b"\x01").sw == 0x6700


@pytest.mark.parametrize(("p1", "p2"), [(1, 0), (0, 1), (0x80, 0)])
def test_bad_p1p2(service, p1, p2):
    assert gc(service, 8, p1=p1, p2=p2).sw == 0x6A86


def test_answered_by_aes_applet_without_pin_or_prompt(aes, ui):
    r = challenge(aes, 32)
    assert r.sw == 0x9000 and len(r.data) == 32
    assert ui.prompts == []


def test_deterministic_rng_is_the_source(service):
    testing.set_rng(testing.deterministic_rng(b"seed"))
    service.health.startup()  # consumes 1024 bytes
    expected = testing.deterministic_rng(b"seed")(1024 + 16)[1024:]
    assert gc(service, 16).data == expected


# -- rate limiting --------------------------------------------------------------------------


def test_request_rate_limit(service, clock):
    for _ in range(rng.REQUESTS_PER_S):
        assert gc(service, 1).sw == 0x9000
    assert gc(service, 1).sw == 0x6985
    assert service.rate_limited == 1
    clock.advance(50)  # one token back after 1/20 s
    assert gc(service, 1).sw == 0x9000
    assert gc(service, 1).sw == 0x6985
    clock.advance(1000)
    for _ in range(rng.REQUESTS_PER_S):
        assert gc(service, 1).sw == 0x9000


def test_byte_rate_limit(clock):
    s = rng.RngService(requests_per_s=1000, bytes_per_s=64)
    assert gc(s, 32).sw == 0x9000
    assert gc(s, 32).sw == 0x9000
    assert gc(s, 1).sw == 0x6985
    clock.advance(250)  # 16 bytes refilled
    assert gc(s, 17).sw == 0x6985
    assert gc(s, 16).sw == 0x9000


def test_refused_request_consumes_nothing(clock):
    s = rng.RngService(requests_per_s=2, bytes_per_s=40)
    assert gc(s, 32).sw == 0x9000
    assert gc(s, 32).sw == 0x6985  # bytes exhausted; request token must not be lost
    assert gc(s, 8).sw == 0x9000


def test_default_byte_budget_not_binding_at_32_bytes(service, clock):
    for _ in range(5):
        for _ in range(rng.REQUESTS_PER_S):
            assert gc(service, 32).sw == 0x9000
        clock.advance(1000)


def test_rate_limit_does_not_affect_aes_operations(aes, key1, clock):
    from .aesutil import encipher, mse

    for _ in range(rng.REQUESTS_PER_S + 5):
        challenge(aes, 4)
    assert mse(aes, key1.kid, 0xF1).sw == 0x9000
    assert encipher(aes, b"still works").sw == 0x9000


# -- health tests ---------------------------------------------------------------------------


def test_cutoffs():
    assert (rng.RCT_CUTOFF, rng.APT_WINDOW, rng.APT_CUTOFF, rng.STARTUP_SAMPLES) == (6, 512, 19, 1024)


def test_startup_test_runs_once(service):
    assert service.health.state == rng.STATE_UNTESTED
    gc(service, 8)
    st = service.health.status()
    assert st["state"] == rng.STATE_OK
    assert st["bytes_tested"] == 1024 + 8
    gc(service, 8)
    assert service.health.status()["bytes_tested"] == 1024 + 16


def test_stuck_rng_fails_rct_and_latches(service):
    testing.set_rng(lambda n: b"\x00" * n)
    r = gc(service, 8)
    assert (r.data, r.sw) == (b"", 0x6400)
    st = service.health.status()
    assert st["state"] == rng.STATE_FAILED and st["last_failure"] == "rct" and st["rct_failures"] == 1
    testing.set_rng(None)  # source recovers...
    assert gc(service, 8).sw == 0x6400  # ...but the failure is latched
    assert service.refused_health == 2
    assert service.health.retest()
    assert gc(service, 8).sw == 0x9000


def test_rct_after_startup(service):
    gc(service, 8)
    testing.set_rng(lambda n: b"\x5a" * n)
    assert gc(service, 32).sw == 0x6400
    assert service.health.last_failure == "rct"


def test_rct_across_requests(service):
    gc(service, 1)
    testing.set_rng(lambda n: b"\x77" * n)
    assert gc(service, 3).sw == 0x9000  # 3 equal bytes...
    assert gc(service, 3).sw == 0x6400  # ...6 in a row across requests


def test_apt_detects_bias_without_repetitions(service):
    """Every other byte is 0x41: never 6 in a row, but 19+ per 512-byte window."""
    state = {"i": 0}

    def biased(n):
        out = bytearray()
        for _ in range(n):
            i = state["i"]
            out.append(0x41 if i % 2 == 0 else (i // 2) % 200 + 50)
            state["i"] += 1
        return bytes(out)

    testing.set_rng(biased)
    assert gc(service, 8).sw == 0x6400
    assert service.health.last_failure == "apt"
    assert service.health.apt_failures == 1


def _window(occurrences):
    """512 distinct-ish bytes where the first value occurs ``occurrences`` times."""
    window = bytearray(range(256)) * 2  # value 0 already at 0 and 256
    for k in range(occurrences - 2):
        window[3 + 20 * k] = window[0]
    return bytes(window)


def test_apt_exact_cutoff():
    hm = rng.HealthMonitor()
    assert hm._feed(_window(18))
    assert hm._feed(_window(18))  # each window is counted on its own
    assert not hm._feed(_window(19))
    assert hm.last_failure == "apt"


def test_healthy_source_never_alarms(service):
    for _ in range(300):
        service.health.random_bytes(32)
    assert service.health.state == rng.STATE_OK


def test_short_source_output_is_failure():
    hm = rng.HealthMonitor(source=lambda n: bytes(range(n)) if n > 32 else b"\x01")
    with pytest.raises(rng.RngHealthError):
        hm.random_bytes(8)


def test_aes_key_creation_refused_on_rng_failure(store, service):
    testing.set_rng(lambda n: b"\x00" * n)
    with pytest.raises(rng.RngHealthError):
        localmgmt.create_key("k", rng=service.health.random_bytes, store=store)
    assert store.entries() == []


def test_status_for_menu(service):
    gc(service, 4)
    st = localmgmt.rng_status(service)
    assert st["state_key"] == "rng.state.ok"
    assert st["max_challenge"] == 32
    labels = [k for k, _ in localmgmt.rng_fields(service)]
    assert labels[0] == "rng.status" and "rng.field.rct" in labels
    testing.set_rng(lambda n: b"\x00" * n)
    gc(service, 8)
    assert ("rng.field.last_failure", "RCT") in localmgmt.rng_fields(service)
    testing.set_rng(None)
    assert localmgmt.rng_retest(service)


# -- dispatcher-level GET CHALLENGE ------------------------------------------------------------


def test_rng_applet_fallback(service):
    a = rng.RngApplet(service=service)
    assert not a.matches(b"\xf0") and not a.matches(b"")
    r = run(a.process(apdu.parse(apdu.build(0, 0x84, 0, 0, b"", 16))))
    assert r.sw == 0x9000 and len(r.data) == 16
    assert run(a.process(apdu.parse(apdu.build(0, 0x2A, 0x84, 0x80, b"\x80\x00")))).sw == 0x6D00
    assert run(a.process(apdu.parse(apdu.build(0x80, 0x84, 0, 0, b"", 16)))).sw == 0x6E00


def test_module_level_get_challenge():
    rng._reset_default()
    r = rng.get_challenge(apdu.parse(apdu.build(0, 0x84, 0, 0, b"", 32)))
    assert r.sw == 0x9000 and len(r.data) == 32
    assert rng.default() is rng.default()
    rng._reset_default()


def test_through_dispatcher_without_selection(service, piv_like=None):
    dispatcher = pytest.importorskip("feuristic.apps.card.dispatcher")
    from feuristic.apps.card.aes.applet import AesApplet

    aes = AesApplet(None, master_secret=bytes(32), rng=service)
    d = dispatcher.Dispatcher([aes], fallback=rng.RngApplet(service=service))
    rsp = run(d.transmit(bytes.fromhex("0084000020")))
    assert rsp[-2:] == b"\x90\x00" and len(rsp) == 34
    # an AES operation is not reachable without SELECT
    rsp = run(d.transmit(bytes.fromhex("002281B803830101")))
    assert rsp == b"\x6d\x00"


def test_aes_applet_wrong_class_for_challenge(aes):
    assert tx(aes, 0x84, 0, 0, b"", 8, cla=0x80).sw == 0x6E00
