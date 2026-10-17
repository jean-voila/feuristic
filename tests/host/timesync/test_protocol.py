# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from feuristic.apps.timesync import protocol as p
from feuristic.core import clock as clock_mod
from feuristic.core.errors import UserCancelled, UserTimeout
from feuristic.core.interaction import SENSITIVE, ScriptedInteraction

from ..aio import run

T = 1_800_000_000


def session(answers=(), default=True, clock=None, **kw):
    ui = ScriptedInteraction(answers, default)
    sc = clock if clock is not None else clock_mod.SessionClock()
    return p.TimeSyncSession(ui, sc, **kw), ui, sc


def feed(s, data):
    return run(s.feed(data))


# -- wire format ------------------------------------------------------------------------


def test_response_encoding():
    assert p.ok(T) == b"OK 1800000000\n"
    assert p.err(6) == b"ERR 6\n"
    assert p.HELLO_RESPONSE == b"FEURISTIC TIME 1\n"
    assert (p.ERR_SYNTAX, p.ERR_VERSION, p.ERR_RANGE, p.ERR_REFUSED, p.ERR_BUSY, p.ERR_TOO_LONG) == (
        1,
        2,
        3,
        4,
        5,
        6,
    )


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        (b"TIME 1 1800000000", ("time", T)),
        (b"TIME 1 0001800000000", ("time", T)),
        (b"TIME 001 1800000000", ("time", T)),
        (b"TIME 1 0", ("time", 0)),
        (b"TIME 1 " + b"9" * 20, ("time", 10**20 - 1)),
        (b"HELLO", ("hello", None)),
        (b"TIME 2 1800000000", ("err", 2)),
        (b"TIME 0 1800000000", ("err", 2)),
        (b"TIME 999 x", ("err", 2)),
        (b"TIME 2", ("err", 2)),
        (b"TIME 1 " + b"1" * 21, ("err", 3)),
        (b"TIME 1 " + b"1" * 21 + b"x", ("err", 1)),
        (b"TIME 1", ("err", 1)),
        (b"TIME", ("err", 1)),
        (b"TIME 1 ", ("err", 1)),
        (b"TIME  1 1800000000", ("err", 1)),
        (b"TIME 1  1800000000", ("err", 1)),
        (b" TIME 1 1800000000", ("err", 1)),
        (b"TIME 1 1800000000 ", ("err", 1)),
        (b"TIME 1 1800000000 extra", ("err", 1)),
        (b"TIME 1 -1800000000", ("err", 1)),
        (b"TIME 1 +1800000000", ("err", 1)),
        (b"TIME 1 1.8e9", ("err", 1)),
        (b"TIME 1 0x6B49D200", ("err", 1)),
        (b"TIME 1 1800000000\x00", ("err", 1)),
        (b"TIME\t1\t1800000000", ("err", 1)),
        (b"TIME 1\xff1800000000", ("err", 1)),
        (b"time 1 1800000000", ("err", 1)),
        (b"TIME v1 1800000000", ("err", 1)),
        (b"TIME 1000 1800000000", ("err", 1)),
        (b"HELLO ", ("err", 1)),
        (b"hello", ("err", 1)),
        (b"SET 1800000000", ("err", 1)),
        (None, ("err", 6)),
        (b"T" * 65, ("err", 6)),
    ],
)
def test_parse_line(line, expected):
    assert p.parse_line(line) == expected


# -- line assembler ------------------------------------------------------------------------


def test_assembler_terminators_and_empty_lines():
    a = p.LineAssembler()
    assert a.feed(b"TIME 1 1\nHELLO\r\nX\r\r\n\n") == [b"TIME 1 1", b"HELLO", b"X"]
    assert a.pending() == 0


def test_assembler_chunked():
    a = p.LineAssembler()
    out = []
    for b in b"TIME 1 1800000000\r\nHEL":
        out += a.feed(bytes([b]))
    assert out == [b"TIME 1 1800000000"]
    assert a.pending() == 3
    assert a.feed(b"LO\n") == [b"HELLO"]


def test_assembler_overflow_exact_bounds():
    a = p.LineAssembler()
    assert a.feed(b"A" * 64 + b"\n") == [b"A" * 64]
    assert a.feed(b"A" * 65 + b"\n") == [None]
    assert a.feed(b"B" * 1000) == []
    assert a.pending() == 0  # overflowed data is not buffered
    assert a.feed(b"tail\r\nHELLO\n") == [None, b"HELLO"]
    a.feed(b"partial")
    a.reset()
    assert a.feed(b"\n") == []
    with pytest.raises(ValueError):
        p.LineAssembler(0)


@given(st.lists(st.binary(max_size=200), max_size=30))
def test_assembler_bounded_on_arbitrary_streams(chunks):
    a = p.LineAssembler()
    total = 0
    for c in chunks:
        out = a.feed(c)
        total += len(c)
        assert a.pending() <= p.MAX_LINE
        for line in out:
            assert line is None or 1 <= len(line) <= p.MAX_LINE
            assert line is None or (b"\r" not in line and b"\n" not in line)
        assert len(out) <= len(c)


@given(st.binary(max_size=300), st.lists(st.integers(min_value=1, max_value=64), max_size=40))
def test_assembler_chunking_invariant(data, sizes):
    whole = p.LineAssembler().feed(data)
    a = p.LineAssembler()
    parts = []
    pos = 0
    for n in sizes:
        parts += a.feed(data[pos : pos + n])
        pos += n
    parts += a.feed(data[pos:])
    assert parts == whole


# -- session: basic flows -----------------------------------------------------------------------


def test_first_set_applied_without_confirmation(clock):
    s, ui, sc = session()
    assert feed(s, b"TIME 1 1800000000\n") == [b"OK 1800000000\n"]
    assert ui.prompts == []
    assert s.done and s.applied == T
    assert sc.now() == T
    clock.advance(5_000)
    assert sc.now() == T + 5


def test_first_set_confirm_option(clock):
    s, ui, sc = session(answers=[False], confirm_first=True)
    assert feed(s, b"TIME 1 1800000000\n") == [b"ERR 4\n"]
    assert not sc.is_set() and not s.done
    p0 = ui.prompts[0]
    assert p0.title == "timesync.confirm_first.title"
    assert p0.fields[0] == ("timesync.field.current", "Not set")
    assert feed(s, b"TIME 1 1800000000\n") == [b"OK 1800000000\n"]


def test_hello_and_errors_do_not_finish_session():
    s, ui, sc = session()
    out = feed(s, b"HELLO\nFOO\nTIME 2 5\nTIME 1 5\n" + b"X" * 100 + b"\nTIME 1 99999999999999999999999\n")
    assert out == [b"FEURISTIC TIME 1\n", b"ERR 1\n", b"ERR 2\n", b"ERR 3\n", b"ERR 6\n", b"ERR 3\n"]
    assert not s.done and not sc.is_set()


@pytest.mark.parametrize("value", [clock_mod.MIN_UNIX - 1, clock_mod.MAX_UNIX + 1, 0, 10**19])
def test_out_of_range(value):
    s, _, sc = session()
    assert feed(s, b"TIME 1 %d\n" % value) == [b"ERR 3\n"]
    assert not sc.is_set()


def test_range_boundaries():
    for v in (clock_mod.MIN_UNIX, clock_mod.MAX_UNIX):
        s, _, _ = session()
        assert feed(s, b"TIME 1 %d\n" % v) == [p.ok(v)]


def test_after_done_further_time_is_busy_but_hello_answered():
    s, _, sc = session()
    feed(s, b"TIME 1 1800000000\n")
    assert feed(s, b"TIME 1 1800000100\nHELLO\n") == [b"ERR 5\n", b"FEURISTIC TIME 1\n"]
    assert sc.now() == T


def test_small_adjustments_accepted_directly(clock):
    sc = clock_mod.SessionClock()
    sc.set(T)
    for v in (T - 60, T + 300, T + 10):
        s, ui, _ = session(clock=sc)
        assert feed(s, p.ok(v).replace(b"OK", b"TIME 1")) == [p.ok(v)]
        assert ui.prompts == []
        sc.set(T)


# -- confirmation flows (spec §4) ---------------------------------------------------------------


def test_backward_more_than_60s_requires_confirmation(clock):
    sc = clock_mod.SessionClock()
    sc.set(T)
    s, ui, _ = session(answers=[True], clock=sc)
    assert feed(s, b"TIME 1 1799996400\n") == [b"OK 1799996400\n"]
    pr = ui.prompts[0]
    assert (pr.kind, pr.title, pr.severity) == (
        "timesync.confirm",
        "timesync.confirm_backward.title",
        SENSITIVE,
    )
    assert pr.fields == (
        ("timesync.field.current", "2027-01-15 08:00:00 UTC"),
        ("timesync.field.new", "2027-01-15 07:00:00 UTC"),
        ("timesync.field.delta", "-01:00:00"),
    )
    assert sc.now() == T - 3600


def test_backward_refused_keeps_time(clock):
    sc = clock_mod.SessionClock()
    sc.set(T)
    s, ui, _ = session(answers=[False], clock=sc)
    assert feed(s, b"TIME 1 1799999939\n") == [b"ERR 4\n"]
    assert sc.now() == T
    assert not s.done
    assert len(ui.prompts) == 1


def test_forward_jump_shown_before_acceptance(clock):
    sc = clock_mod.SessionClock()
    sc.set(T)
    s, ui, _ = session(answers=[True], clock=sc)
    assert feed(s, b"TIME 1 1800086400\n") == [b"OK 1800086400\n"]
    pr = ui.prompts[0]
    assert pr.title == "timesync.confirm_forward.title"
    assert pr.fields[2] == ("timesync.field.delta", "+1 d 00:00:00")


def test_forward_refused(clock):
    sc = clock_mod.SessionClock()
    sc.set(T)
    s, _, _ = session(answers=[False], clock=sc)
    assert feed(s, b"TIME 1 1800000301\n") == [b"ERR 4\n"]
    assert sc.now() == T


@pytest.mark.parametrize("exc", [UserTimeout, UserCancelled])
def test_confirmation_errors_map_to_refused(clock, exc):
    class UI(ScriptedInteraction):
        async def confirm(self, prompt):
            raise exc

    sc = clock_mod.SessionClock()
    sc.set(T)
    s = p.TimeSyncSession(UI(), sc)
    assert run(s.handle_line(b"TIME 1 1700000000")) == b"ERR 3\n"  # below MIN_UNIX
    assert run(s.handle_line(b"TIME 1 1750000000")) == b"ERR 4\n"
    assert not s.busy


def test_time_spent_on_confirmation_is_compensated(clock):
    class SlowUI(ScriptedInteraction):
        async def confirm(self, prompt):
            clock.advance(12_400)
            return True

    sc = clock_mod.SessionClock()
    sc.set(T)
    s = p.TimeSyncSession(SlowUI(), sc)
    assert run(s.handle_line(b"TIME 1 1799990000")) == p.ok(1_799_990_012)
    assert sc.now() == 1_799_990_012


def test_reentrant_line_while_confirming_is_busy(clock):
    sc = clock_mod.SessionClock()
    sc.set(T)
    inner = []

    class UI(ScriptedInteraction):
        async def confirm(self, prompt):
            inner.append(run(s.handle_line(b"TIME 1 1800000001")))
            inner.append(run(s.handle_line(b"HELLO")))
            inner.append(run(s.handle_line(b"BAD")))
            return True

    s = p.TimeSyncSession(UI(), sc)
    assert run(s.handle_line(b"TIME 1 1799000000")) == b"OK 1799000000\n"
    assert inner == [b"ERR 5\n", b"FEURISTIC TIME 1\n", b"ERR 1\n"]
    assert not s.busy and s.done


def test_global_clock_default():
    try:
        clock_mod.CLOCK.clear()
        s = p.TimeSyncSession(ScriptedInteraction())
        assert run(s.feed(b"TIME 1 1800000000\r\n")) == [b"OK 1800000000\n"]
        assert clock_mod.CLOCK.now() == T
    finally:
        clock_mod.CLOCK.clear()


def test_french_prompt():
    from feuristic.core import i18n

    i18n.set_language(i18n.FR)
    try:
        s, ui, _ = session(answers=[True], confirm_first=True)
        feed(s, b"TIME 1 1800000000\n")
        assert ui.prompts[0].fields[0] == ("timesync.field.current", "Non réglée")
    finally:
        i18n.set_language(i18n.EN)


# -- robustness ------------------------------------------------------------------------------------

_ALLOWED = {b"FEURISTIC TIME 1\n"} | {p.err(c) for c in range(1, 7)}


@settings(max_examples=300, deadline=None)
@given(st.lists(st.binary(max_size=128), max_size=20), st.booleans())
def test_arbitrary_streams_never_crash(chunks, answer):
    s, _, sc = session(default=answer)
    lines_possible = 0
    out_all = []
    for c in chunks:
        out = feed(s, c)
        lines_possible += c.count(b"\n") + c.count(b"\r")
        for r in out:
            assert len(r) <= 24
            assert r in _ALLOWED or (r.startswith(b"OK ") and r.endswith(b"\n"))
        out_all += out
    assert len(out_all) <= lines_possible
    assert s.assembler.pending() <= p.MAX_LINE
    oks = [r for r in out_all if r.startswith(b"OK ")]
    assert len(oks) <= 1
    if oks:
        v = int(oks[0][3:-1])
        assert clock_mod.MIN_UNIX <= v <= clock_mod.MAX_UNIX


_tokens = st.sampled_from(
    [b"TIME", b"HELLO", b"1", b"2", b" ", b"  ", b"1800000000", b"-5", b"\r", b"\n", b"\r\n", b"x", b"\x00"]
)


@settings(max_examples=300, deadline=None)
@given(st.lists(_tokens, max_size=40))
def test_grammar_fuzz(tokens):
    s, _, _ = session()
    out = feed(s, b"".join(tokens))
    for r in out:
        assert r in _ALLOWED or r == b"OK 1800000000\n"
