# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
import datetime

import pytest
from hypothesis import given
from hypothesis import strategies as st

from feuristic.apps.timesync import datetime_fmt as f

EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.UTC)
MIN_TS = int((datetime.datetime(1, 1, 1, tzinfo=datetime.UTC) - EPOCH).total_seconds())
MAX_TS = int((datetime.datetime(9999, 12, 31, 23, 59, 59, tzinfo=datetime.UTC) - EPOCH).total_seconds())


def _ref(ts):
    return EPOCH + datetime.timedelta(seconds=ts)


@pytest.mark.parametrize(
    ("ts", "text"),
    [
        (0, "1970-01-01 00:00:00 UTC"),
        (-1, "1969-12-31 23:59:59 UTC"),
        (951782400, "2000-02-29 00:00:00 UTC"),
        (1_704_067_200, "2024-01-01 00:00:00 UTC"),
        (1_709_164_800, "2024-02-29 00:00:00 UTC"),
        (1_800_000_000, "2027-01-15 08:00:00 UTC"),
        (2_147_483_647, "2038-01-19 03:14:07 UTC"),
        (4_102_444_800, "2100-01-01 00:00:00 UTC"),
        (4_107_456_000, "2100-02-28 00:00:00 UTC"),
        (4_107_542_400, "2100-03-01 00:00:00 UTC"),
        (MIN_TS, "0001-01-01 00:00:00 UTC"),
        (MAX_TS, "9999-12-31 23:59:59 UTC"),
    ],
)
def test_known_dates(ts, text):
    assert f.format_utc(ts) == text


@given(st.integers(min_value=MIN_TS, max_value=MAX_TS))
def test_matches_python_datetime(ts):
    d = _ref(ts)
    assert f.utc_fields(ts) == (d.year, d.month, d.day, d.hour, d.minute, d.second)
    assert f.format_utc(ts) == d.strftime("%Y-%m-%d %H:%M:%S UTC").rjust(23, "0")


@given(st.integers(min_value=-(10**9), max_value=10**9))
def test_days_roundtrip(days):
    y, m, d = f.civil_from_days(days)
    assert 1 <= m <= 12 and 1 <= d <= 31
    assert f.days_from_civil(y, m, d) == days


def test_far_years_formatting():
    assert f.format_utc(-62_167_219_200).startswith("0000-01-01")
    assert f.format_utc(-62_198_755_200).startswith("-1-01-01")
    assert f.format_utc(253_402_300_800).startswith("10000-01-01")


@pytest.mark.parametrize(
    ("delta", "text"),
    [
        (0, "+0 s"),
        (59, "+59 s"),
        (-59, "-59 s"),
        (60, "+01:00"),
        (-305, "-05:05"),
        (3600, "+01:00:00"),
        (-3661, "-01:01:01"),
        (86400, "+1 d 00:00:00"),
        (3 * 86400 + 4 * 3600 + 5 * 60 + 6, "+3 d 04:05:06"),
        (-400 * 86400, "-400 d 00:00:00"),
    ],
)
def test_format_delta(delta, text):
    assert f.format_delta(delta) == text
