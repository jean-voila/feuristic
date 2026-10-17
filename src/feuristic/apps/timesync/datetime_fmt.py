# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""UTC date formatting without the ``time`` module (not available on device).

:func:`civil_from_days` converts a day count relative to 1970-01-01 into a
proleptic Gregorian date using the branch-free algorithm of Howard Hinnant
("chrono-Compatible Low-Level Date Algorithms", ``civil_from_days``), which
is exact for every integer input. Floor division is used for negative
values (identical semantics on CPython and MicroPython).
"""

from micropython import const

_SECONDS_PER_DAY = const(86400)


def civil_from_days(days: int):
    """Return ``(year, month, day)`` for ``days`` since 1970-01-01."""
    z = days + 719468
    era = z // 146097
    doe = z - era * 146097  # [0, 146096]
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365  # [0, 399]
    y = yoe + era * 400
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)  # [0, 365]
    mp = (5 * doy + 2) // 153  # [0, 11]
    d = doy - (153 * mp + 2) // 5 + 1  # [1, 31]
    m = mp + 3 if mp < 10 else mp - 9  # [1, 12]
    if m <= 2:
        y += 1
    return y, m, d


def days_from_civil(y: int, m: int, d: int) -> int:
    """Inverse of :func:`civil_from_days`."""
    if m <= 2:
        y -= 1
    era = y // 400
    yoe = y - era * 400
    mp = m - 3 if m > 2 else m + 9
    doy = (153 * mp + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def _two(v: int) -> str:
    return ("0" + str(v)) if v < 10 else str(v)


def utc_fields(unix: int):
    """``(year, month, day, hour, minute, second)`` in UTC for UNIX seconds."""
    days = unix // _SECONDS_PER_DAY
    secs = unix - days * _SECONDS_PER_DAY
    y, m, d = civil_from_days(days)
    return y, m, d, secs // 3600, (secs // 60) % 60, secs % 60


def format_utc(unix: int) -> str:
    """``"YYYY-MM-DD HH:MM:SS UTC"`` (ISO 8601 calendar date, language neutral)."""
    y, m, d, hh, mm, ss = utc_fields(unix)
    ys = str(y) if y >= 0 else "-" + str(-y)
    if 0 <= y < 1000:
        ys = "0" * (4 - len(ys)) + ys
    return ys + "-" + _two(m) + "-" + _two(d) + " " + _two(hh) + ":" + _two(mm) + ":" + _two(ss) + " UTC"


def format_delta(seconds: int) -> str:
    """Signed duration, e.g. ``"+42 s"``, ``"-05:00"``, ``"+3 d 04:05:06"``."""
    sign = "-" if seconds < 0 else "+"
    s = -seconds if seconds < 0 else seconds
    if s < 60:
        return sign + str(s) + " s"
    days = s // _SECONDS_PER_DAY
    rem = s - days * _SECONDS_PER_DAY
    hh = rem // 3600
    mm = (rem // 60) % 60
    ss = rem % 60
    if days:
        return sign + str(days) + " d " + _two(hh) + ":" + _two(mm) + ":" + _two(ss)
    if hh:
        return sign + _two(hh) + ":" + _two(mm) + ":" + _two(ss)
    return sign + _two(mm) + ":" + _two(ss)
