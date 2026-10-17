# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
import os
import re

import pytest

from feuristic.apps.otp import strings as otp_strings
from feuristic.apps.timesync import strings as ts_strings
from feuristic.core import i18n

PROMPT_KINDS = {
    "otp.export",
    "otp.hotp_generate",
    "otp.import",
    "otp.replace",
    "otp.delete",
    "timesync.confirm",
}
SRC = os.path.join(os.path.dirname(__file__), "..", "..", "..", "src", "feuristic", "apps")


@pytest.mark.parametrize(("mod", "prefix"), [(otp_strings, "otp."), (ts_strings, "timesync.")])
def test_tables_complete(mod, prefix):
    mod.register()
    mod.register()  # idempotent
    for key, (en, fr) in mod.STRINGS.items():
        assert key.startswith(prefix)
        assert key == key.lower()
        assert en.strip() and fr.strip(), key
        assert en.count("{}") == fr.count("{}"), key
    assert not [k for k in i18n.missing_translations() if k.startswith(prefix)]


@pytest.mark.parametrize(
    ("app", "mod", "prefix"), [("otp", otp_strings, "otp"), ("timesync", ts_strings, "timesync")]
)
def test_every_used_key_is_defined(app, mod, prefix):
    used = set()
    folder = os.path.join(SRC, app)
    for name in os.listdir(folder):
        if name.endswith(".py") and name != "strings.py":
            with open(os.path.join(folder, name), encoding="utf-8") as f:
                used |= set(re.findall(r'"(' + prefix + r'\.[a-z0-9_.]+)"', f.read()))
    used.discard(prefix + ".py")
    used -= PROMPT_KINDS  # Prompt.kind identifiers are not i18n keys
    missing = sorted(k for k in used if k not in mod.STRINGS)
    assert not missing


def test_french_uses_typographic_spacing():
    # French typography: a space before "?", "!" and ":"
    for _key, (_en, fr) in list(otp_strings.STRINGS.items()) + list(ts_strings.STRINGS.items()):
        for i, ch in enumerate(fr):
            if ch in "?!:":
                assert i > 0 and fr[i - 1] in " \u00a0\u202f", fr


def test_key_french_strings():
    assert otp_strings.STRINGS["otp.time_not_set"][1] == "Heure à synchroniser"
    assert "photographiant ce QR" in otp_strings.STRINGS["otp.export.warning"][1]
