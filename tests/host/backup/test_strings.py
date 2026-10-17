# SPDX-License-Identifier: GPL-3.0-only
import os
import re

import pytest

from feuristic.apps.backup import errors, strings
from feuristic.apps.importer import strings as importer_strings
from feuristic.core import errors as core_errors
from feuristic.core import i18n

SRC = os.path.join(os.path.dirname(__file__), "..", "..", "..", "src", "feuristic", "apps")


@pytest.fixture(autouse=True)
def _registered():
    strings.register()
    importer_strings.register()
    yield
    i18n.set_language(i18n.EN)


@pytest.mark.parametrize("table", [strings.STRINGS, importer_strings.STRINGS])
def test_complete_translations(table):
    for key, (en, fr) in table.items():
        assert en and fr, key
        assert en.count("{}") == fr.count("{}"), key
        assert key.startswith(("backup.", "importer."))


def test_french_is_actually_french():
    differ = [k for k, (en, fr) in strings.STRINGS.items() if en != fr]
    assert len(differ) >= len(strings.STRINGS) - 2  # "Type" is the same in both
    i18n.set_language(i18n.FR)
    assert "inexportables" in i18n.t("backup.warn.recoverable")
    assert i18n.t("backup.frame.counter", 2, 5) == "QR 2 sur 5"


def test_every_key_used_in_code_exists():
    keys = set(i18n.keys())
    pattern = re.compile(r'"((?:backup|importer)\.[a-z0-9_.]+)"')
    used = set()
    for sub in ("backup", "importer"):
        d = os.path.join(SRC, sub)
        for name in os.listdir(d):
            if name.endswith(".py") and name != "strings.py":
                with open(os.path.join(d, name), encoding="utf-8") as f:
                    used |= set(pattern.findall(f.read()))
    # prompt kinds / notify kinds are identifiers, not necessarily strings
    kinds = {
        "backup.export",
        "backup.export_full",
        "backup.restore",
        "backup.overwrite",
        "backup.restore_incomplete",
        "backup.restore_done",
    }
    missing = sorted(k for k in used - kinds if k not in keys)
    assert missing == []


@pytest.mark.parametrize(
    ("exc", "key"),
    [
        (errors.UnsupportedVersion("x"), "backup.err.version"),
        (errors.UnsupportedParameters("x"), "backup.err.params"),
        (errors.BackupFormatError("x"), "backup.err.format"),
        (errors.AuthenticationFailed("x"), "backup.err.auth"),
        (errors.PlaintextError("x"), "backup.err.plaintext"),
        (errors.WeakPassphrase("x"), "backup.err.weak"),
        (errors.UnsupportedItem("x"), "backup.err.item"),
        (errors.FrameChecksumError("x"), "backup.err.checksum"),
        (errors.FrameIdMismatch("x"), "backup.err.other_backup"),
        (errors.FrameTotalMismatch("x"), "backup.err.total"),
        (errors.FrameConflict("x"), "backup.err.conflict"),
        (errors.FrameLimitExceeded("x"), "backup.err.limit"),
        (errors.FrameIncomplete([1, 2]), "backup.err.missing"),
        (errors.FrameFormatError("x"), "backup.err.frame"),
        (core_errors.StorageFull("x"), "backup.err.storage_full"),
        (core_errors.UserCancelled("x"), "backup.err.cancelled"),
        (ValueError("x"), "backup.err.format"),
    ],
)
def test_error_keys(exc, key):
    assert strings.error_key(exc) == key
    assert key in set(i18n.keys())


def test_error_hierarchy():
    assert issubclass(errors.FrameError, core_errors.InvalidInput)
    assert issubclass(errors.AuthenticationFailed, core_errors.FeuristicError)
    assert not issubclass(errors.AuthenticationFailed, core_errors.InvalidInput)
    assert errors.FrameIncomplete([3]).missing == [3]
