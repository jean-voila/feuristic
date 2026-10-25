# SPDX-License-Identifier: GPL-3.0-only
"""Guards for the hardware security boundary (docs/hardware-security.md).

feuristic relies on upstream for every secure-element, secret-sector and
bootloader operation. These checks fail if a change starts to:

* call the Optiga Trust M directly (metadata writes, key generation, the
  ``set_sec_max`` throttle) from feuristic code, which could make the secure
  element unusable for upstream PIN stretching or for official firmware;
* patch upstream's secure element, secret storage, PIN storage, boot chain,
  vendor headers or firmware version/monotonic counters, which would change
  native Trezor protections or burn irreversible monotonic counters;
* build with upstream's ``--production`` flag, which permanently locks
  Optiga object metadata (LcsO = operational).
"""

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
PATCHES = sorted((ROOT / "patches").glob("*.patch"))

PROTECTED_UPSTREAM_PREFIXES = (
    "core/embed/sec/",
    "storage/",
    "core/embed/projects/bootloader/",
    "core/embed/projects/boardloader/",
    "core/embed/projects/prodtest/",
    "core/embed/projects/secmon/",
    "core/embed/models/",
    "core/embed/projects/firmware/version.h",
    "core/embed/upymod/modtrezorcrypto/modtrezorcrypto-optiga.h",
    "core/embed/upymod/modtrezorconfig/",
)

# Code references only (imports, calls, C identifiers); prose may name the chip.
FORBIDDEN_OPTIGA_TOKENS = re.compile(
    r"\boptiga\s*\.|import\s+[\w., ]*optiga|from\s+[\w.]*optiga"
    r"|\boptiga_\w+\s*\(|set_sec_max|\bOPTIGA_\w+|sec/optiga"
)


def _patched_paths():
    for patch in PATCHES:
        for line in patch.read_text(errors="replace").splitlines():
            m = re.match(r"^diff --git a/(\S+) b/(\S+)$", line)
            if m:
                yield patch.name, m.group(2)


def _added_lines():
    for patch in PATCHES:
        for line in patch.read_text(errors="replace").splitlines():
            if line.startswith("+") and not line.startswith("+++"):
                yield patch.name, line[1:]


@pytest.mark.parametrize(
    "code",
    [
        "from trezorcrypto import optiga",
        "import trezorcrypto.optiga",
        "optiga.set_sec_max()",
        "optiga.sign(2, digest)",
        "optiga_set_data_object(OID, true, buf, n);",
        "#include <sec/optiga.h>",
        "uint16_t oid = OPTIGA_OID_ECC_KEY + 1;",
    ],
)
def test_guard_pattern_matches_real_access(code):
    assert FORBIDDEN_OPTIGA_TOKENS.search(code)


def test_guard_pattern_ignores_prose():
    assert not FORBIDDEN_OPTIGA_TOKENS.search("the Optiga attestation objects are lost")


def test_patch_series_is_present():
    assert PATCHES, "patch series missing"


def test_patches_leave_native_security_code_untouched():
    touched = [
        (name, path)
        for name, path in _patched_paths()
        if any(path == p or path.startswith(p) for p in PROTECTED_UPSTREAM_PREFIXES)
    ]
    assert touched == []


def test_patches_add_no_direct_optiga_access():
    hits = [(name, text) for name, text in _added_lines() if FORBIDDEN_OPTIGA_TOKENS.search(text)]
    assert hits == []


@pytest.mark.parametrize("subdir", ["src/feuristic", "firmware", "lib"])
def test_feuristic_sources_do_not_drive_the_secure_element(subdir):
    hits = []
    for path in (ROOT / subdir).rglob("*"):
        if path.suffix not in (".py", ".c", ".h") or "__pycache__" in path.parts:
            continue
        for n, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
            if FORBIDDEN_OPTIGA_TOKENS.search(line):
                hits.append(f"{path.relative_to(ROOT)}:{n}")
    assert hits == []


def _build_entry_points():
    yield ROOT / "Makefile"
    yield from (ROOT / "tools").glob("*.sh")
    yield from (ROOT / "tools" / "ci").glob("*.sh")
    yield from (ROOT / ".github" / "workflows").glob("*.yml")


def test_builds_never_request_production_mode():
    hits = []
    for path in _build_entry_points():
        text = path.read_text(errors="replace")
        if re.search(r"--production|PRODUCTION\s*[:=]\s*1", text):
            hits.append(str(path.relative_to(ROOT)))
    assert hits == []


def test_release_builds_keep_debuglink_out():
    """The release target must not enable debuglink (a host-controlled UI)."""
    makefile = (ROOT / "Makefile").read_text()
    m = re.search(r"^firmware:.*?\n((?:\t.*\n)+)", makefile, re.MULTILINE)
    assert m is not None
    recipe = m.group(1)
    assert "xtask build firmware" in recipe
    assert "--debug-link" not in recipe
    assert "--pyopt=false" not in recipe
