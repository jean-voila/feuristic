#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Manage the feuristic patch series on top of the pinned upstream Trezor firmware.

The superproject pins ``upstream/trezor-firmware`` to an *unmodified* upstream
release commit. feuristic changes to upstream files live in ``patches/`` as a
``git format-patch`` series listed in ``patches/series``.

Commands::

    tools/upstream.py apply     # reset the submodule to the pinned commit and
                                # apply the series on branch feuristic/patched
    tools/upstream.py export    # regenerate patches/ from feuristic/patched
    tools/upstream.py status    # show base, branch and applied patches
    tools/upstream.py check     # fail if the superproject would record a
                                # patched submodule commit (used by CI/hooks)

Developer workflow: run ``apply``, edit files inside the submodule, commit
them there on ``feuristic/patched`` (one logical change per commit, with a
``Feuristic-Rationale:`` trailer), then run ``export`` and commit ``patches/``.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SUB = ROOT / "upstream" / "trezor-firmware"
PATCHES = ROOT / "patches"
SERIES = PATCHES / "series"
BRANCH = "feuristic/patched"
IDENTITY = ["-c", "user.name=feuristic build", "-c", "user.email=build@feuristic.invalid"]


def git(*args: str, cwd: Path = SUB, check: bool = True, capture: bool = True) -> str:
    r = subprocess.run(["git", *IDENTITY, *args], cwd=cwd, check=False, text=True, capture_output=capture)
    if check and r.returncode != 0:
        sys.stderr.write(r.stdout or "")
        sys.stderr.write(r.stderr or "")
        raise SystemExit(f"git {' '.join(args)} failed ({r.returncode})")
    return (r.stdout or "").strip()


def pinned_commit() -> str:
    """Commit recorded by the superproject for the submodule (the base)."""
    out = git("ls-tree", "HEAD", "upstream/trezor-firmware", cwd=ROOT)
    parts = out.split()
    if len(parts) < 3 or parts[1] != "commit":
        raise SystemExit("cannot determine pinned upstream commit")
    return parts[2]


def series() -> list[str]:
    if not SERIES.exists():
        return []
    names = []
    for raw in SERIES.read_text().splitlines():
        entry = raw.strip()
        if entry and not entry.startswith("#"):
            names.append(entry)
    return names


def cmd_apply(_args: argparse.Namespace) -> None:
    base = pinned_commit()
    dirty = git("status", "--porcelain", "--untracked-files=no")
    if dirty:
        raise SystemExit("submodule has uncommitted changes to tracked files; commit or stash them first")
    git("checkout", "-q", "--detach", base)
    git("branch", "-f", BRANCH, base)
    git("checkout", "-q", BRANCH)
    for name in series():
        patch = PATCHES / name
        if not patch.exists():
            raise SystemExit(f"missing patch {name}")
        r = subprocess.run(
            ["git", *IDENTITY, "am", "--3way", "--keep-cr", "--committer-date-is-author-date", str(patch)],
            cwd=SUB,
            text=True,
            capture_output=True,
            check=False,
        )
        if r.returncode != 0:
            sys.stderr.write(r.stdout + r.stderr)
            git("am", "--abort", check=False)
            raise SystemExit(f"failed to apply {name}")
        print(f"applied {name}")
    print(f"{len(series())} patch(es) applied on {BRANCH} (base {base[:12]})")


def cmd_export(_args: argparse.Namespace) -> None:
    base = pinned_commit()
    count = int(git("rev-list", "--count", f"{base}..{BRANCH}"))
    tmp = PATCHES / ".export"
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)
    git(
        "format-patch",
        "--quiet",
        "--no-signature",
        "--zero-commit",
        "--no-stat",
        "--full-index",
        "-N",
        "-o",
        str(tmp),
        f"{base}..{BRANCH}",
    )
    for old in PATCHES.glob("*.patch"):
        old.unlink()
    names = []
    for p in sorted(tmp.glob("*.patch")):
        dest = PATCHES / p.name
        p.rename(dest)
        names.append(p.name)
    tmp.rmdir()
    header = (
        "# feuristic patch series applied on top of the pinned upstream commit.\n"
        "# Managed by tools/upstream.py — do not edit by hand.\n"
    )
    SERIES.write_text(header + "".join(n + "\n" for n in names))
    print(f"exported {count} patch(es)")


def cmd_status(_args: argparse.Namespace) -> None:
    base = pinned_commit()
    head = git("rev-parse", "HEAD")
    branch = git("rev-parse", "--abbrev-ref", "HEAD")
    print(f"pinned base : {base}")
    print(f"submodule   : {head} ({branch})")
    print(f"series      : {len(series())} patch(es)")
    print(git("log", "--oneline", f"{base}..HEAD") or "(no feuristic commits applied)")


def cmd_check(_args: argparse.Namespace) -> None:
    staged = git("diff", "--cached", "--name-only", cwd=ROOT).splitlines()
    if "upstream/trezor-firmware" in staged:
        raise SystemExit(
            "refusing: the submodule pointer is staged; feuristic must pin an unmodified upstream commit"
        )
    print("ok")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in (
        ("apply", cmd_apply),
        ("export", cmd_export),
        ("status", cmd_status),
        ("check", cmd_check),
    ):
        sub.add_parser(name).set_defaults(fn=fn)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
