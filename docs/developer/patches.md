<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Upstream patch maintenance

The superproject records an **unmodified upstream** commit. The ordered
[series](../../patches/series) contains changes to build integration, exclusive
USB modes, UI/translations, entry point, frozen modules, native bindings and
emulator entropy. Read each patch's `Feuristic-Rationale:` trailer before
changing its contract.

`tools/upstream.py` implements `apply`, `export`, `status`, `check`.
`apply` refuses tracked dirty files, detaches to the pinned base, resets the
submodule branch `feuristic/patched`, checks it out, then uses `git am --3way`.
It can discard local committed work on that branch and does not protect
untracked files. Never run it as an automatic fix in an active checkout.

The current project policy requires the checked-out branch to remain in place;
creating/switching branches or worktrees needs an explicit request. In an
already patched checkout inspect without mutation:

```sh
uv run python tools/upstream.py status
git -C upstream/trezor-firmware status --short
git -C upstream/trezor-firmware log --oneline
make patches-check
```

When an authorized integration task edits an upstream file, keep the change
on the current existing submodule branch, make logical commits with descriptive
messages and the rationale trailer, then regenerate:

```sh
make patches-export
make patches-check
```

Commit/push only when requested. Export rewrites all `*.patch` files and the
series list, so review their complete diff. Do not stage a changed
`upstream/trezor-firmware` gitlink when it merely points to local patch commits.
Application/native-library changes outside upstream belong directly to the
superproject, not duplicate copies inside patches.

For a clean reproduction, use the pinned base plus the exported series in a
separately authorized build environment. Check `git am` application, both
hardware builds, both emulator models, compatibility and relevant tests.
An upstream upgrade is a deliberate base change: review storage, cryptography,
USB endpoints/syscalls, UI APIs, licenses and build inputs; regenerate and
review every patch, then repeat R01–R16 on both revisions.

## Host CA bundle

The certifi patch updates the upstream host lockfile to 2026.10.19 for
[GHSA-6q48-6c7w-9gw2](https://github.com/certifi/python-certifi/security/advisories/GHSA-6q48-6c7w-9gw2).
Upstream normally delays newly released Python packages by 30 days. Only certifi
is exempted so the CA security fix can be selected. The frozen version and hashes
remain recorded in `uv.lock`; firmware application code is not changed.
