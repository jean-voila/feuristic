# Contributing to Feuristic

Feuristic accepts focused fixes, documentation, hardware test results and
protocol improvements. Check existing issues before beginning a large change.
For vulnerabilities, use [the private reporting procedure](SECURITY.md).

## Before you start

Read the [architecture](docs/architecture.md), [threat model](docs/threat-model.md)
and the relevant protocol. Install the [build environment](docs/developer/building.md).
Documentation-only work needs just `uv sync --frozen --only-group docs`.

Contributions are GPL-3.0-only. You must have the right to contribute the code
and preserve upstream notices. New owned source files need the SPDX header and
copyright line checked by `tools/check_spdx.py`. No contributor license agreement
is required.

## Pull request review

1. Describe a concrete problem and the resulting behavior. Link its issue where
   available. Keep unrelated changes in separate pull requests.
2. Explain effects on PINs, physical consent, USB parsing, storage, keys or
   recovery. A security property must not be weakened silently.
3. Include the checks actually executed, model/OS and evidence. Label skipped
   hardware tests explicitly; emulator results are not physical results.
4. Add a regression test when behavior changes. User-facing strings need English
   and French; run the translation generator if tables change.
5. A maintainer reviews correctness, security, licenses and test coverage. All
   required automated checks must pass before merge. At least one approving
   maintainer review is expected for code changes; security-sensitive changes
   need a reviewer familiar with the affected protocol.

Do not include PINs, seeds, private keys, real QR backups, personal device IDs or
unrelated environment dumps. Use disposable identities in reproductions.

## Checks by change type

| Change | Run |
|---|---|
| Documentation | `uv run --group docs mkdocs build --strict` |
| Python logic | `make test-host` and `make lint` |
| Device UI / USB / boot | Host checks and the affected functional tests on both model emulators |
| C parsers / crypto / USB | `make test-c`, ARM cross checks and the relevant fuzz targets |
| Firmware candidate | Both builds, required CI and the applicable physical acceptance procedures |

See [testing](docs/developer/testing.md). Run the affected checks first; reviewers
may request additional evidence. Hardware reports belong in `docs/acceptance/`.

## Upstream changes

Keep upstream modifications small, documented in `patches/`, with a
`Feuristic-Rationale:` trailer. Do not stage the patched submodule gitlink.
Use the [patch guide](docs/developer/patches.md); do not reset another prepared
working tree as a routine repair.

## Scope and style

No cryptocurrency features, telemetry, required companion service or network
account. Python follows Ruff and MicroPython compatibility rules; C follows
clang-format and warning-as-error checks. Keep code and commits descriptive.

Participation follows the [Code of Conduct](CODE_OF_CONDUCT.md).
