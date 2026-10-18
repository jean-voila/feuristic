# Contributing to feuristic

Thank you for your interest! feuristic is security-sensitive firmware, so
contributions are held to a high bar of clarity, tests and review.

## Ground rules

* Licence: contributions are accepted under **GPL-3.0-only**. Every new
  file starts with `SPDX-License-Identifier: GPL-3.0-only` and a copyright
  line (`tools/check_spdx.py` checks it).
* Never weaken a security property silently: anything touching keys, PINs,
  confirmations, USB parsing or storage needs a rationale in the commit
  message and tests demonstrating the property.
* No cryptocurrency features, no telemetry, no network services, no
  companion application requirement (spec §1).

## Workflow

1. `make setup`, then create a branch.
2. Code + tests (see below). Keep commits focused; write descriptive
   messages (what and **why**).
3. `make lint test` locally (and `make emu test-functional` for anything
   that touches firmware behaviour).
4. Open a pull request. CI must be green: lint, host tests (coverage gate),
   C tests with sanitizers, fuzzing, firmware builds for both models,
   emulator functional tests.

## Where code goes

| Change | Location | Tests |
|---|---|---|
| protocol / application logic | `src/feuristic/apps`, `src/feuristic/core` (shared code, MicroPython rules: [docs/developer/micropython-compat.md](docs/developer/micropython-compat.md)) | `tests/host` (+ `tests/upy` for platform behaviour) |
| device UI, boot, USB glue | `src/feuristic/ui`, `src/feuristic/fw` | `tests/functional` |
| image/QR/FAT/RSA C code | `lib/` (freestanding C99, no malloc) | `tests/c` + a fuzz target in `tests/fuzz` |
| kernel USB classes, MicroPython C modules | `firmware/` | emulator + functional tests |
| changes to upstream files | commit inside `upstream/trezor-firmware` on `feuristic/patched`, then `make patches-export` | — |

Upstream changes must stay small and be explained in the patch commit
message with a `Feuristic-Rationale:` trailer. The superproject always
pins an **unmodified** upstream commit (`make patches-check`).

## Style

* Python: `ruff check` / `ruff format` (line length 110).
* C: `clang-format` (upstream `.clang-format`), `-Wall -Wextra -Werror`.
* Documentation in English; user-facing strings in English **and** French
  (`strings.py` next to each application).

## Code of conduct

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
