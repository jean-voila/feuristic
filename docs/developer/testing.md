<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Testing and evidence

All commands run at repository root. A passing host test is evidence for that
layer; it does not satisfy a real-hardware criterion in [the acceptance
matrix](../acceptance/README.md). Record exact commit, source cleanliness,
command, environment, results, skips and artifact hashes.

| Layer | Command | What it establishes |
|---|---|---|
| Lint/compatibility | `make lint` | Python, native formatting, SPDX and MicroPython restrictions |
| Host | `make test-host` | protocol logic, vectors, bounds, storage model |
| Coverage | `make coverage` | branch coverage for configured host sources; UI/glue exclusions remain |
| Portable C | `make test-c` | CTest with ASan/UBSan |
| MCU cross compile | `tools/ci/arm-cross-check.sh` | portable libraries compile for Cortex-M4/M33 with warnings as errors |
| MicroPython | `make test-upy` | actual emulator runtime, native module bindings and norcow tests |
| Functional | `make test-functional` | UDP transports and debuglink flows through emulator |
| Fuzz | `FUZZ_SECONDS=60 make fuzz` | bounded smoke campaign, not proof of parser correctness |
| PC/SC interop | commands below | real host tools over virtual reader |
| Hardware | R01–R16 | physical USB, OLED/camera, RAM, timing, flash and OS interoperability |

`make test` runs host, C and functional suites, not every row above. CI runs
additional ARM/fuzz checks and scheduled reproducibility. `make lint` does not
itself run shellcheck; CI separately runs `shellcheck tools/*.sh tools/ci/*.sh`.

## Both emulator models

```sh
make emu MODEL=T3B1
uv run pytest -q tests/functional --junitxml=build/functional-T3B1.xml
make emu MODEL=T2B1
FEURISTIC_EMU="$PWD/upstream/trezor-firmware/core/build-xtask/artifacts/T2B1/firmware-emu" \
  uv run pytest -q tests/functional --junitxml=build/functional-T2B1.xml
```

The harness starts separate processes/profiles and allocates ports in steps
of 16 from `FEURISTIC_EMU_BASE_PORT` (default 22000). Use a distinct base range
for concurrent pytest invocations. A missing emulator causes skips: inspect
the summary and require actual executions. The harness uses a 20 MiB heap;
measure memory on each MCU separately.

Targeted regressions:

```sh
uv run pytest -q tests/host/fido2/test_capacity_budget.py tests/host/core/test_storage_budget.py
uv run pytest -q tests/host/backup tests/host/importer
uv run pytest -q tests/functional/test_import.py tests/functional/test_timesync.py
uv run pytest -q tests/functional/test_upy.py
```

Storage details: [storage-budget.md](storage-budget.md). Native corpus,
fuzzer and benchmark details: [fqr](lib-fqr.md), [fimg](lib-fimg.md),
[fmsc](lib-fmsc.md), [RSA](rsa.md) and [fuzz targets](../../tests/fuzz/).
Power-cut injection in a model and orderly emulator shutdown cannot replace
interrupting real flash writes.

## Linux interoperability

Use a dedicated Linux test host. Install packages and start PC/SC using the
same sequence as CI:

```sh
sudo apt-get update
sudo apt-get install -y pcscd vsmartcard-vpcd opensc gnupg scdaemon
sudo systemctl stop pcscd.socket pcscd.service
sudo pcscd --disable-polkit
FEURISTIC_INTEROP=1 uv run pytest -v tests/functional/interop --junitxml=build/interop.xml
```

This changes the host PC/SC service state; record/restore its normal service
configuration after the run. The fixtures create an isolated GnuPG home and
start `tools/vpcd_bridge.py`; do not also connect a competing manual bridge.
The present suite checks GnuPG detection/generation/signing, PIV detection and
GET CHALLENGE. It does not constitute the complete R09/R10 OS matrix.

## Failure handling

Keep emulator logs from the failing profile, JUnit XML, command and traceback.
Minimize hostile inputs and preserve a hash and generation seed. Re-run the
failed layer after a fix, then its affected integration tests. Never publish
real test secrets, PINs, private camera backups or unredacted APDU transcripts
containing credentials. Security reporting: [SECURITY.md](../../SECURITY.md).
