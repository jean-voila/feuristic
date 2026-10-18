# SPDX-License-Identifier: GPL-3.0-only
# feuristic — top-level build and test entry points.
#
#   make help                 list targets
#   make setup                fetch submodules, apply patches, install Python deps
#   make firmware MODEL=T2B1  release firmware (T2B1 or T3B1)
#   make firmware-debug       debug firmware (debuglink, logs)
#   make emu                  emulator (debuglink, used by functional tests)
#   make test                 every test suite that runs on this machine
#
# Local builds use tools/env.sh (macOS/Linux with rustup + ARM GNU toolchain);
# CI and reproducible release builds use upstream's Nix shell (make nix-firmware).

SHELL := /bin/bash
MODEL ?= T3B1
model_lc = $(shell echo $(MODEL) | tr A-Z a-z)
UPSTREAM := upstream/trezor-firmware
CORE := $(UPSTREAM)/core
ENV := source tools/env.sh &&
UV ?= uv
ARTIFACTS := $(CORE)/build-xtask/artifacts/$(MODEL)
DIST := dist
VERSION := $(shell $(UV) run --quiet python -c "import sys; sys.path.insert(0,'src'); from feuristic.version import VERSION; print(VERSION)" 2>/dev/null)
GITREV := $(shell git rev-parse --short=12 HEAD)

.PHONY: help setup patches patches-export patches-check firmware firmware-debug emu \
        test test-host test-c test-upy test-functional fuzz lint format compat \
        coverage sbom dist clean

help: ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n",$$1,$$2}'

setup: ## fetch submodules, apply the patch series, install Python deps
	git submodule update --init --depth 1 $(UPSTREAM)
	cd $(UPSTREAM) && git submodule update --init --depth 1 vendor/micropython vendor/QR-Code-generator \
	  vendor/secp256k1-zkp vendor/cmsis_device_u5 vendor/cmsis_5 vendor/stm32u5xx_hal_driver \
	  vendor/mldsa-native vendor/libtropic vendor/sphincsplus vendor/ts-tvl vendor/fido2-tests vendor/nanopb
	cd $(UPSTREAM)/vendor/micropython && git submodule update --init --depth 1 lib/stm32lib
	$(MAKE) patches
	cd $(UPSTREAM) && $(UV) sync
	$(UV) sync

patches: ## (re)apply patches/ onto the pinned upstream commit
	$(UV) run python tools/upstream.py apply

patches-export: ## regenerate patches/ from the feuristic/patched branch
	$(UV) run python tools/upstream.py export

patches-check: ## refuse to record a patched submodule commit
	$(UV) run python tools/upstream.py check

firmware: ## release firmware for MODEL (T2B1 or T3B1)
	$(ENV) cd $(CORE) && xtask build firmware -m $(model_lc)
	@mkdir -p $(DIST)
	cp $(ARTIFACTS)/firmware.bin $(DIST)/feuristic-$(VERSION)-$(MODEL)-$(GITREV).bin
	cd $(DIST) && shasum -a 256 feuristic-$(VERSION)-$(MODEL)-$(GITREV).bin > feuristic-$(VERSION)-$(MODEL)-$(GITREV).bin.sha256
	@echo "built $(DIST)/feuristic-$(VERSION)-$(MODEL)-$(GITREV).bin"

firmware-debug: ## debug firmware for MODEL (debuglink, assertions, logs)
	$(ENV) cd $(CORE) && xtask build firmware -m $(model_lc) --pyopt=false --debug-link
	@mkdir -p $(DIST)
	cp $(ARTIFACTS)/firmware.bin $(DIST)/feuristic-$(VERSION)-$(MODEL)-$(GITREV)-DEBUG.bin

emu: ## emulator with debuglink (MODEL=T3B1 or T2B1)
	$(ENV) cd $(CORE) && xtask build firmware --emulator -m $(model_lc) --debug-link --disable-animation

emu-run: ## run the emulator in a window (Ctrl-C to quit)
	cd $(CORE)/src && TREZOR_PROFILE_DIR=$${TREZOR_PROFILE_DIR:-/tmp/feuristic-emu} \
	  ../build-xtask/artifacts/$(MODEL)/firmware-emu -O0 -X heapsize=20M -m main

test: test-host test-c test-functional ## run every local test suite

test-host: ## CPython unit tests (fast)
	$(UV) run pytest -q tests/host

coverage: ## CPython unit tests with branch coverage report
	$(UV) run pytest -q tests/host --cov --cov-report=term-missing --cov-report=xml

test-c: ## C unit tests of lib/ with ASan/UBSan
	cmake -S tests/c -B build/c -DFEURISTIC_SANITIZE=ON -DCMAKE_BUILD_TYPE=Debug
	cmake --build build/c -j
	ctest --test-dir build/c --output-on-failure

test-upy: ## MicroPython unit tests inside the emulator (needs `make emu`)
	$(UV) run pytest -q tests/functional/test_upy.py

test-functional: ## end-to-end tests against the emulator (needs `make emu`)
	$(UV) run pytest -q tests/functional

fuzz: ## run each libFuzzer target for FUZZ_SECONDS (default 60)
	tools/fuzz.sh $${FUZZ_SECONDS:-60}

lint: ## ruff, MicroPython compatibility, clang-format, shellcheck
	$(UV) run ruff check src tests tools
	$(UV) run ruff format --check src tests tools
	$(UV) run python tools/check_upy_compat.py
	tools/check_c_format.sh
	tools/check_spdx.py

format: ## auto-format Python and C sources
	$(UV) run ruff format src tests tools
	$(UV) run ruff check --fix src tests tools
	tools/check_c_format.sh --fix

compat: ## MicroPython compatibility check only
	$(UV) run python tools/check_upy_compat.py

sbom: ## SPDX SBOM for the current tree
	$(UV) run python tools/sbom.py --output $(DIST)/feuristic-$(VERSION)-$(GITREV).spdx.json

dist: ## release artifacts for both models + SBOM + checksums
	$(MAKE) firmware MODEL=T2B1
	$(MAKE) firmware MODEL=T3B1
	$(MAKE) sbom

clean: ## remove feuristic build outputs (keeps upstream caches)
	rm -rf build dist .pytest_cache .ruff_cache .coverage coverage.xml
