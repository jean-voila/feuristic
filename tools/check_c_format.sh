#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Check (or with --fix, apply) clang-format on feuristic-owned C sources.
# Vendored code (lib/third_party) is never reformatted.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
ROOT_VENV_CF=$ROOT/.venv/bin/clang-format
CF=${CLANG_FORMAT:-$ROOT_VENV_CF}
if [ ! -x "$CF" ]; then
  echo "clang-format not found; skipping C format check" >&2
  exit 0
fi
cd "$ROOT"
files=()
while IFS= read -r f; do files+=("$f"); done < <(git ls-files 'lib/*.c' 'lib/*.h' 'firmware/*.c' 'firmware/*.h' \
  'tests/c/*.c' 'tests/c/*.h' 'tests/fuzz/*.c' 'tests/fuzz/*.h' | grep -v '^lib/third_party/' \
  | grep -v '_vectors.h$' | grep -v '_table.h$')
if [ "${1:-}" = "--fix" ]; then
  "$CF" -i --style=file "${files[@]}"
else
  "$CF" --dry-run --Werror --style=file "${files[@]}"
fi
