# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Generate lib/fqr/src/fqr_tables.c (ISO/IEC 18004 constants for lib/fqr).

The tables are computed from closed-form definitions (GF(256) arithmetic,
BCH codes, alignment-pattern spacing rule, raw module counts) and the
per-version error-correction block table of ISO/IEC 18004:2015 Table 9.
Every value is cross-checked against the independent tables shipped with
`segno` (ISO/IEC 18004 Tables 9, C.1, D.1 and E.1) before the C file is
written, so a transcription error makes this script fail.

Usage:  uv run python lib/fqr/tools/gen_tables.py [--check]
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

import segno.consts as sc

OUT = pathlib.Path(__file__).resolve().parents[1] / "src" / "fqr_tables.c"

# ISO/IEC 18004:2015 Table 9 — error correction codewords per block and
# number of blocks, indexed [level][version] with level order L, M, Q, H.
ECC_PER_BLOCK = (
    (
        0,
        7,
        10,
        15,
        20,
        26,
        18,
        20,
        24,
        30,
        18,
        20,
        24,
        26,
        30,
        22,
        24,
        28,
        30,
        28,
        28,
        28,
        28,
        30,
        30,
        26,
        28,
        30,
        30,
        30,
        30,
        30,
        30,
        30,
        30,
        30,
        30,
        30,
        30,
        30,
        30,
    ),
    (
        0,
        10,
        16,
        26,
        18,
        24,
        16,
        18,
        22,
        22,
        26,
        30,
        22,
        22,
        24,
        24,
        28,
        28,
        26,
        26,
        26,
        26,
        28,
        28,
        28,
        28,
        28,
        28,
        28,
        28,
        28,
        28,
        28,
        28,
        28,
        28,
        28,
        28,
        28,
        28,
        28,
    ),
    (
        0,
        13,
        22,
        18,
        26,
        18,
        24,
        18,
        22,
        20,
        24,
        28,
        26,
        24,
        20,
        30,
        24,
        28,
        28,
        26,
        30,
        28,
        30,
        30,
        30,
        30,
        28,
        30,
        30,
        30,
        30,
        30,
        30,
        30,
        30,
        30,
        30,
        30,
        30,
        30,
        30,
    ),
    (
        0,
        17,
        28,
        22,
        16,
        22,
        28,
        26,
        26,
        24,
        28,
        24,
        28,
        22,
        24,
        24,
        30,
        28,
        28,
        26,
        28,
        30,
        24,
        30,
        30,
        30,
        30,
        30,
        30,
        30,
        30,
        30,
        30,
        30,
        30,
        30,
        30,
        30,
        30,
        30,
        30,
    ),
)
NUM_BLOCKS = (
    (
        0,
        1,
        1,
        1,
        1,
        1,
        2,
        2,
        2,
        2,
        4,
        4,
        4,
        4,
        4,
        6,
        6,
        6,
        6,
        7,
        8,
        8,
        9,
        9,
        10,
        12,
        12,
        12,
        13,
        14,
        15,
        16,
        17,
        18,
        19,
        19,
        20,
        21,
        22,
        24,
        25,
    ),
    (
        0,
        1,
        1,
        1,
        2,
        2,
        4,
        4,
        4,
        5,
        5,
        5,
        8,
        9,
        9,
        10,
        10,
        11,
        13,
        14,
        16,
        17,
        17,
        18,
        20,
        21,
        23,
        25,
        26,
        28,
        29,
        31,
        33,
        35,
        37,
        38,
        40,
        43,
        45,
        47,
        49,
    ),
    (
        0,
        1,
        1,
        2,
        2,
        4,
        4,
        6,
        6,
        8,
        8,
        8,
        10,
        12,
        16,
        12,
        17,
        16,
        18,
        21,
        20,
        23,
        23,
        25,
        27,
        29,
        34,
        34,
        35,
        38,
        40,
        43,
        45,
        48,
        51,
        53,
        56,
        59,
        62,
        65,
        68,
    ),
    (
        0,
        1,
        1,
        2,
        4,
        4,
        4,
        5,
        6,
        8,
        8,
        11,
        11,
        16,
        16,
        18,
        16,
        19,
        21,
        25,
        25,
        25,
        34,
        30,
        32,
        35,
        37,
        40,
        42,
        45,
        48,
        51,
        54,
        57,
        60,
        63,
        66,
        70,
        74,
        77,
        81,
    ),
)
SEGNO_LEVEL = (sc.ERROR_LEVEL_L, sc.ERROR_LEVEL_M, sc.ERROR_LEVEL_Q, sc.ERROR_LEVEL_H)
FORMAT_LEVEL_BITS = (1, 0, 3, 2)  # L, M, Q, H as encoded in format information


def raw_modules(ver: int) -> int:
    n = (16 * ver + 128) * ver + 64
    if ver >= 2:
        na = ver // 7 + 2
        n -= (25 * na - 10) * na - 55
        if ver >= 7:
            n -= 36
    return n


def align_pos(ver: int) -> list[int]:
    if ver == 1:
        return []
    na = ver // 7 + 2
    step = (ver * 8 + na * 3 + 5) // (na * 4 - 4) * 2
    res = [0] * na
    pos = ver * 4 + 10
    for i in range(na - 1, 0, -1):
        res[i] = pos
        pos -= step
    res[0] = 6
    return res


def bch(value: int, nbits: int, gen: int, gen_deg: int) -> int:
    rem = value << gen_deg
    for i in range(nbits + gen_deg - 1, gen_deg - 1, -1):
        if rem >> i & 1:
            rem ^= gen << (i - gen_deg)
    return value << gen_deg | rem


def main() -> int:
    # GF(256), primitive polynomial x^8+x^4+x^3+x^2+1 (0x11D), generator 2.
    exp = [0] * 512
    log = [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        x <<= 1
        if x & 0x100:
            x ^= 0x11D
    for i in range(255, 512):
        exp[i] = exp[i - 255]
    assert tuple(exp[:255]) == tuple(sc.GALIOS_EXP[:255]), "GF exp mismatch"

    # Block structure vs segno (Table 9).
    for v in range(1, 41):
        total = raw_modules(v) // 8
        for lv in range(4):
            nb, ec = NUM_BLOCKS[lv][v], ECC_PER_BLOCK[lv][v]
            short_len = total // nb
            n_long = total % nb
            blocks = []
            if nb - n_long:
                blocks.append((nb - n_long, short_len, short_len - ec))
            if n_long:
                blocks.append((n_long, short_len + 1, short_len + 1 - ec))
            ref = tuple((b.num_blocks, b.num_total, b.num_data) for b in sc.ECC[v][SEGNO_LEVEL[lv]])
            assert tuple(blocks) == ref, (v, lv, blocks, ref)
    # Alignment positions vs segno (Table E.1).
    for v in range(2, 41):
        assert tuple(align_pos(v)) == tuple(sc.ALIGNMENT_POS[v - 2]), v
    # Format information vs segno (Table C.1), indexed [level bits << 3 | mask].
    fmt = [bch(d, 5, 0x537, 10) ^ 0x5412 for d in range(32)]
    seg_order = (sc.ERROR_LEVEL_M, sc.ERROR_LEVEL_L, sc.ERROR_LEVEL_H, sc.ERROR_LEVEL_Q)
    for d in range(32):
        lvl_bits, mask = d >> 3, d & 7
        assert sc.FORMAT_INFO[seg_order.index(lvl_bits) * 8 + mask] == fmt[d], d
    # Version information vs segno (Table D.1).
    ver_info = [bch(v, 6, 0x1F25, 12) for v in range(7, 41)]
    assert tuple(ver_info) == tuple(sc.VERSION_INFO), "version info mismatch"

    out = []
    w = out.append
    w("// SPDX-License-Identifier: GPL-3.0-only")
    w("// Copyright (C) 2026 The feuristic contributors")
    w("//")
    w("// GENERATED by lib/fqr/tools/gen_tables.py -- do not edit by hand.")
    w("// ISO/IEC 18004:2015 constants, cross-checked against segno's tables.")
    w("")
    w('#include "fqr_internal.h"')
    w("")

    def arr(ctype: str, name: str, vals: list[int], per_line: int = 16, fmt_s: str = "0x{:02x}") -> None:
        w(f"const {ctype} {name}[{len(vals)}] = {{")
        for i in range(0, len(vals), per_line):
            w("    " + ", ".join(fmt_s.format(v) for v in vals[i : i + per_line]) + ",")
        w("};")
        w("")

    arr("uint8_t", "fqr_gf_exp", exp)
    arr("uint8_t", "fqr_gf_log", log)
    w("/* Error-correction codewords per block, [level L,M,Q,H][version]. */")
    w("const uint8_t fqr_ecc_per_block[4][41] = {")
    for lv in range(4):
        w("    {" + ", ".join(str(v) for v in ECC_PER_BLOCK[lv]) + "},")
    w("};")
    w("")
    w("/* Number of error-correction blocks, [level L,M,Q,H][version]. */")
    w("const uint8_t fqr_num_blocks[4][41] = {")
    for lv in range(4):
        w("    {" + ", ".join(str(v) for v in NUM_BLOCKS[lv]) + "},")
    w("};")
    w("")
    w("/* Total codewords per version (raw data modules / 8). */")
    arr("uint16_t", "fqr_total_codewords", [0] + [raw_modules(v) // 8 for v in range(1, 41)], 10, "{}")
    w("/* Remainder bits per version. */")
    arr("uint8_t", "fqr_remainder_bits", [0] + [raw_modules(v) % 8 for v in range(1, 41)], 20, "{}")
    w("/* Alignment pattern centre coordinates; unused entries are 0. */")
    w("const uint8_t fqr_align_pos[41][FQR_MAX_ALIGN_PER_AXIS] = {")
    for v in range(41):
        p = align_pos(v) if v >= 1 else []
        p = p + [0] * (7 - len(p))
        w("    {" + ", ".join(str(q) for q in p) + "},")
    w("};")
    w("")
    w("/* Format information codewords (after XOR with 0x5412), indexed by the")
    w(" * 5 data bits: (level bits << 3) | mask, level bits M=0 L=1 H=2 Q=3. */")
    arr("uint16_t", "fqr_format_codewords", fmt, 8, "0x{:04x}")
    w("/* Version information codewords for versions 7..40. */")
    arr("uint32_t", "fqr_version_codewords", ver_info, 6, "0x{:05x}")

    text = "\n".join(out).rstrip() + "\n"
    # Use the project's pinned formatter so --check and CI agree byte for byte.
    formatter = pathlib.Path(sys.executable).with_name("clang-format")
    text = subprocess.run(  # noqa: S603 - executable from the active dev environment
        [str(formatter), "--style=file", "--assume-filename=" + str(OUT)],
        input=text,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    if "--check" in sys.argv:
        if OUT.read_text() != text:
            print(f"{OUT} is out of date", file=sys.stderr)
            return 1
        print("tables up to date")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text)
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
