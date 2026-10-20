#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Compare bounded image->QR decoding at several bitmap dimensions.

Uses the real portable C fimg/fqr implementations, the existing photographed QR
corpus, and deterministic synthetic v3/v5/v9 PNG/JPEG camera-like variants.
This is software evidence, not a physical OLED/camera acceptance result.
"""

from __future__ import annotations

import argparse
import ctypes
import io
import json
import random
import subprocess
import tempfile
from pathlib import Path

import segno
from PIL import Image, ImageFilter

ROOT = Path(__file__).resolve().parent.parent
WRAPPER = r"""
#include <stdlib.h>
#include "fimg.h"
#include "fqr.h"
int decode_import(const unsigned char *data, size_t len, unsigned side,
                  unsigned char *out, size_t cap, size_t *outlen) {
  fimg_config_t cfg;
  fimg_config_default(&cfg);
  cfg.max_out_width = (uint16_t)side;
  cfg.max_out_height = (uint16_t)side;
  size_t wsz = fimg_workspace_size(&cfg);
  if (wsz < FQR_WORKSPACE_SIZE) wsz = FQR_WORKSPACE_SIZE;
  unsigned char *ws = malloc(wsz), *bm = malloc(fimg_bitmap_size(&cfg));
  fimg_ctx_t *ctx = NULL;
  int status = -1;
  fimg_info_t info = {0};
  if (!ws || !bm || fimg_init(&ctx, ws, wsz, &cfg, bm, fimg_bitmap_size(&cfg)) != FIMG_OK) goto done;
  for (size_t at = 0; at < len; at += 64) {
    size_t n = len-at < 64 ? len-at : 64;
    status = fimg_feed(ctx, data+at, n);
    if (status != FIMG_OK) { status += 100; goto done; }
  }
  status = fimg_finish(ctx, &info);
  if (status != FIMG_OK || !info.complete) { status += 100; goto done; }
  fqr_image_t image = {bm, info.out_width, info.out_height, info.stride};
  fqr_result_t result = {0};
  result.payload = out;
  result.payload_cap = cap;
  status = fqr_decode_single(&image, ws, wsz, NULL, &result);
  if (status == FQR_OK) status = result.status;
  *outlen = result.payload_len;
done:
  free(ws); free(bm);
  return status;
}
"""


def cases():
    corpus = ROOT / "tests/c/fimg/vectors"
    otp_uri = b"otpauth://totp/feuristic:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=feuristic&digits=6"
    # Exact deterministic payloads in tests/c/fimg/gen_vectors.py:gen_qr().
    backup = b"feuristic-backup:1:" + b"I" * 900
    for text in sorted(corpus.glob("*.qr.txt")):
        name = text.name[: -len(".qr.txt")]
        for suffix in (".png", ".jpg", ".jpeg"):
            image_path = corpus / (name + suffix)
            if image_path.exists():
                expected = (
                    backup
                    if name.startswith("qr_backup")
                    else (b"HELLO" if name.startswith("qr_v1") else otp_uri)
                )
                yield image_path.name, image_path.read_bytes(), expected
    for version, length in ((3, 50), (5, 110), (9, 250)):
        payload = ("FB1:" + "A" * length).encode()
        qr = segno.make(payload.decode(), version=version, error="m", boost_error=False, micro=False)
        buffer = io.BytesIO()
        qr.save(buffer, kind="png", scale=1, border=4)
        original = Image.open(io.BytesIO(buffer.getvalue())).convert("L")
        for dimension in (256, 512, 768, 1024):
            qr_side = int(dimension * 0.8)
            base = Image.new("L", (dimension, dimension), 255)
            base.paste(
                original.resize((qr_side, qr_side), Image.Resampling.NEAREST),
                ((dimension - qr_side) // 2,) * 2,
            )
            for variant in ("clean", "rotate", "blur", "shadow"):
                image = base.copy()
                if variant == "rotate":
                    image = image.rotate(15, Image.Resampling.BICUBIC, fillcolor=255)
                elif variant == "blur":
                    image = image.filter(ImageFilter.GaussianBlur(0.7))
                elif variant == "shadow":
                    rng = random.Random(2606 + version + dimension)  # noqa: S311 - reproducible image noise
                    pixels = bytearray(image.tobytes())
                    for index, value in enumerate(pixels):
                        factor = 0.55 + 0.45 * (index % dimension) / dimension
                        pixels[index] = max(0, min(255, int(value * factor) + rng.randrange(-6, 7)))
                    image = Image.frombytes("L", image.size, bytes(pixels))
                for kind in ("PNG", "JPEG"):
                    output = io.BytesIO()
                    image.save(output, format=kind, quality=70)
                    yield f"v{version}-{dimension}-{variant}-{kind}", output.getvalue(), payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/image-import-probe.json")
    parser.add_argument("--sides", type=int, nargs="+", default=[512, 384, 320])
    args = parser.parse_args()
    if 512 not in args.sides or any(side < 128 or side > 1024 for side in args.sides):
        parser.error("sides must include baseline512 and lie in128..1024")
    results = []
    with tempfile.TemporaryDirectory(prefix="feuristic-image-probe-") as directory:
        temp = Path(directory)
        source = temp / "probe.c"
        source.write_text(WRAPPER)
        library = temp / "probe.so"
        command = ["clang", "-std=c99", "-O2", "-shared", "-fPIC"]
        command += ["-I" + str(ROOT / f"lib/{name}/include") for name in ("fimg", "fqr")]
        command += [str(source)]
        for name in ("fimg", "fqr"):
            command += [str(path) for path in sorted((ROOT / f"lib/{name}/src").glob("*.c"))]
        command += ["-o", str(library)]
        subprocess.run(command, check=True)
        native = ctypes.CDLL(str(library)).decode_import
        native.argtypes = [
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_uint,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        native.restype = ctypes.c_int
        for name, data, expected in cases():
            row = {
                "name": name,
                "input_bytes": len(data),
                "within_file_limit": len(data) <= 256 * 1024,
                "results": {},
            }
            for side in args.sides:
                output = ctypes.create_string_buffer(3072)
                length = ctypes.c_size_t()
                status = native(data, len(data), side, output, len(output), ctypes.byref(length))
                row["results"][str(side)] = {
                    "status": status,
                    "correct": status == 0 and output.raw[: length.value] == expected,
                }
            results.append(row)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2) + "\n")
    regressions = []
    for side in args.sides:
        eligible = sum(row["within_file_limit"] for row in results)
        success = sum(row["results"][str(side)]["correct"] for row in results if row["within_file_limit"])
        oversized_rejected = sum(
            not row["within_file_limit"] and row["results"][str(side)]["status"] == 105 for row in results
        )
        lost = [
            row["name"]
            for row in results
            if row["results"]["512"]["correct"] and not row["results"][str(side)]["correct"]
        ]
        print(
            f"side={side}: {success}/{eligible} within-limit correct; "
            f"oversized rejected={oversized_rejected}/{len(results) - eligible}; "
            f"baseline regressions={lost}"
        )
        if side == 384:
            regressions = lost
    print("results:", args.output)
    return bool(regressions)


if __name__ == "__main__":
    raise SystemExit(main())
