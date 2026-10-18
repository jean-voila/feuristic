# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Generate the lib/fimg test corpus (tests/c/fimg/vectors/).

Run from the repository root:

    uv run python tests/c/fimg/gen_vectors.py

The output is deterministic. It writes:

* PNG files from a minimal in-house encoder (every colour type / bit depth,
  every filter type, stored / fixed / dynamic deflate, split IDATs, tRNS,
  ancillary and APNG chunks) plus damaged variants;
* JPEG files from Pillow (libjpeg-turbo) and from a small in-house baseline
  encoder (H1V2 sampling, non-interleaved / multi-scan, 16-bit DQT, combined
  tables, fill bytes, RGB component ids) plus damaged / unsupported variants;
* raw zlib streams (valid and hand-crafted invalid ones) for the inflater;
* QR renders (segno) with their module matrix;
* ``manifest.txt`` describing the expected result of every file.

Reference luma (``*.pgm``) is computed from the raw samples with the exact
integer formulas of fimg (BT.601 as Pillow, alpha over white) and
cross-checked against Pillow's decoder; JPEG references are Pillow's luma
output (``draft("L")``, i.e. libjpeg's Y plane, islow IDCT).

Manifest line formats (fields separated by spaces):

    luma <file> <status> <tol> <ref.pgm> [strict]
    lumacrc <file> <status> <w> <h> <crc32hex>
    status <file> <status> [strict]
    qr <file> <status> <matrix.txt> <min_agree_permille>
    zlib <file> ok <len> <crc32hex> | zlib <file> err <name> | zlib <file> trunc
"""

from __future__ import annotations

import io
import math
import random
import struct
import sys
import zlib
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

try:
    import segno
except ImportError:  # pragma: no cover
    segno = None

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "vectors"
SEED_PNG = ROOT.parent.parent / "fuzz" / "corpus" / "fimg_png"
SEED_JPEG = ROOT.parent.parent / "fuzz" / "corpus" / "fimg_jpeg"

manifest: list[str] = []
rng = random.Random(0xF1A6)


def write(name: str, data: bytes) -> None:
    (OUT / name).write_bytes(data)


def write_pgm(name: str, w: int, h: int, pix: list[int]) -> None:
    assert len(pix) == w * h
    write(name, b"P5\n%d %d\n255\n" % (w, h) + bytes(pix))


# --------------------------------------------------------------------------
# integer reference formulas (must match lib/fimg)
# --------------------------------------------------------------------------


def l24(r: int, g: int, b: int) -> int:
    return (r * 19595 + g * 38470 + b * 7471 + 0x8000) >> 16


def div255(x: int) -> int:
    return (x + 128 + ((x + 128) >> 8)) >> 8


def over_white(y: int, a: int) -> int:
    return div255(y * a + 255 * (255 - a))


# --------------------------------------------------------------------------
# minimal PNG encoder
# --------------------------------------------------------------------------

CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}


def chunk(ctype: bytes, data: bytes, crc_fix: int = 0) -> bytes:
    crc = zlib.crc32(ctype + data) ^ crc_fix
    return struct.pack(">I", len(data)) + ctype + data + struct.pack(">I", crc & 0xFFFFFFFF)


def pack_row(samples: list[int], depth: int) -> bytes:
    if depth == 8:
        return bytes(samples)
    if depth == 16:
        return b"".join(struct.pack(">H", s) for s in samples)
    out = bytearray()
    acc = 0
    nbits = 0
    for s in samples:
        acc = (acc << depth) | s
        nbits += depth
        if nbits == 8:
            out.append(acc)
            acc = nbits = 0
    if nbits:
        out.append(acc << (8 - nbits))
    return bytes(out)


def paeth(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    return b if pb <= pc else c


def filter_row(ftype: int, row: bytes, prev: bytes, bpp: int) -> bytes:
    out = bytearray(len(row))
    for i, x in enumerate(row):
        a = row[i - bpp] if i >= bpp else 0
        b = prev[i]
        c = prev[i - bpp] if i >= bpp else 0
        pred = (0, a, b, (a + b) >> 1, paeth(a, b, c))[ftype]
        out[i] = (x - pred) & 0xFF
    return bytes([ftype]) + bytes(out)


def png_raw(w, h, ctype, depth, pixels, filters="cycle"):
    """pixels[y][x] = tuple of samples (len = channels). Returns filtered scanlines."""
    ch = CHANNELS[ctype]
    bpp = max(1, ch * depth // 8)
    rows = []
    prev = None
    for y in range(h):
        flat = [s for px in pixels[y] for s in px]
        row = pack_row(flat, depth)
        if prev is None:
            prev = bytes(len(row))
        if filters == "cycle":
            f = y % 5
        elif isinstance(filters, int):
            f = filters
        else:
            f = filters[y % len(filters)]
        rows.append(filter_row(f, row, prev, bpp))
        prev = row
    return b"".join(rows)


def zcompress(raw: bytes, mode: str = "default") -> bytes:
    if mode == "stored":
        c = zlib.compressobj(0)
    elif mode == "fixed":
        c = zlib.compressobj(9, zlib.DEFLATED, 15, 9, zlib.Z_FIXED)
    elif mode == "huffman":
        c = zlib.compressobj(9, zlib.DEFLATED, 15, 9, zlib.Z_HUFFMAN_ONLY)
    elif mode == "rle":
        c = zlib.compressobj(9, zlib.DEFLATED, 15, 9, zlib.Z_RLE)
    elif mode == "fast":
        c = zlib.compressobj(1)
    elif mode == "small-window":
        c = zlib.compressobj(9, zlib.DEFLATED, 9)
    else:
        c = zlib.compressobj(9)
    return c.compress(raw) + c.flush()


def ihdr(w, h, depth, ctype, interlace=0, comp=0, filt=0):
    return chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, depth, ctype, comp, filt, interlace))


SIG = b"\x89PNG\r\n\x1a\n"


def png_file(
    w,
    h,
    ctype,
    depth,
    pixels,
    *,
    filters="cycle",
    zmode="default",
    idat_split=None,
    plte=None,
    trns=None,
    extra_before=b"",
    extra_after=b"",
    raw_override=None,
    zdata_override=None,
):
    raw = raw_override if raw_override is not None else png_raw(w, h, ctype, depth, pixels, filters)
    z = zdata_override if zdata_override is not None else zcompress(raw, zmode)
    out = SIG + ihdr(w, h, depth, ctype) + extra_before
    if plte is not None:
        out += chunk(b"PLTE", bytes(c for rgb in plte for c in rgb))
    if trns is not None:
        out += chunk(b"tRNS", trns)
    if idat_split is None:
        out += chunk(b"IDAT", z)
    else:
        out += chunk(b"IDAT", b"")
        i = 0
        k = 0
        while i < len(z):
            n = idat_split[k % len(idat_split)]
            out += chunk(b"IDAT", z[i : i + n])
            i += n
            k += 1
    out += extra_after + chunk(b"IEND", b"")
    return out


def ref_luma(w, h, ctype, depth, pixels, plte=None, trns=None):
    key = None
    pal_luma = [0] * 256
    if ctype == 3:
        alpha = list(trns) if trns else []
        for i, (r, g, b) in enumerate(plte):
            y = l24(r, g, b)
            if i < len(alpha):
                y = over_white(y, alpha[i])
            pal_luma[i] = y
    elif trns is not None and ctype == 0:
        key = (struct.unpack(">H", trns)[0],)
    elif trns is not None and ctype == 2:
        key = struct.unpack(">HHH", trns)
    out = []
    for y in range(h):
        for px in pixels[y]:
            if ctype == 0:
                v = px[0]
                if key is not None and px == key:
                    out.append(255)
                elif depth < 8:
                    out.append(v * (255 // ((1 << depth) - 1)))
                elif depth == 8:
                    out.append(v)
                else:
                    out.append(v >> 8)
            elif ctype == 2:
                if key is not None and px == key:
                    out.append(255)
                elif depth == 8:
                    out.append(l24(*px))
                else:
                    out.append(l24(px[0] >> 8, px[1] >> 8, px[2] >> 8))
            elif ctype == 3:
                out.append(pal_luma[px[0]])
            elif ctype == 4:
                s = 0 if depth == 8 else 8
                out.append(over_white(px[0] >> s, px[1] >> s))
            else:
                s = 0 if depth == 8 else 8
                out.append(over_white(l24(px[0] >> s, px[1] >> s, px[2] >> s), px[3] >> s))
    return out


def pillow_luma(data: bytes):
    """Pillow's view of a PNG, reduced with the same formulas (None if not comparable)."""
    im = Image.open(io.BytesIO(data))
    im.load()
    if im.mode in ("I;16", "I;16B", "I"):
        return [v >> 8 for v in im.get_flattened_data()] if "transparency" not in im.info else None
    if im.mode in ("RGB", "RGBA", "P", "L", "LA", "1", "PA"):
        rgba = im.convert("RGBA")
        return [over_white(l24(r, g, b), a) for (r, g, b, a) in rgba.get_flattened_data()]
    return None


def make_pixels(w, h, ctype, depth, seed):
    r = random.Random(seed)
    maxv = (1 << depth) - 1
    ch = CHANNELS[ctype]
    pix = []
    for y in range(h):
        row = []
        for x in range(w):
            px = []
            for c in range(ch):
                if ctype == 3:
                    v = (x * 7 + y * 3 + r.randrange(3)) % (maxv + 1)
                else:
                    base = ((x * 255 // max(1, w - 1)) * (c + 1) + y * 13 * (c + 2)) % 256
                    noise = r.randrange(-20, 21)
                    v8 = max(0, min(255, base + noise))
                    v = (v8 * maxv + 127) // 255 if depth <= 8 else v8 * 257 + r.randrange(0, 256) % 257
                    v = min(v, maxv)
                if (ctype in (4, 6)) and c == ch - 1:
                    # alpha: opaque, transparent and partial areas
                    zone = (x * 4 // max(1, w)) % 4
                    v = (0, maxv, maxv // 2, r.randrange(maxv + 1))[zone]
                px.append(v)
            row.append(tuple(px))
        pix.append(row)
    return pix


def add_png(
    name,
    data,
    w,
    h,
    ctype,
    depth,
    pixels,
    plte=None,
    trns=None,
    status="ok",
    check_pillow=True,
    ref=None,
    crc_only=False,
):
    write(name, data)
    if status != "ok":
        manifest.append(f"status {name} {status}")
        return
    if ref is None:
        ref = ref_luma(w, h, ctype, depth, pixels, plte, trns)
    if check_pillow:
        pl = pillow_luma(data)
        if pl is not None and pl != ref:
            bad = sum(1 for a, b in zip(pl, ref) if a != b)
            print(f"note: pillow disagrees with the reference on {name}: {bad} px", file=sys.stderr)
    if crc_only:
        manifest.append(f"lumacrc {name} ok {w} {h} {zlib.crc32(bytes(ref)):08x}")
        return
    pgm = name.rsplit(".", 1)[0] + ".pgm"
    write_pgm(pgm, w, h, ref)
    manifest.append(f"luma {name} ok 0 {pgm}")


def gen_png() -> None:
    combos = [
        (0, 1),
        (0, 2),
        (0, 4),
        (0, 8),
        (0, 16),
        (2, 8),
        (2, 16),
        (3, 1),
        (3, 2),
        (3, 4),
        (3, 8),
        (4, 8),
        (4, 16),
        (6, 8),
        (6, 16),
    ]
    for ct, d in combos:
        w, h = 37, 23
        pix = make_pixels(w, h, ct, d, ct * 100 + d)
        plte = None
        if ct == 3:
            n = 1 << d
            plte = [((i * 53) % 256, (i * 97) % 256, (i * 31 + 7) % 256) for i in range(n)]
        data = png_file(w, h, ct, d, pix, plte=plte)
        add_png(f"png_ct{ct}_d{d}.png", data, w, h, ct, d, pix, plte)

    # every filter type, three different bytes-per-pixel values
    for ct, d, tag in ((2, 8, "rgb8"), (6, 16, "rgba16"), (0, 1, "g1"), (0, 8, "g8")):
        w, h = 29, 17
        pix = make_pixels(w, h, ct, d, 999 + d)
        for f in range(5):
            data = png_file(w, h, ct, d, pix, filters=f)
            add_png(f"png_filter{f}_{tag}.png", data, w, h, ct, d, pix)

    # deflate flavours and IDAT splitting
    w, h = 64, 40
    pix = make_pixels(w, h, 2, 8, 4242)
    for zm in ("stored", "fixed", "huffman", "rle", "fast", "small-window"):
        add_png(f"png_z_{zm}.png", png_file(w, h, 2, 8, pix, zmode=zm), w, h, 2, 8, pix)
    sw, sh = 23, 11
    spix = make_pixels(sw, sh, 2, 8, 4243)
    add_png("png_idat_split1.png", png_file(sw, sh, 2, 8, spix, idat_split=[1]), sw, sh, 2, 8, spix)
    add_png(
        "png_idat_split_primes.png", png_file(w, h, 2, 8, pix, idat_split=[7, 13, 251, 3]), w, h, 2, 8, pix
    )

    # transparency
    w, h = 33, 21
    pix = make_pixels(w, h, 3, 4, 77)
    plte = [((i * 40) % 256, (i * 90) % 256, (255 - i * 16) % 256) for i in range(16)]
    trns = bytes([0, 128, 255, 10, 200])
    add_png("png_plte_trns.png", png_file(w, h, 3, 4, pix, plte=plte, trns=trns), w, h, 3, 4, pix, plte, trns)
    pix = make_pixels(w, h, 0, 8, 78)
    key = pix[3][5][0]
    trns = struct.pack(">H", key)
    add_png("png_gray8_trns.png", png_file(w, h, 0, 8, pix, trns=trns), w, h, 0, 8, pix, None, trns)
    pix = make_pixels(w, h, 0, 2, 79)
    trns = struct.pack(">H", 1)
    add_png("png_gray2_trns.png", png_file(w, h, 0, 2, pix, trns=trns), w, h, 0, 2, pix, None, trns)
    pix = make_pixels(w, h, 0, 16, 80)
    trns = struct.pack(">H", pix[0][0][0])
    add_png(
        "png_gray16_trns.png",
        png_file(w, h, 0, 16, pix, trns=trns),
        w,
        h,
        0,
        16,
        pix,
        None,
        trns,
        check_pillow=False,
    )
    pix = make_pixels(w, h, 2, 8, 81)
    trns = struct.pack(">HHH", *pix[2][2])
    add_png("png_rgb8_trns.png", png_file(w, h, 2, 8, pix, trns=trns), w, h, 2, 8, pix, None, trns)
    pix = make_pixels(w, h, 2, 16, 82)
    trns = struct.pack(">HHH", *pix[1][1])
    add_png(
        "png_rgb16_trns.png",
        png_file(w, h, 2, 16, pix, trns=trns),
        w,
        h,
        2,
        16,
        pix,
        None,
        trns,
        check_pillow=False,
    )
    # invalid tRNS (too long for the palette): ignored
    pix = make_pixels(w, h, 3, 2, 83)
    plte = [(0, 0, 0), (90, 90, 90), (180, 180, 180), (255, 255, 255)]
    add_png(
        "png_trns_ignored.png",
        png_file(w, h, 3, 2, pix, plte=plte, trns=bytes(5)),
        w,
        h,
        3,
        2,
        pix,
        plte,
        None,
        check_pillow=False,
    )
    # palette index beyond PLTE -> black
    pix = [[((x + y) % 8,) for x in range(w)] for y in range(h)]
    plte = [(255, 255, 255)] * 5
    ref = [255 if ((x + y) % 8) < 5 else 0 for y in range(h) for x in range(w)]
    add_png(
        "png_plte_short.png",
        png_file(w, h, 3, 8, pix, plte=plte),
        w,
        h,
        3,
        8,
        pix,
        plte,
        None,
        check_pillow=False,
        ref=ref,
    )

    # ancillary chunks, unknown private chunk, APNG
    pix = make_pixels(w, h, 0, 8, 90)
    anc = (
        chunk(b"gAMA", struct.pack(">I", 45455))
        + chunk(b"tEXt", b"Comment\x00hello")
        + chunk(b"prVt", bytes(range(200)))
        + chunk(b"zTXt", b"k\x00\x00" + zlib.compress(b"x"))
    )
    add_png(
        "png_ancillary.png",
        png_file(w, h, 0, 8, pix, extra_before=anc, extra_after=chunk(b"tIME", bytes(7))),
        w,
        h,
        0,
        8,
        pix,
    )
    actl = chunk(b"acTL", struct.pack(">II", 2, 0))
    fctl = chunk(b"fcTL", struct.pack(">IIIIIHHBB", 0, w, h, 0, 0, 1, 10, 0, 0))
    fdat = chunk(b"fcTL", struct.pack(">IIIIIHHBB", 1, w, h, 0, 0, 1, 10, 0, 0)) + chunk(
        b"fdAT", struct.pack(">I", 2) + zcompress(png_raw(w, h, 0, 8, make_pixels(w, h, 0, 8, 91)))
    )
    add_png(
        "png_apng.png",
        png_file(w, h, 0, 8, pix, extra_before=actl + fctl, extra_after=fdat),
        w,
        h,
        0,
        8,
        pix,
        check_pillow=False,
    )

    # large valid images
    w = h = 1024
    pix = [[(((x // 32) + (y // 32)) % 2 * 255,) for x in range(w)] for y in range(h)]
    add_png(
        "png_1024_gray1.png",
        png_file(w, h, 0, 1, [[(v[0] // 255,) for v in r] for r in pix]),
        w,
        h,
        0,
        1,
        [[(v[0] // 255,) for v in r] for r in pix],
        check_pillow=False,
        crc_only=True,
    )

    # ---------------- errors ----------------
    w, h = 20, 10
    pix = make_pixels(w, h, 0, 8, 5)
    good = png_file(w, h, 0, 8, pix)
    raw = png_raw(w, h, 0, 8, pix)
    z = zcompress(raw)

    def errpng(name, data, status, strict=False):
        write(name, data)
        manifest.append(f"status {name} {status}" + (" strict" if strict else ""))

    # Adam7 interlaced (valid data, expected to be refused)
    errpng(
        "png_err_interlaced.png",
        SIG + ihdr(w, h, 8, 0, interlace=1) + chunk(b"IDAT", z) + chunk(b"IEND", b""),
        "png-interlaced",
    )
    errpng(
        "png_err_interlace2.png",
        SIG + ihdr(w, h, 8, 0, interlace=2) + chunk(b"IDAT", z) + chunk(b"IEND", b""),
        "png-unsupported",
    )
    errpng(
        "png_err_crc_ihdr.png",
        SIG
        + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 0, 0, 0, 0), 1)
        + chunk(b"IDAT", z)
        + chunk(b"IEND", b""),
        "png-crc",
    )
    errpng(
        "png_err_crc_idat.png",
        SIG + ihdr(w, h, 8, 0) + chunk(b"IDAT", z, 0x100) + chunk(b"IEND", b""),
        "png-crc",
    )
    errpng(
        "png_err_crc_iend.png",
        SIG + ihdr(w, h, 8, 0) + chunk(b"IDAT", z) + chunk(b"IEND", b"", 0x80000000),
        "png-crc",
    )
    errpng(
        "png_err_crc_anc.png",
        SIG + ihdr(w, h, 8, 0) + chunk(b"tEXt", b"a\x00b", 4) + chunk(b"IDAT", z) + chunk(b"IEND", b""),
        "png-crc",
    )
    badadler = z[:-1] + bytes([z[-1] ^ 1])
    errpng(
        "png_err_adler.png",
        SIG + ihdr(w, h, 8, 0) + chunk(b"IDAT", badadler) + chunk(b"IEND", b""),
        "png-zlib",
    )
    errpng(
        "png_err_zhdr.png",
        SIG + ihdr(w, h, 8, 0) + chunk(b"IDAT", b"\x78\x9a" + z[2:]) + chunk(b"IEND", b""),
        "png-zlib",
    )
    errpng(
        "png_err_zdict.png",
        SIG + ihdr(w, h, 8, 0) + chunk(b"IDAT", b"\x78\xbb" + z[2:]) + chunk(b"IEND", b""),
        "png-zlib",
    )
    errpng(
        "png_err_bomb.png",
        SIG + ihdr(w, h, 8, 0) + chunk(b"IDAT", zcompress(raw + b"\x00" * 21)) + chunk(b"IEND", b""),
        "png-data-size",
    )
    errpng(
        "png_err_bomb_big.png",
        SIG + ihdr(w, h, 8, 0) + chunk(b"IDAT", zcompress(bytes(5_000_000))) + chunk(b"IEND", b""),
        "png-data-size",
    )
    errpng(
        "png_err_short.png",
        SIG + ihdr(w, h, 8, 0) + chunk(b"IDAT", zcompress(raw[:-21])) + chunk(b"IEND", b""),
        "png-data-size",
    )
    errpng(
        "png_err_short1.png",
        SIG + ihdr(w, h, 8, 0) + chunk(b"IDAT", zcompress(raw[:-1])) + chunk(b"IEND", b""),
        "png-data-size",
    )
    errpng(
        "png_err_zextra.png",
        SIG + ihdr(w, h, 8, 0) + chunk(b"IDAT", z + b"\x00") + chunk(b"IEND", b""),
        "png-corrupt",
    )
    errpng(
        "png_err_zextra_chunk.png",
        SIG + ihdr(w, h, 8, 0) + chunk(b"IDAT", z) + chunk(b"IDAT", b"\x01") + chunk(b"IEND", b""),
        "png-corrupt",
    )
    errpng(
        "png_ok_empty_idat_after.png",
        SIG + ihdr(w, h, 8, 0) + chunk(b"IDAT", z) + chunk(b"IDAT", b"") + chunk(b"IEND", b""),
        "ok",
    )
    errpng(
        "png_err_zunterminated.png",
        SIG + ihdr(w, h, 8, 0) + chunk(b"IDAT", z[:-4]) + chunk(b"IEND", b""),
        "png-zlib",
    )
    errpng("png_err_no_iend.png", good[:-12], "truncated")
    errpng("png_err_trunc_idat.png", good[: len(good) // 2], "truncated")
    errpng("png_err_trunc_sig.png", good[:5], "not-image")
    errpng("png_err_trunc_hdr.png", good[: 8 + 6], "truncated")
    errpng("png_trailing.png", good + b"\x00" * 100 + b"garbage", "ok")
    errpng("png_trailing_strict.png", good + b"x", "trailing-data", strict=True)
    errpng(
        "png_err_ihdr_len.png",
        SIG
        + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 0, 0, 0, 0) + b"\x00")
        + chunk(b"IDAT", z)
        + chunk(b"IEND", b""),
        "png-corrupt",
    )
    errpng(
        "png_err_first_not_ihdr.png",
        SIG + chunk(b"tEXt", b"a\x00b") + ihdr(w, h, 8, 0) + chunk(b"IDAT", z) + chunk(b"IEND", b""),
        "png-corrupt",
    )
    errpng(
        "png_err_two_ihdr.png",
        SIG + ihdr(w, h, 8, 0) + ihdr(w, h, 8, 0) + chunk(b"IDAT", z) + chunk(b"IEND", b""),
        "png-corrupt",
    )
    errpng(
        "png_err_depth.png",
        SIG + ihdr(w, h, 4, 2) + chunk(b"IDAT", z) + chunk(b"IEND", b""),
        "png-unsupported",
    )
    errpng(
        "png_err_ctype.png",
        SIG + ihdr(w, h, 8, 5) + chunk(b"IDAT", z) + chunk(b"IEND", b""),
        "png-unsupported",
    )
    errpng(
        "png_err_comp.png",
        SIG + ihdr(w, h, 8, 0, comp=1) + chunk(b"IDAT", z) + chunk(b"IEND", b""),
        "png-unsupported",
    )
    errpng(
        "png_err_filtm.png",
        SIG + ihdr(w, h, 8, 0, filt=1) + chunk(b"IDAT", z) + chunk(b"IEND", b""),
        "png-unsupported",
    )
    errpng("png_err_dim0.png", SIG + ihdr(0, h, 8, 0) + chunk(b"IDAT", z) + chunk(b"IEND", b""), "dimensions")
    errpng(
        "png_err_dim1025.png",
        SIG + ihdr(1025, 1, 8, 0) + chunk(b"IDAT", z) + chunk(b"IEND", b""),
        "dimensions",
    )
    errpng(
        "png_err_dim_huge.png", SIG + ihdr(0x7FFFFFFF, 0x7FFFFFFF, 8, 0) + chunk(b"IEND", b""), "dimensions"
    )
    errpng(
        "png_err_noplte.png", SIG + ihdr(w, h, 8, 3) + chunk(b"IDAT", z) + chunk(b"IEND", b""), "png-corrupt"
    )
    errpng(
        "png_err_plte_gray.png",
        SIG + ihdr(w, h, 8, 0) + chunk(b"PLTE", bytes(6)) + chunk(b"IDAT", z) + chunk(b"IEND", b""),
        "png-corrupt",
    )
    errpng(
        "png_err_plte_len.png",
        SIG + ihdr(w, h, 8, 3) + chunk(b"PLTE", bytes(769)) + chunk(b"IDAT", z) + chunk(b"IEND", b""),
        "png-corrupt",
    )
    errpng(
        "png_err_plte_after_idat.png",
        SIG
        + ihdr(w, h, 8, 2)
        + chunk(b"IDAT", zcompress(png_raw(w, h, 2, 8, make_pixels(w, h, 2, 8, 1))))
        + chunk(b"PLTE", bytes(6))
        + chunk(b"IEND", b""),
        "png-corrupt",
    )
    errpng(
        "png_err_critical.png",
        SIG + ihdr(w, h, 8, 0) + chunk(b"ABCD", b"") + chunk(b"IDAT", z) + chunk(b"IEND", b""),
        "png-unsupported",
    )
    badf = bytearray(raw)
    badf[0] = 5
    errpng(
        "png_err_filter5.png",
        SIG + ihdr(w, h, 8, 0) + chunk(b"IDAT", zcompress(bytes(badf))) + chunk(b"IEND", b""),
        "png-corrupt",
    )
    errpng(
        "png_err_chunklen.png", SIG + ihdr(w, h, 8, 0) + b"\x80\x00\x00\x00tEXt" + bytes(16), "png-corrupt"
    )
    errpng(
        "png_err_chunktype.png",
        SIG + ihdr(w, h, 8, 0) + chunk(b"tE1t", b"") + chunk(b"IDAT", z) + chunk(b"IEND", b""),
        "png-corrupt",
    )
    errpng(
        "png_err_idat_gap.png",
        SIG
        + ihdr(w, h, 8, 0)
        + chunk(b"IDAT", z[:10])
        + chunk(b"tEXt", b"a\x00b")
        + chunk(b"IDAT", z[10:])
        + chunk(b"IEND", b""),
        "png-data-size",
    )
    errpng(
        "png_err_iend_len.png",
        SIG + ihdr(w, h, 8, 0) + chunk(b"IDAT", z) + chunk(b"IEND", b"x"),
        "png-corrupt",
    )
    errpng("png_err_iend_early.png", SIG + ihdr(w, h, 8, 0) + chunk(b"IEND", b""), "png-corrupt")
    errpng("png_err_not_image.png", b"GIF89a" + bytes(30), "not-image")
    errpng("png_err_sig.png", SIG[:7] + b"\x0b" + good[8:], "not-image")


# --------------------------------------------------------------------------
# baseline JPEG encoder (for structures Pillow cannot produce)
# --------------------------------------------------------------------------

STD_LUM_Q = [
    16,
    11,
    10,
    16,
    24,
    40,
    51,
    61,
    12,
    12,
    14,
    19,
    26,
    58,
    60,
    55,
    14,
    13,
    16,
    24,
    40,
    57,
    69,
    56,
    14,
    17,
    22,
    29,
    51,
    87,
    80,
    62,
    18,
    22,
    37,
    56,
    68,
    109,
    103,
    77,
    24,
    35,
    55,
    64,
    81,
    104,
    113,
    92,
    49,
    64,
    78,
    87,
    103,
    121,
    120,
    101,
    72,
    92,
    95,
    98,
    112,
    100,
    103,
    99,
]
STD_CHR_Q = [
    17,
    18,
    24,
    47,
    99,
    99,
    99,
    99,
    18,
    21,
    26,
    66,
    99,
    99,
    99,
    99,
    24,
    26,
    56,
    99,
    99,
    99,
    99,
    99,
    47,
    66,
    99,
    99,
    99,
    99,
    99,
    99,
] + [99] * 32
ZIGZAG = [
    0,
    1,
    8,
    16,
    9,
    2,
    3,
    10,
    17,
    24,
    32,
    25,
    18,
    11,
    4,
    5,
    12,
    19,
    26,
    33,
    40,
    48,
    41,
    34,
    27,
    20,
    13,
    6,
    7,
    14,
    21,
    28,
    35,
    42,
    49,
    56,
    57,
    50,
    43,
    36,
    29,
    22,
    15,
    23,
    30,
    37,
    44,
    51,
    58,
    59,
    52,
    45,
    38,
    31,
    39,
    46,
    53,
    60,
    61,
    54,
    47,
    55,
    62,
    63,
]
DC_LUM_BITS = [0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0]
DC_LUM_VALS = list(range(12))
DC_CHR_BITS = [0, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0]
DC_CHR_VALS = list(range(12))
AC_LUM_BITS = [0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 0x7D]
AC_LUM_VALS = bytes.fromhex(
    "01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435"
    "363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798"
    "999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4"
    "f5f6f7f8f9fa"
)
AC_CHR_BITS = [0, 2, 1, 2, 4, 4, 3, 4, 7, 5, 4, 4, 0, 1, 2, 0x77]
AC_CHR_VALS = bytes.fromhex(
    "000102031104052131061241510761711322328108144291a1b1c109233352f0156272d10a162434e125f11718191a262728292a"
    "35363738393a434445464748494a535455565758595a636465666768696a737475767778797a82838485868788898a9293949596"
    "9798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7e8e9eaf2f3f4"
    "f5f6f7f8f9fa"
)


def scale_q(tab, quality):
    s = 5000 // quality if quality < 50 else 200 - quality * 2
    return [max(1, min(255, (q * s + 50) // 100)) for q in tab]


def huff_codes(bits, vals):
    codes = {}
    code = 0
    k = 0
    for l in range(1, 17):
        for _ in range(bits[l - 1]):
            codes[vals[k]] = (code, l)
            code += 1
            k += 1
        code <<= 1
    return codes


class BitWriter:
    def __init__(self):
        self.out = bytearray()
        self.acc = 0
        self.n = 0

    def put(self, v, n):
        for i in range(n - 1, -1, -1):
            self.acc = (self.acc << 1) | ((v >> i) & 1)
            self.n += 1
            if self.n == 8:
                self.out.append(self.acc)
                if self.acc == 0xFF:
                    self.out.append(0)
                self.acc = self.n = 0

    def flush(self):
        while self.n:
            self.put(1, 1)


COS = [[math.cos((2 * x + 1) * u * math.pi / 16) for x in range(8)] for u in range(8)]


def fdct_quant(block, q):
    out = [0] * 64
    for v in range(8):
        for u in range(8):
            s = 0.0
            for y in range(8):
                for x in range(8):
                    s += block[y * 8 + x] * COS[u][x] * COS[v][y]
            cu = 1 / math.sqrt(2) if u == 0 else 1
            cv = 1 / math.sqrt(2) if v == 0 else 1
            out[v * 8 + u] = s * cu * cv / 4
    return [int(round(out[ZIGZAG[k]] / q[k])) for k in range(64)]


def magnitude(v):
    a = abs(v)
    n = a.bit_length()
    return n, (v if v >= 0 else v + (1 << n) - 1)


def encode_block(bw, coefs, pred, dct, act):
    diff = coefs[0] - pred
    n, bits = magnitude(diff)
    c, l = dct[n]
    bw.put(c, l)
    if n:
        bw.put(bits, n)
    run = 0
    for k in range(1, 64):
        v = coefs[k]
        if v == 0:
            run += 1
            continue
        while run > 15:
            c, l = act[0xF0]
            bw.put(c, l)
            run -= 16
        n, bits = magnitude(v)
        c, l = act[(run << 4) | n]
        bw.put(c, l)
        bw.put(bits, n)
        run = 0
    if run:
        c, l = act[0]
        bw.put(c, l)
    return coefs[0]


def plane_blocks(plane, pw, ph, q):
    """plane: list of rows (already padded to pw x ph, multiples of 8)."""
    blocks = {}
    for by in range(ph // 8):
        for bx in range(pw // 8):
            blk = [plane[by * 8 + y][bx * 8 + x] - 128 for y in range(8) for x in range(8)]
            blocks[(bx, by)] = fdct_quant(blk, q)
    return blocks


def pad_plane(plane, w, h, pw, ph):
    out = []
    for y in range(ph):
        row = plane[min(y, h - 1)]
        out.append([row[min(x, w - 1)] for x in range(pw)])
    return out


def my_jpeg(
    img: Image.Image,
    *,
    samp=(2, 2),
    quality=75,
    restart=0,
    scans="interleaved",
    dqt16=False,
    combine=False,
    ids=(1, 2, 3),
    fill=False,
    gray_samp=(1, 1),
    com=b"",
    jfif=True,
):
    w, h = img.size
    gray = img.mode == "L"
    ycc = [img] if gray else list(img.convert("YCbCr").split())
    hmax, vmax = (1, 1) if gray else samp
    mw, mh = 8 * hmax, 8 * vmax
    qy = scale_q(STD_LUM_Q, quality)
    qc = scale_q(STD_CHR_Q, quality)
    planes = []
    comps = []
    for ci, chan in enumerate(ycc):
        data = (
            list(chan.getdata())
            if not hasattr(chan, "get_flattened_data")
            else list(chan.get_flattened_data())
        )
        rows = [data[y * w : (y + 1) * w] for y in range(h)]
        if ci == 0:
            hs, vs = gray_samp if gray else samp
            cw, ch_ = w, h
            sub = rows
        else:
            hs, vs = 1, 1
            cw, ch_ = -(-w // hmax), -(-h // vmax)
            sub = [
                [
                    sum(
                        rows[min(y * vmax + dy, h - 1)][min(x * hmax + dx, w - 1)]
                        for dy in range(vmax)
                        for dx in range(hmax)
                    )
                    // (hmax * vmax)
                    for x in range(cw)
                ]
                for y in range(ch_)
            ]
        # pad to a whole number of MCUs (interleaved) in component units
        if ci == 0 and not gray:
            pw, ph = -(-w // mw) * mw, -(-h // mh) * mh
        elif gray:
            pw, ph = -(-w // 8) * 8, -(-h // 8) * 8
        else:
            pw, ph = -(-w // mw) * 8, -(-h // mh) * 8
        planes.append((pad_plane(sub, cw, ch_, pw, ph), cw, ch_))
        comps.append((ids[ci], hs, vs, 0 if ci == 0 else 1))
    blocks = [
        plane_blocks(p, len(p[0]), len(p), qy if ci == 0 else qc) for ci, (p, _, _) in enumerate(planes)
    ]
    dcl, acl = huff_codes(DC_LUM_BITS, DC_LUM_VALS), huff_codes(AC_LUM_BITS, AC_LUM_VALS)
    dcc, acc_ = huff_codes(DC_CHR_BITS, DC_CHR_VALS), huff_codes(AC_CHR_BITS, AC_CHR_VALS)
    tabs = [(dcl, acl), (dcc, acc_)]

    out = bytearray(b"\xff\xd8")
    if jfif:
        out += b"\xff\xe0" + struct.pack(">H", 16) + b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    if com:
        out += b"\xff\xfe" + struct.pack(">H", len(com) + 2) + com
    qtabs = [qy] if gray else [qy, qc]
    segs = []
    for t, q in enumerate(qtabs):
        if dqt16:
            segs.append(bytes([0x10 | t]) + b"".join(struct.pack(">H", v) for v in q))
        else:
            segs.append(bytes([t]) + bytes(q))
    if combine:
        body = b"".join(segs)
        out += b"\xff\xdb" + struct.pack(">H", len(body) + 2) + body
    else:
        for s in segs:
            out += b"\xff\xdb" + struct.pack(">H", len(s) + 2) + s
    sof = struct.pack(">BHHB", 8, h, w, len(comps)) + b"".join(
        bytes([cid, (hs << 4) | vs, tq]) for cid, hs, vs, tq in comps
    )
    out += b"\xff\xc0" + struct.pack(">H", len(sof) + 2) + sof
    hsegs = [
        bytes([0x00]) + bytes(DC_LUM_BITS) + bytes(DC_LUM_VALS),
        bytes([0x10]) + bytes(AC_LUM_BITS) + AC_LUM_VALS,
    ]
    if not gray:
        hsegs += [
            bytes([0x01]) + bytes(DC_CHR_BITS) + bytes(DC_CHR_VALS),
            bytes([0x11]) + bytes(AC_CHR_BITS) + AC_CHR_VALS,
        ]
    if combine:
        body = b"".join(hsegs)
        out += b"\xff\xc4" + struct.pack(">H", len(body) + 2) + body
    else:
        for s in hsegs:
            out += b"\xff\xc4" + struct.pack(">H", len(s) + 2) + s
    if restart:
        out += b"\xff\xdd" + struct.pack(">HH", 4, restart)

    def emit_scan(comp_idx, units):
        """units: list of lists of (ci, block) per MCU."""
        nonlocal out
        sos = (
            bytes([len(comp_idx)])
            + b"".join(bytes([comps[ci][0], (0 if ci == 0 else 0x11)]) for ci in comp_idx)
            + b"\x00\x3f\x00"
        )
        out += b"\xff\xda" + struct.pack(">H", len(sos) + 2) + sos
        bw = BitWriter()
        preds = [0, 0, 0]
        rst = 0
        for m, unit in enumerate(units):
            if restart and m and m % restart == 0:
                bw.flush()
                out += bw.out
                if fill:
                    out += b"\xff\xff"
                out += bytes([0xFF, 0xD0 + rst])
                rst = (rst + 1) & 7
                bw = BitWriter()
                preds = [0, 0, 0]
            for ci, blk in unit:
                d, a = tabs[0 if ci == 0 else 1]
                preds[ci] = encode_block(bw, blk, preds[ci], d, a)
        bw.flush()
        out += bw.out
        if fill:
            out += b"\xff\xff\xff"

    def nonint_units(ci):
        _, cw, ch_ = planes[ci]
        return [[(ci, blocks[ci][(bx, by)])] for by in range(-(-ch_ // 8)) for bx in range(-(-cw // 8))]

    if gray:
        emit_scan([0], nonint_units(0))
    elif scans == "interleaved":
        units = []
        for my in range(-(-h // mh)):
            for mx in range(-(-w // mw)):
                u = [
                    (0, blocks[0][(mx * hmax + bx, my * vmax + by)])
                    for by in range(vmax)
                    for bx in range(hmax)
                ]
                u += [(1, blocks[1][(mx, my)]), (2, blocks[2][(mx, my)])]
                units.append(u)
        emit_scan([0, 1, 2], units)
    elif scans == "separate":
        for ci in range(3):
            emit_scan([ci], nonint_units(ci))
    elif scans == "chroma_first":
        emit_scan([1], nonint_units(1))
        emit_scan([2], nonint_units(2))
        emit_scan([0], nonint_units(0))
    out += b"\xff\xd9"
    return bytes(out)


def pillow_y(data: bytes):
    im = Image.open(io.BytesIO(data))
    im.draft("L", im.size)
    im = im.convert("L") if im.mode != "L" else im
    assert im.size == Image.open(io.BytesIO(data)).size
    return list(im.get_flattened_data())


def test_image(w, h, seed, mode="RGB"):
    r = random.Random(seed)
    im = Image.new("RGB", (w, h))
    px = im.load()
    for y in range(h):
        for x in range(w):
            px[x, y] = (
                (x * 255 // max(1, w - 1) + r.randrange(-15, 16)) % 256,
                (y * 255 // max(1, h - 1)) % 256,
                ((x ^ y) * 3 + r.randrange(0, 30)) % 256,
            )
    if w >= 8 and h >= 8:
        d = ImageDraw.Draw(im)
        d.rectangle((w // 5, h // 5, w // 2, h // 2), fill=(0, 0, 0))
        d.ellipse((w // 2, h // 3, w - 3, h - 3), fill=(250, 250, 240))
    return im.convert(mode) if mode != "RGB" else im


def add_jpeg(name, data, status="ok", strict=False):
    write(name, data)
    if status != "ok":
        manifest.append(f"status {name} {status}" + (" strict" if strict else ""))
        return
    im = Image.open(io.BytesIO(data))
    w, h = im.size
    pgm = name.rsplit(".", 1)[0] + ".pgm"
    write_pgm(pgm, w, h, pillow_y(data))
    manifest.append(f"luma {name} ok 2 {pgm}" + (" strict" if strict else ""))


def pil_jpeg(im, **kw):
    b = io.BytesIO()
    im.save(b, "JPEG", **kw)
    return b.getvalue()


def patch_marker(data: bytes, old: int, new: int) -> bytes:
    i = data.index(bytes([0xFF, old]))
    return data[: i + 1] + bytes([new]) + data[i + 2 :]


def find_segment(data: bytes, marker: int) -> int:
    i = 2
    while i < len(data):
        assert data[i] == 0xFF
        m = data[i + 1]
        if m == marker:
            return i
        ln = struct.unpack(">H", data[i + 2 : i + 4])[0]
        i += 2 + ln
    raise ValueError("marker not found")


def gen_jpeg() -> None:
    for w, h in ((61, 37), (64, 48), (17, 9), (8, 8), (1, 1), (130, 7)):
        im = test_image(w, h, w * 1000 + h)
        add_jpeg(f"jpg_gray_{w}x{h}.jpg", pil_jpeg(im.convert("L"), quality=75))
        for sub, tag in ((0, "444"), (1, "422"), (2, "420")):
            add_jpeg(f"jpg_{tag}_{w}x{h}.jpg", pil_jpeg(im, quality=75, subsampling=sub))
    im = test_image(77, 51, 5)
    for q in (1, 5, 50, 95, 100):
        add_jpeg(f"jpg_420_q{q}.jpg", pil_jpeg(im, quality=q, subsampling=2))
        add_jpeg(f"jpg_gray_q{q}.jpg", pil_jpeg(im.convert("L"), quality=q))
    add_jpeg("jpg_420_optimize.jpg", pil_jpeg(im, quality=80, subsampling=2, optimize=True))
    add_jpeg("jpg_444_optimize.jpg", pil_jpeg(im, quality=80, subsampling=0, optimize=True))
    for blocks in (1, 3, 7):
        add_jpeg(
            f"jpg_420_rst{blocks}.jpg", pil_jpeg(im, quality=70, subsampling=2, restart_marker_blocks=blocks)
        )
        add_jpeg(
            f"jpg_gray_rst{blocks}.jpg", pil_jpeg(im.convert("L"), quality=70, restart_marker_blocks=blocks)
        )
    add_jpeg("jpg_422_rstrows.jpg", pil_jpeg(im, quality=70, subsampling=1, restart_marker_rows=1))
    exif = b"Exif\x00\x00" + b"\xff\xd8\xff\xdb" + bytes(200) + b"\xff\xd9"
    add_jpeg("jpg_app1_embedded.jpg", pil_jpeg(im, quality=70, exif=exif))
    add_jpeg("jpg_comment.jpg", pil_jpeg(im, quality=70, comment=b"hello \xff\xd9 world" * 50))

    # in-house encoder variants
    small = test_image(45, 29, 9)
    add_jpeg("jpg_my_440.jpg", my_jpeg(small, samp=(1, 2)))
    add_jpeg("jpg_my_440_rst5.jpg", my_jpeg(small, samp=(1, 2), restart=5))
    add_jpeg("jpg_my_420.jpg", my_jpeg(small, samp=(2, 2)))
    add_jpeg("jpg_my_422.jpg", my_jpeg(small, samp=(2, 1)))
    add_jpeg("jpg_my_444.jpg", my_jpeg(small, samp=(1, 1)))
    add_jpeg("jpg_my_dqt16.jpg", my_jpeg(small, dqt16=True))
    add_jpeg("jpg_my_combined.jpg", my_jpeg(small, combine=True, dqt16=True))
    add_jpeg("jpg_my_fill.jpg", my_jpeg(small, restart=2, fill=True))
    add_jpeg("jpg_my_separate.jpg", my_jpeg(small, scans="separate"))
    add_jpeg("jpg_my_separate_rst.jpg", my_jpeg(small, scans="separate", restart=3))
    add_jpeg("jpg_my_chroma_first.jpg", my_jpeg(small, scans="chroma_first"))
    add_jpeg("jpg_my_gray_samp22.jpg", my_jpeg(small.convert("L"), gray_samp=(2, 2)))
    add_jpeg("jpg_my_noapp.jpg", my_jpeg(small, jfif=False, com=b"x" * 3000))
    add_jpeg("jpg_my_rst_wrap.jpg", my_jpeg(test_image(64, 64, 3), samp=(1, 1), restart=1))
    write("jpg_err_rgb_ids.jpg", my_jpeg(small, samp=(1, 1), ids=(ord("R"), ord("G"), ord("B")), jfif=False))
    manifest.append("status jpg_err_rgb_ids.jpg jpeg-color")

    base = pil_jpeg(im, quality=75, subsampling=2)
    gbase = pil_jpeg(im.convert("L"), quality=75)

    def err(name, data, status, strict=False):
        write(name, data)
        manifest.append(f"status {name} {status}" + (" strict" if strict else ""))

    err("jpg_err_progressive.jpg", pil_jpeg(im, quality=75, progressive=True), "jpeg-progressive")
    err("jpg_err_sof1.jpg", patch_marker(base, 0xC0, 0xC1), "jpeg-extended")
    err("jpg_err_sof3.jpg", patch_marker(base, 0xC0, 0xC3), "jpeg-lossless")
    err("jpg_err_sof5.jpg", patch_marker(base, 0xC0, 0xC5), "jpeg-hierarchical")
    err("jpg_err_sof9.jpg", patch_marker(base, 0xC0, 0xC9), "jpeg-arithmetic")
    err("jpg_err_sof10.jpg", patch_marker(base, 0xC0, 0xCA), "jpeg-arithmetic")
    err("jpg_err_dac.jpg", base[:2] + b"\xff\xcc\x00\x04\x00\x10" + base[2:], "jpeg-arithmetic")
    err("jpg_err_sof55.jpg", patch_marker(base, 0xC0, 0xF7), "jpeg-lossless")
    i = find_segment(base, 0xC0)
    p12 = bytearray(base)
    p12[i + 4] = 12
    err("jpg_err_12bit.jpg", bytes(p12), "jpeg-extended")
    err("jpg_err_cmyk.jpg", pil_jpeg(im.convert("CMYK"), quality=75), "jpeg-color")
    try:
        err("jpg_err_rgb_adobe.jpg", pil_jpeg(im, quality=75, keep_rgb=True), "jpeg-color")
    except TypeError:
        pass
    s411 = bytearray(base)
    s411[i + 11] = 0x41
    err("jpg_err_411.jpg", bytes(s411), "jpeg-sampling")
    s2 = bytearray(base)
    s2[i + 14] = 0x22
    err("jpg_err_chroma22.jpg", bytes(s2), "jpeg-sampling")
    ln = struct.unpack(">H", base[i + 2 : i + 4])[0]
    sof = base[i : i + 2 + ln]
    err("jpg_err_two_sof.jpg", base[:i] + sof + sof + base[i + 2 + ln :], "jpeg-multiframe")
    gi = find_segment(gbase, 0xC0)
    d0 = bytearray(gbase)
    d0[gi + 5 : gi + 7] = b"\x00\x00"
    err("jpg_err_height0.jpg", bytes(d0), "dimensions")
    big = bytearray(gbase)
    big[gi + 5 : gi + 9] = struct.pack(">HH", 2000, 2000)
    err("jpg_err_2000.jpg", bytes(big), "dimensions")
    big[gi + 5 : gi + 9] = struct.pack(">HH", 1024, 1025)
    err("jpg_err_1025.jpg", bytes(big), "dimensions")
    nc = bytearray(gbase)
    nc[gi + 9] = 2
    err("jpg_err_2comp.jpg", bytes(nc), "jpeg-color")
    err("jpg_err_trunc_half.jpg", base[: len(base) // 2], "truncated")
    err("jpg_err_trunc_noeoi.jpg", base[:-2], "truncated")
    err("jpg_err_trunc_hdr.jpg", base[:100], "truncated")
    err("jpg_err_trunc_3.jpg", base[:3], "truncated")
    err("jpg_err_soi_only.jpg", b"\xff\xd8", "not-image")
    err("jpg_trailing.jpg", base + b"\x00" * 1000 + b"\xff\xd8junk", "ok")
    err("jpg_trailing_strict.jpg", base + b"\x00", "trailing-data", strict=True)
    sos = find_segment(base, 0xDA)
    sos_len = struct.unpack(">H", base[sos + 2 : sos + 4])[0]
    data_start = sos + 2 + sos_len
    err("jpg_err_eoi_early.jpg", base[: data_start + 40] + b"\xff\xd9", "jpeg-huffman")
    err("jpg_err_eoi_noscan.jpg", base[:sos] + b"\xff\xd9", "jpeg-corrupt")
    garbage = bytearray(base)
    for k in range(data_start + 10, data_start + 60):
        garbage[k] = 0xFF if k % 2 else 0x7F
    err("jpg_err_huffdata.jpg", bytes(garbage), "jpeg-huffman")
    hi = find_segment(base, 0xC4)
    hbad = bytearray(base)
    hbad[hi + 5] = 200  # counts sum > 256
    err("jpg_err_dht_counts.jpg", bytes(hbad), "jpeg-corrupt")
    hbad = bytearray(base)
    hbad[hi + 5 : hi + 7] = bytes([2, 0])  # two 1-bit codes: all-ones code
    err("jpg_err_dht_full.jpg", bytes(hbad), "jpeg-corrupt")
    hbad = bytearray(base)
    hbad[hi + 4] = 0x25
    err("jpg_err_dht_class.jpg", bytes(hbad), "jpeg-corrupt")
    qi = find_segment(base, 0xDB)
    qbad = bytearray(base)
    qbad[qi + 4] = 0x05
    err("jpg_err_dqt_id.jpg", bytes(qbad), "jpeg-corrupt")
    qbad[qi + 4] = 0x20
    err("jpg_err_dqt_prec.jpg", bytes(qbad), "jpeg-corrupt")
    sbad = bytearray(base)
    sbad[sos + 6] = 0x22  # Y uses DC/AC table 2
    err("jpg_err_sos_table.jpg", bytes(sbad), "jpeg-corrupt")
    sbad = bytearray(base)
    sbad[sos + 5] = 9  # unknown component id
    err("jpg_err_sos_comp.jpg", bytes(sbad), "jpeg-corrupt")
    sbad = bytearray(base)
    sbad[sos + 2 + sos_len - 2] = 5  # Se != 63
    err("jpg_err_sos_se.jpg", bytes(sbad), "jpeg-corrupt")
    err("jpg_err_sos_first.jpg", base[:2] + base[sos:], "jpeg-corrupt")
    rstj = pil_jpeg(im, quality=70, subsampling=2, restart_marker_blocks=1)
    k = rstj.index(b"\xff\xd1")
    err("jpg_err_rst_order.jpg", rstj[: k + 1] + b"\xd3" + rstj[k + 2 :], "jpeg-corrupt")
    k = rstj.index(b"\xff\xd2")
    err("jpg_err_rst_missing.jpg", rstj[:k] + rstj[k + 2 :], "jpeg-corrupt")
    err("jpg_err_garbage_marker.jpg", base[:20] + b"\x00" + base[20:], "jpeg-corrupt")
    err("jpg_err_sniff.jpg", base[:2] + b"\x00" + base[2:], "not-image")
    err("jpg_err_rst_outside.jpg", base[:2] + b"\xff\xd0" + base[2:], "jpeg-corrupt")
    err("jpg_err_dri_len.jpg", base[:2] + b"\xff\xdd\x00\x05\x00\x01\x00" + base[2:], "jpeg-corrupt")
    err("jpg_err_seglen.jpg", base[:2] + b"\xff\xfe\x00\x01" + base[2:], "jpeg-corrupt")
    err("jpg_err_dnl.jpg", base[:2] + b"\xff\xdc\x00\x04\x00\x10" + base[2:], "jpeg-corrupt")
    err(
        "jpg_err_nodqt.jpg",
        base[:qi] + base[qi + 2 + struct.unpack(">H", base[qi + 2 : qi + 4])[0] :],
        "jpeg-corrupt",
    )


# --------------------------------------------------------------------------
# zlib streams
# --------------------------------------------------------------------------


class LsbWriter:
    def __init__(self):
        self.bits: list[int] = []

    def put(self, v, n):
        for i in range(n):
            self.bits.append((v >> i) & 1)

    def put_code(self, code, n):  # Huffman codes are sent MSB first
        for i in range(n - 1, -1, -1):
            self.bits.append((code >> i) & 1)

    def align(self):
        while len(self.bits) % 8:
            self.bits.append(0)

    def data(self):
        b = self.bits + [0] * (-len(self.bits) % 8)
        return bytes(sum(b[i + j] << j for j in range(8)) for i in range(0, len(b), 8))


def canon(lens):
    codes = {}
    bl = [0] * 16
    for l in lens:
        if l:
            bl[l] += 1
    code = 0
    nxt = [0] * 16
    for b in range(1, 16):
        code = (code + bl[b - 1]) << 1
        nxt[b] = code
    for s, l in enumerate(lens):
        if l:
            codes[s] = (nxt[l], l)
            nxt[l] += 1
    return codes


def zwrap(deflate: bytes, data_for_adler: bytes | None, adler_xor=0) -> bytes:
    a = zlib.adler32(data_for_adler if data_for_adler is not None else b"") ^ adler_xor
    return b"\x78\x9c" + deflate + struct.pack(">I", a & 0xFFFFFFFF)


def fixed_codes():
    lens = [8] * 144 + [9] * 112 + [7] * 24 + [8] * 8
    return canon(lens), canon([5] * 32)


def complete_lengths(symbols):
    """Lengths of a complete prefix code over @symbols (19-entry list)."""
    syms = list(symbols)
    if len(syms) == 1:
        syms.append(18 if syms[0] != 18 else 17)
    k = len(syms)
    L = (k - 1).bit_length()
    n_short = (1 << L) - k
    lens = [0] * 19
    for i, s in enumerate(syms):
        lens[s] = L - 1 if i < n_short else L
    return lens


def dyn_header(bw, lit_lens, dist_lens, clen_lens=None, raw_clen_syms=None):
    nlen, ndist = len(lit_lens), len(dist_lens)
    seq = raw_clen_syms if raw_clen_syms is not None else [(l, 0, 0) for l in lit_lens + dist_lens]
    if clen_lens is None:
        clen_lens = complete_lengths(sorted({s for s, _, _ in seq}))
    order = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]
    bw.put(nlen - 257, 5)
    bw.put(ndist - 1, 5)
    bw.put(19 - 4, 4)
    for i in range(19):
        bw.put(clen_lens[order[i]], 3)
    cc = canon(clen_lens)
    for s, eb, ev in seq:
        c, l = cc[s]
        bw.put_code(c, l)
        if eb:
            bw.put(ev, eb)


def gen_zlib() -> None:
    zdir = OUT / "zlib"
    zdir.mkdir(exist_ok=True)

    def ok(name, stream):
        data = zlib.decompress(stream)
        (zdir / name).write_bytes(stream)
        manifest.append(f"zlib zlib/{name} ok {len(data)} {zlib.crc32(data):08x}")

    def bad(name, stream, code):
        try:
            zlib.decompress(stream)
            raise AssertionError(f"python zlib accepted {name}")
        except zlib.error:
            pass
        (zdir / name).write_bytes(stream)
        manifest.append(f"zlib zlib/{name} err {code}")

    r = random.Random(7)
    text = b" ".join(
        r.choice([b"alpha", b"beta", b"gamma", b"delta", b"otpauth://totp/x"]) for _ in range(20000)
    )
    rnd = bytes(r.randrange(256) for _ in range(40000))
    far = rnd[:1000] + bytes(32768 - 1000) + rnd[:1000] * 3
    for nm, d in (
        ("empty", b""),
        ("one", b"x"),
        ("text", text),
        ("rand", rnd),
        ("far", far),
        ("zeros", bytes(300000)),
    ):
        for lvl in (0, 1, 6, 9):
            ok(f"{nm}_l{lvl}.z", zlib.compress(d, lvl))
        for strat, sn in ((zlib.Z_FIXED, "fixed"), (zlib.Z_HUFFMAN_ONLY, "huff"), (zlib.Z_RLE, "rle")):
            c = zlib.compressobj(9, zlib.DEFLATED, 15, 9, strat)
            ok(f"{nm}_{sn}.z", c.compress(d) + c.flush())
    # sync-flushed stream (empty stored blocks in the middle)
    c = zlib.compressobj(6)
    s = (
        c.compress(text[:5000])
        + c.flush(zlib.Z_SYNC_FLUSH)
        + c.compress(text[5000:9000])
        + c.flush(zlib.Z_FULL_FLUSH)
        + c.compress(b"tail")
        + c.flush()
    )
    ok("flushes.z", s)

    lit, dist = fixed_codes()
    # crafted valid: single distance code (incomplete code allowed by zlib)
    bw = LsbWriter()
    bw.put(1, 1)
    bw.put(2, 2)
    lit_lens = [0] * 257
    lit_lens[ord("a")] = 1
    lit_lens[256] = 2
    lit_lens += [2]  # length code 257 (3)
    dist_lens = [1]
    dyn_header(bw, lit_lens, dist_lens)
    lc = canon(lit_lens)
    bw.put_code(*lc[ord("a")])
    bw.put_code(*lc[257])  # len 3
    bw.put_code(0, 1)  # dist code 0 -> distance 1
    bw.put_code(*lc[256])
    ok("dyn_single_dist.z", zwrap(bw.data(), b"aaaa"))

    # invalid streams
    bad("hdr_check.z", b"\x78\x9d" + zlib.compress(b"x")[2:], "header")
    bad("hdr_cm.z", b"\x77\x9c"[0:1] + b"\x85" + zlib.compress(b"x")[2:], "header")
    bad("hdr_cinfo.z", bytes([0x88, (31 - (0x8800 % 31)) % 31]) + zlib.compress(b"x")[2:], "header")
    bad("hdr_dict.z", bytes([0x78, 0xBB]) + b"\x00\x00\x00\x01" + zlib.compress(b"x")[2:], "dict")
    bw = LsbWriter()
    bw.put(1, 1)
    bw.put(3, 2)
    bad("block3.z", zwrap(bw.data(), b""), "block")
    bw = LsbWriter()
    bw.put(1, 1)
    bw.put(0, 2)
    bw.align()
    bw.put(5, 16)
    bw.put(0x1234, 16)
    bad("stored_nlen.z", zwrap(bw.data() + b"hello", b"hello"), "stored")
    bw = LsbWriter()
    bw.put(1, 1)
    bw.put(1, 2)
    bw.put_code(*lit[286])
    bad("fixed_286.z", zwrap(bw.data(), b""), "code")
    bw = LsbWriter()
    bw.put(1, 1)
    bw.put(1, 2)
    bw.put_code(*lit[ord("a")])
    bw.put_code(*lit[257])
    bw.put_code(*dist[30])
    bad("fixed_dist30.z", zwrap(bw.data(), b""), "code")
    bw = LsbWriter()
    bw.put(1, 1)
    bw.put(1, 2)
    bw.put_code(*lit[ord("a")])
    bw.put_code(*lit[257])
    bw.put_code(*dist[1])  # distance 2 with 1 byte of history
    bw.put_code(*lit[256])
    bad("fixed_far.z", zwrap(bw.data(), b"aaaa"), "dist")
    good = zlib.compress(text[:3000])
    bad("adler.z", good[:-1] + bytes([good[-1] ^ 0x40]), "adler")
    (zdir / "trunc.z").write_bytes(good[:-3])
    manifest.append("zlib zlib/trunc.z trunc")
    (zdir / "trunc_mid.z").write_bytes(good[: len(good) // 2])
    manifest.append("zlib zlib/trunc_mid.z trunc")

    def dyn_bad(name, lit_lens, dist_lens, clen_lens=None, raw=None, hlit_override=None):
        bw = LsbWriter()
        bw.put(1, 1)
        bw.put(2, 2)
        if hlit_override is not None:
            bw.put(hlit_override[0], 5)
            bw.put(hlit_override[1], 5)
            bw.put(15, 4)
            for _ in range(19):
                bw.put(0, 3)
        else:
            dyn_header(bw, lit_lens, dist_lens, clen_lens, raw)
        bad(name, zwrap(bw.data() + bytes(8), b""), "tree")

    full_lit = [8] * 144 + [9] * 112 + [7] * 24 + [8] * 6
    dyn_bad("dyn_hlit.z", None, None, hlit_override=(30, 0))
    dyn_bad("dyn_hdist.z", None, None, hlit_override=(0, 30))
    dyn_bad("dyn_hdist31.z", None, None, hlit_override=(0, 31))
    over = list(full_lit)
    over[0] = 1
    dyn_bad("dyn_oversub.z", over, [5] * 30)
    inc = list(full_lit)
    inc[10] = 0
    dyn_bad("dyn_incomplete.z", inc, [5] * 30)
    noeob = [8] * 144 + [9] * 112 + [0] + [7] * 23 + [8] * 6
    dyn_bad("dyn_noeob.z", noeob, [5] * 30)
    cl = [0] * 19
    cl[8] = 1  # code-length code incomplete (single code)
    dyn_bad("dyn_clen_incomplete.z", [8] * 286, [8] * 30, clen_lens=cl, raw=[(8, 0, 0)] * 316)
    cl = [3] * 19  # over-subscribed code-length code
    dyn_bad("dyn_clen_oversub.z", [8] * 286, [8] * 30, clen_lens=cl, raw=[(8, 0, 0)] * 316)
    cl = [0] * 19
    cl[16] = 1
    cl[8] = 1
    dyn_bad("dyn_rep_first.z", [8] * 286, [8] * 30, clen_lens=cl, raw=[(16, 2, 0)] + [(8, 0, 0)] * 300)
    cl = [0] * 19
    cl[18] = 1
    cl[8] = 1
    dyn_bad("dyn_rep_overflow.z", [8] * 286, [8] * 30, clen_lens=cl, raw=[(8, 0, 0)] * 200 + [(18, 7, 127)])
    # dynamic header with lit/dist count fields describing 257+1
    lit_lens = [0] * 256 + [1, 1]
    bw = LsbWriter()
    bw.put(1, 1)
    bw.put(2, 2)
    dyn_header(bw, lit_lens, [0])
    lc = canon(lit_lens)
    bw.put_code(*lc[257])  # length with an all-zero distance code -> invalid distance code
    bad("dyn_nodist_used.z", zwrap(bw.data() + bytes(4), b""), "code")


# --------------------------------------------------------------------------
# QR renders
# --------------------------------------------------------------------------

OTP_URI = "otpauth://totp/feuristic:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=feuristic&digits=6"


def qr_render(payload, scale, border, size=None, error="m", version=None):
    q = segno.make(payload, error=error, micro=False, version=version)
    matrix = [[1 if v else 0 for v in row] for row in q.matrix]
    n = len(matrix)
    side = (n + 2 * border) * scale
    total = size or side
    off = (total - n * scale) // 2
    im = Image.new("L", (total, total), 255)
    px = im.load()
    for y in range(n):
        for x in range(n):
            if matrix[y][x]:
                for dy in range(scale):
                    for dx in range(scale):
                        px[off + x * scale + dx, off + y * scale + dy] = 0
    return im, matrix, off


def add_qr(name, data, matrix, off, scale, min_agree):
    write(name, data)
    mname = name.rsplit(".", 1)[0] + ".qr.txt"
    lines = [f"QR {off} {off} {scale} {len(matrix)}"] + ["".join(str(v) for v in row) for row in matrix]
    write(mname, ("\n".join(lines) + "\n").encode())
    manifest.append(f"qr {name} ok {mname} {min_agree}")


def png_from_image(im: Image.Image, mode="L", depth=8) -> bytes:
    w, h = im.size
    if mode == "1":
        data = list(im.convert("L").get_flattened_data())
        pix = [[(1 if data[y * w + x] >= 128 else 0,) for x in range(w)] for y in range(h)]
        return png_file(w, h, 0, 1, pix, filters=[0, 1, 2])
    b = io.BytesIO()
    im.convert(mode).save(b, "PNG", optimize=True)
    return b.getvalue()


def degrade(im: Image.Image, seed: int, blur=1.2, noise=18, gradient=True) -> Image.Image:
    r = random.Random(seed)
    im = im.convert("RGB").filter(ImageFilter.GaussianBlur(blur))
    w, h = im.size
    px = im.load()
    for y in range(h):
        for x in range(w):
            g = 1.0 - (0.45 * x / w + 0.25 * y / h) if gradient else 1.0
            c = px[x, y]
            v = [max(0, min(255, int(ch * g * 0.85 + 30 * g + r.randrange(-noise, noise + 1)))) for ch in c]
            px[x, y] = (v[0], int(v[1] * 0.97), int(v[2] * 0.9))
    return im


def gen_qr() -> None:
    if segno is None:
        print("segno missing: QR vectors skipped", file=sys.stderr)
        return
    im, m, off = qr_render(OTP_URI, 4, 4)
    add_qr("qr_otp_png1.png", png_from_image(im, "1"), m, off, 4, 990)
    im, m, off = qr_render(OTP_URI, 6, 6, size=420)
    add_qr("qr_otp_png8_420.png", png_from_image(im, "L"), m, off, 6, 990)
    rgb = Image.merge("RGB", (im, im.point(lambda v: v * 0.9 + 20), im.point(lambda v: v * 0.7 + 60)))
    add_qr("qr_otp_rgb.png", png_from_image(rgb, "RGB"), m, off, 6, 990)
    im, m, off = qr_render(OTP_URI, 22, 4, size=1000)
    add_qr("qr_otp_1000.png", png_from_image(im, "L"), m, off, 22, 990)
    add_qr("qr_otp_1000_q90.jpg", pil_jpeg(im.convert("RGB"), quality=90, subsampling=2), m, off, 22, 990)
    im, m, off = qr_render(OTP_URI, 9, 4, size=480)
    add_qr("qr_otp_480_q50_gray.jpg", pil_jpeg(im, quality=50), m, off, 9, 985)
    deg = degrade(im, 3)
    add_qr("qr_otp_480_photo.jpg", pil_jpeg(deg, quality=60, subsampling=2), m, off, 9, 0)
    im, m, off = qr_render(OTP_URI, 5, 4, size=260)
    add_qr("qr_otp_260_photo.png", png_from_image(degrade(im, 4, blur=0.8, noise=10), "L"), m, off, 5, 0)
    im, m, off = qr_render("HELLO", 44, 2, size=1020, error="l", version=1)
    add_qr("qr_v1_huge_modules.png", png_from_image(im, "L"), m, off, 44, 990)
    add_qr(
        "qr_v1_huge_modules_photo.jpg", pil_jpeg(degrade(im, 5, blur=3, noise=12), quality=70), m, off, 44, 0
    )
    im, m, off = qr_render(OTP_URI, 3, 2, size=140)
    add_qr("qr_otp_tiny_3px.png", png_from_image(im, "L"), m, off, 3, 990)
    big_payload = "feuristic-backup:1:" + "".join(
        random.Random(1).choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$%*+-./:") for _ in range(900)
    )
    im, m, off = qr_render(big_payload, 8, 4, size=1024, error="l")
    add_qr("qr_backup_1024.png", png_from_image(im, "L"), m, off, 8, 990)
    add_qr("qr_backup_1024_q70.jpg", pil_jpeg(im, quality=70), m, off, 8, 985)


def gen_seeds() -> None:
    """Fuzz seeds: one option byte (see tests/fuzz/fimg_fuzz_common.h) + the file."""
    seed_inf = SEED_PNG.parent / "fimg_inflate"
    for d in (SEED_PNG, SEED_JPEG, seed_inf):
        d.mkdir(parents=True, exist_ok=True)
        for p in d.iterdir():
            p.unlink()
    k = 0
    for p in sorted(OUT.rglob("*")):
        if not p.is_file() or p.stat().st_size > 24 * 1024:
            continue
        if p.suffix in (".png", ".jpg"):
            try:
                w, h = Image.open(p).size
            except Exception:  # damaged vectors are good seeds
                w = h = 0
            if w * h > 320 * 320:
                continue  # large images slow the fuzzers down ~100x
        opt = bytes([(k * 37) & 0x7F])  # vary configuration / chunking, keep CRC fixing on
        k += 1
        if p.suffix == ".png":
            (SEED_PNG / p.name).write_bytes(opt + p.read_bytes())
        elif p.suffix == ".jpg":
            (SEED_JPEG / p.name).write_bytes(opt + p.read_bytes())
        elif p.suffix == ".z":
            (seed_inf / p.name).write_bytes(opt + p.read_bytes())


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for p in OUT.rglob("*"):
        if p.is_file():
            p.unlink()
    gen_png()
    gen_jpeg()
    gen_zlib()
    gen_qr()
    header = [
        "# Generated by tests/c/fimg/gen_vectors.py -- do not edit.",
        "# SPDX-License-Identifier: GPL-3.0-only",
    ]
    (OUT / "manifest.txt").write_text("\n".join(header + manifest) + "\n")
    gen_seeds()
    total = sum(p.stat().st_size for p in OUT.rglob("*") if p.is_file())
    print(f"{len(manifest)} vectors, {total / 1024:.0f} KiB in {OUT}")


if __name__ == "__main__":
    main()
