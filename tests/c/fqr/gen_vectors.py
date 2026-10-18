# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Generate the lib/fqr image test corpus (1-bpp PBM P4 files + manifest).

    uv run python tests/c/fqr/gen_vectors.py                 # committed corpus
    uv run python tests/c/fqr/gen_vectors.py --large --out build/fqr-large

The committed corpus (tests/c/fqr/vectors/) is small and representative; the
--large set adds many more random variants of every category. Output is
deterministic for a given segno/Pillow version (seeded PRNG).

Manifest format (one record per image, read by tests/c/fqr/test_vectors.c):

    image <file> <status> <count> <polarity>
    code <version|0> <ecc L/M/Q/H|-> <mask|-> <inverted 0/1> <payload hex|-> [key=value ...]
    group <name> <payload hex>

status   : ok | notfound | fail (any failure, n_found == 0) | multiple
count    : exact number of distinct codes expected (status ok/multiple)
polarity : auto | both | normal | inverted
code keys: eci=<designator> sa=<index>/<total>/<parity> group=<name>
group    : concatenation (in index order) of the payloads of every code
           carrying group=<name> must equal the given payload.
"""

from __future__ import annotations

import argparse
import io
import math
import pathlib
import random
import sys

import segno
from PIL import Image, ImageChops, ImageDraw, ImageFilter

HERE = pathlib.Path(__file__).resolve().parent
LEVELS = "LMQH"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def qr(content, **kw):
    kw.setdefault("micro", False)
    kw.setdefault("boost_error", False)
    return segno.make(content, **kw)


def qr_fit(content, min_version: int, **kw):
    """Smallest symbol of version >= min_version holding content."""
    for v in range(min_version, 41):
        try:
            return qr(content, version=v, **kw)
        except segno.DataOverflowError:
            continue
    raise ValueError("content too long")


def symbol_image(q, scale: int = 1, border: int = 4, invert: bool = False) -> Image.Image:
    """Grayscale image of a segno symbol (0 = dark, 255 = light)."""
    m = q.matrix
    n = len(m)
    size = (n + 2 * border) * scale
    dark, light = (255, 0) if invert else (0, 255)
    im = Image.new("L", (n + 2 * border, n + 2 * border), light)
    px = im.load()
    for r, row in enumerate(m):
        for c, v in enumerate(row):
            if v:
                px[c + border, r + border] = dark
    if scale != 1:
        im = im.resize((size, size), Image.NEAREST)
    return im


def solve(a: list[list[float]], b: list[float]) -> list[float]:
    n = len(b)
    m = [row[:] + [b[i]] for i, row in enumerate(a)]
    for col in range(n):
        piv = max(range(col, n), key=lambda r: abs(m[r][col]))
        m[col], m[piv] = m[piv], m[col]
        for r in range(n):
            if r != col and m[r][col] != 0:
                f = m[r][col] / m[col][col]
                for k in range(col, n + 1):
                    m[r][k] -= f * m[col][k]
    return [m[i][n] / m[i][i] for i in range(n)]


def perspective_coeffs(dst, src):
    """Coefficients for Image.transform(PERSPECTIVE): output dst -> input src."""
    a, b = [], []
    for (x, y), (u, v) in zip(dst, src):
        a.append([x, y, 1, 0, 0, 0, -u * x, -u * y])
        b.append(u)
        a.append([0, 0, 0, x, y, 1, -v * x, -v * y])
        b.append(v)
    return solve(a, b)


def warp(im: Image.Image, corners, out_size, fill=255) -> Image.Image:
    """Map im's corners (TL, TR, BR, BL) onto `corners` in an out_size image."""
    w, h = im.size
    src = [(0, 0), (w, 0), (w, h), (0, h)]
    coeffs = perspective_coeffs(corners, src)
    return im.transform(out_size, Image.PERSPECTIVE, coeffs, Image.BICUBIC, fillcolor=fill)


def threshold(im: Image.Image, t: int = 128) -> Image.Image:
    return im.point(lambda v: 0 if v < t else 255).convert("1", dither=Image.NONE)


def local_threshold(im: Image.Image, radius: int, c: int) -> Image.Image:
    """Adaptive mean threshold: dark where pixel < local mean - c."""
    mean = im.filter(ImageFilter.BoxBlur(radius))
    diff = ImageChops.subtract(mean, im, scale=1.0, offset=0)  # mean - im, clipped at 0
    return diff.point(lambda v: 0 if v > c else 255).convert("1", dither=Image.NONE)


def salt_pepper(im1: Image.Image, p: float, rng: random.Random) -> Image.Image:
    data = bytearray(im1.convert("L").tobytes())
    for i in range(len(data)):
        if rng.random() < p:
            data[i] = 255 - data[i]
    return Image.frombytes("L", im1.size, bytes(data)).convert("1", dither=Image.NONE)


def jitter_quad(cx, cy, side, angle, jitter, rng):
    pts = []
    a = math.radians(angle)
    for ux, uy in ((-0.5, -0.5), (0.5, -0.5), (0.5, 0.5), (-0.5, 0.5)):
        x = ux * side + rng.uniform(-jitter, jitter) * side
        y = uy * side + rng.uniform(-jitter, jitter) * side
        pts.append((cx + x * math.cos(a) - y * math.sin(a), cy + x * math.sin(a) + y * math.cos(a)))
    return pts


def rand_text(rng: random.Random, n: int) -> bytes:
    alphabet = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~:/?#=&%"
    return bytes(rng.choice(alphabet) for _ in range(n))


def otpauth(rng: random.Random) -> bytes:
    secret = "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(32))
    issuer = rng.choice(["GitHub", "Example", "feuristic", "ACME%20Corp", "Proton"])
    acct = rng.choice(["alice", "bob@example.com", "carol", "dave%40mail.test"])
    return f"otpauth://totp/{issuer}:{acct}?secret={secret}&issuer={issuer}&digits=6&period=30".encode()


# ---------------------------------------------------------------------------
# corpus writer
# ---------------------------------------------------------------------------


class Corpus:
    def __init__(self, out: pathlib.Path):
        self.out = out
        self.lines: list[str] = []
        self.count = 0
        self.bytes = 0
        out.mkdir(parents=True, exist_ok=True)

    def add(
        self,
        name: str,
        im: Image.Image,
        status: str,
        codes: list[dict],
        polarity: str = "auto",
        count: int | None = None,
        groups: dict[str, bytes] | None = None,
    ) -> None:
        if im.mode != "1":
            im = threshold(im)
        fname = f"{name}.pbm"
        buf = io.BytesIO()
        im.save(buf, format="PPM")
        data = buf.getvalue()
        assert data.startswith(b"P4")
        (self.out / fname).write_bytes(data)
        self.bytes += len(data)
        self.count += 1
        if count is None:
            count = len(codes) if status in ("ok", "multiple") else 0
        self.lines.append(f"image {fname} {status} {count} {polarity}")
        for c in codes:
            fields = [
                "code",
                str(c.get("version", 0)),
                c.get("ecc", "-"),
                str(c["mask"]) if c.get("mask") is not None else "-",
                "1" if c.get("inverted") else "0",
                c["payload"].hex() if c.get("payload") is not None else "-",
            ]
            if c.get("eci") is not None:
                fields.append(f"eci={c['eci']}")
            if c.get("sa") is not None:
                fields.append("sa=%d/%d/%d" % c["sa"])
            if c.get("group"):
                fields.append(f"group={c['group']}")
            self.lines.append(" ".join(fields))
        for gname, payload in (groups or {}).items():
            self.lines.append(f"group {gname} {payload.hex()}")

    def finish(self) -> None:
        hdr = [
            "# lib/fqr test corpus, generated by tests/c/fqr/gen_vectors.py -- do not edit.",
            f"# {self.count} images, {self.bytes} bytes of PBM data.",
        ]
        (self.out / "manifest.txt").write_text("\n".join(hdr + self.lines) + "\n")


def code_of(q, payload: bytes, inverted: bool = False, check_meta: bool = True, **extra) -> dict:
    d = {"payload": payload, "inverted": inverted}
    if check_meta:
        d.update(version=q.version, ecc=q.error.upper(), mask=q.mask)
    d.update(extra)
    return d


# ---------------------------------------------------------------------------
# categories
# ---------------------------------------------------------------------------


def cat_all_versions(cp: Corpus, rng: random.Random, large: bool) -> None:
    """Every version x level at 1 px/module, all masks covered."""
    for v in range(1, 41):
        for li, lv in enumerate(LEVELS):
            mask = (v * 3 + li) % 8
            # About 70 % of the byte capacity, random binary data.
            cap = 0
            lo, hi = 1, 3000
            while lo <= hi:  # largest n that fits
                mid = (lo + hi) // 2
                try:
                    qr(b"x" * mid, version=v, error=lv, mode="byte")
                    cap, lo = mid, mid + 1
                except Exception:
                    hi = mid - 1
            n = max(1, int(cap * (0.7 if not large else rng.uniform(0.1, 1.0))))
            payload = bytes(rng.randrange(256) for _ in range(n))
            q = qr(payload, version=v, error=lv, mode="byte", mask=mask)
            assert q.version == v and q.mask == mask
            cp.add(f"ver{v:02d}{lv}_m{mask}_s1", symbol_image(q, 1), "ok", [code_of(q, payload)])


def cat_modes(cp: Corpus, rng: random.Random, large: bool) -> None:
    digits = "".join(rng.choice("0123456789") for _ in range(187)).encode()
    q = qr(digits.decode(), mode="numeric", error="q")
    cp.add("mode_numeric", symbol_image(q, 3), "ok", [code_of(q, digits)])
    alnum = b"HELLO WORLD $%*+-./: 0123456789 FEURISTIC"
    q = qr(alnum.decode(), mode="alphanumeric", error="h")
    cp.add("mode_alnum", symbol_image(q, 3), "ok", [code_of(q, alnum)])
    otp = otpauth(rng)
    q = qr(otp, mode="byte", error="m")
    cp.add("mode_byte_otpauth", symbol_image(q, 4), "ok", [code_of(q, otp)])
    kanji = "点茗漢字のテスト"
    q = qr(kanji, mode="kanji", error="m")
    cp.add("mode_kanji", symbol_image(q, 4), "ok", [code_of(q, kanji.encode("shift_jis"))])
    text = "Grüße, €uro — ünïcödé ✓"
    q = qr(text, mode="byte", eci=True, encoding="utf-8", error="m")
    cp.add("mode_eci_utf8", symbol_image(q, 3), "ok", [code_of(q, text.encode("utf-8"), eci=26)])
    text = "Ελληνικά"
    q = qr(text, mode="byte", eci=True, encoding="iso-8859-7", error="l")
    cp.add("mode_eci_greek", symbol_image(q, 3), "ok", [code_of(q, text.encode("iso-8859-7"), eci=9)])
    # Structured append: three symbols, separately and together.
    msg = b"feuristic-backup:1:" + rand_text(rng, 150)
    # (segno computes the parity over str(content): pass a str, not bytes.)
    seq = segno.make_sequence(msg.decode("ascii"), symbol_count=3, error="m", mode="byte")
    parity = 0
    for ch in msg:
        parity ^= ch
    ims = []
    for i, s in enumerate(seq):
        im = symbol_image(s, 3)
        ims.append(im)
        cp.add(
            f"mode_sa_{i}",
            im,
            "ok",
            [code_of(s, None, sa=(i, 3, parity), group="sa1")],
            groups={"sa1": msg} if i == 2 else None,
        )
    w = sum(i.size[0] for i in ims) + 40
    h = max(i.size[1] for i in ims) + 20
    big = Image.new("L", (w, h), 255)
    x = 10
    for im in ims:
        big.paste(im, (x, 10))
        x += im.size[0] + 10
    cp.add("mode_sa_all", big, "multiple", [code_of(s, None, sa=(i, 3, parity)) for i, s in enumerate(seq)])
    # Empty-ish and maximal payloads.
    q = qr(b"\x00", mode="byte", version=1, error="h")
    cp.add("mode_byte_zero", symbol_image(q, 2), "ok", [code_of(q, b"\x00")])
    big_digits = "".join(rng.choice("0123456789") for _ in range(7089)).encode()
    q = qr(big_digits.decode(), mode="numeric", version=40, error="l")
    cp.add("mode_numeric_max", symbol_image(q, 1), "ok", [code_of(q, big_digits)])


def cat_scales(cp: Corpus, rng: random.Random, large: bool) -> None:
    for v, lv in ((2, "M"), (10, "Q")):
        payload = rand_text(rng, 20 if v == 2 else 150)
        q = qr(payload, version=v, error=lv, mode="byte")
        for s in range(1, 9):
            cp.add(f"scale_v{v}_s{s}", symbol_image(q, s), "ok", [code_of(q, payload)])


def cat_rotations(cp: Corpus, rng: random.Random, large: bool) -> None:
    step = 5 if large else 15
    for ang in range(0, 360, step):
        v = rng.choice([1, 2, 3, 4, 5, 6])
        payload = rand_text(rng, rng.randrange(5, 40))
        q = qr_fit(payload, v, error=rng.choice(LEVELS), mode="byte")
        mp = rng.uniform(2.6, 4.5)
        im = symbol_image(q, 8)
        side = (len(q.matrix) + 8) * mp
        W = int(side * 1.5) + 10
        quad = jitter_quad(W / 2, W / 2, side, ang, 0.0, rng)
        out = warp(im, quad, (W, W))
        cp.add(f"rot_{ang:03d}", threshold(out), "ok", [code_of(q, payload)])


def cat_perspective(cp: Corpus, rng: random.Random, large: bool) -> None:
    n = 120 if large else 24
    for i in range(n):
        payload = otpauth(rng) if i % 2 == 0 else rand_text(rng, rng.randrange(10, 200))
        q = qr(payload, error=rng.choice(LEVELS), mode="byte")
        mp = rng.uniform(2.8, 6.0)
        side = (len(q.matrix) + 8) * mp
        if side > 650:
            mp = 650 / (len(q.matrix) + 8)
            side = 650
        W = int(side * 1.45) + 10
        quad = jitter_quad(W / 2, W / 2, side, rng.uniform(0, 360), 0.08, rng)
        out = warp(symbol_image(q, 6), quad, (W, W))
        cp.add(f"persp_{i:03d}", threshold(out), "ok", [code_of(q, payload)])


def cat_blur(cp: Corpus, rng: random.Random, large: bool) -> None:
    n = 60 if large else 12
    for i in range(n):
        payload = rand_text(rng, rng.randrange(10, 120))
        q = qr(payload, error=rng.choice("MQH"), mode="byte")
        mp = rng.uniform(4.0, 7.0)
        side = (len(q.matrix) + 8) * mp
        W = int(side * 1.4) + 10
        quad = jitter_quad(W / 2, W / 2, side, rng.uniform(0, 360), 0.04, rng)
        out = warp(symbol_image(q, 6), quad, (W, W))
        sigma = rng.uniform(0.6, 0.3 * mp)
        out = out.filter(ImageFilter.GaussianBlur(sigma))
        t = rng.randrange(95, 165)  # off-centre thresholds erode / dilate dark modules
        cp.add(f"blur_{i:03d}", threshold(out, t), "ok", [code_of(q, payload)])


def cat_noise(cp: Corpus, rng: random.Random, large: bool) -> None:
    n = 40 if large else 8
    for i in range(n):
        payload = rand_text(rng, rng.randrange(10, 80))
        q = qr(payload, error="h" if i % 2 else "q", mode="byte")
        mp = rng.uniform(4.0, 6.0)
        side = (len(q.matrix) + 8) * mp
        W = int(side * 1.35) + 10
        quad = jitter_quad(W / 2, W / 2, side, rng.uniform(0, 360), 0.03, rng)
        out = threshold(warp(symbol_image(q, 6), quad, (W, W)))
        p = 0.005 + 0.025 * (i % 4) / 3
        cp.add(f"noise_{i:03d}", salt_pepper(out, p, rng), "ok", [code_of(q, payload)])


def cat_lighting(cp: Corpus, rng: random.Random, large: bool) -> None:
    n = 30 if large else 6
    for i in range(n):
        payload = otpauth(rng)
        q = qr(payload, error="m", mode="byte")
        mp = rng.uniform(4.0, 6.0)
        side = (len(q.matrix) + 8) * mp
        W = int(side * 1.4) + 10
        quad = jitter_quad(W / 2, W / 2, side, rng.uniform(0, 360), 0.05, rng)
        out = warp(symbol_image(q, 6), quad, (W, W))
        # Strong illumination gradient + low contrast, then adaptive threshold.
        grad = Image.linear_gradient("L").resize((W, W)).rotate(rng.uniform(0, 360))
        out = ImageChops.add(out.point(lambda v: 60 + v * 0.45), grad.point(lambda v: v * 0.45))
        out = out.filter(ImageFilter.GaussianBlur(1.0))
        cp.add(f"light_{i:03d}", local_threshold(out, int(mp * 4), 8), "ok", [code_of(q, payload)])


def cat_inverted(cp: Corpus, rng: random.Random, large: bool) -> None:
    n = 18 if large else 6
    for i in range(n):
        payload = rand_text(rng, rng.randrange(10, 60))
        q = qr(payload, error=rng.choice(LEVELS), mode="byte")
        mp = rng.uniform(3.0, 5.0)
        side = (len(q.matrix) + 8) * mp
        W = int(side * 1.4) + 10
        quad = jitter_quad(W / 2, W / 2, side, rng.uniform(0, 360) if i else 0, 0.04 if i else 0, rng)
        out = warp(symbol_image(q, 6, invert=True), quad, (W, W), fill=0)
        cp.add(f"inv_{i:03d}", threshold(out), "ok", [code_of(q, payload, inverted=True)])


def cat_multi(cp: Corpus, rng: random.Random, large: bool) -> None:
    p1, p2, p3 = otpauth(rng), rand_text(rng, 40), rand_text(rng, 25)
    q1, q2, q3 = qr(p1, error="m"), qr(p2, error="q"), qr(p3, error="l")
    a, b, c = symbol_image(q1, 4), symbol_image(q2, 5), symbol_image(q3, 3)
    im = Image.new("L", (a.size[0] + b.size[0] + 30, max(a.size[1], b.size[1]) + 20), 255)
    im.paste(a, (10, 10))
    im.paste(b, (a.size[0] + 20, 10))
    cp.add("multi_two", im, "multiple", [code_of(q1, p1), code_of(q2, p2)])
    # Two rotated codes in a perspective photo.
    W = 640
    base = Image.new("L", (W, 400), 255)
    for img, cx, ang in ((a, 170, 20), (b, 470, -35)):
        side = img.size[0] * 0.9
        quad = jitter_quad(cx, 200, side, ang, 0.03, rng)
        layer = warp(img, quad, (W, 400), fill=255)
        base = ImageChops.darker(base, layer)
    cp.add("multi_two_rotated", threshold(base), "multiple", [code_of(q1, p1), code_of(q2, p2)])
    im3 = Image.new("L", (a.size[0] + b.size[0] + c.size[0] + 40, max(a.size[1], b.size[1]) + 20), 255)
    im3.paste(a, (10, 10))
    im3.paste(b, (a.size[0] + 20, 10))
    im3.paste(c, (a.size[0] + b.size[0] + 30, 10))
    cp.add("multi_three", im3, "multiple", [code_of(q1, p1), code_of(q2, p2), code_of(q3, p3)])
    # Same code twice: two distinct (non-overlapping) codes.
    im2 = Image.new("L", (2 * a.size[0] + 30, a.size[1] + 20), 255)
    im2.paste(a, (10, 10))
    im2.paste(a, (a.size[0] + 20, 10))
    cp.add("multi_same_twice", im2, "multiple", [code_of(q1, p1)], count=2)
    # Normal + inverted: AUTO finds one, BOTH finds two.
    inv = symbol_image(q2, 5, invert=True)
    im4 = Image.new("L", (a.size[0] + inv.size[0] + 40, max(a.size[1], inv.size[1]) + 40), 255)
    im4.paste(a, (10, 10))
    im4.paste(0, (a.size[0] + 20, 0, im4.size[0], im4.size[1]))
    im4.paste(inv, (a.size[0] + 30, 20))
    cp.add("multi_mixed_auto", im4, "ok", [code_of(q1, p1)], polarity="auto")
    cp.add(
        "multi_mixed_both",
        im4,
        "multiple",
        [code_of(q1, p1), code_of(q2, p2, inverted=True)],
        polarity="both",
    )


def cat_negative(cp: Corpus, rng: random.Random, large: bool) -> None:
    cp.add("none_blank", Image.new("1", (320, 240), 1), "notfound", [])
    cp.add("none_black", Image.new("1", (200, 200), 0), "notfound", [])
    noise = Image.frombytes("L", (300, 300), bytes(rng.choice((0, 255)) for _ in range(300 * 300)))
    cp.add("none_noise", noise.convert("1", dither=Image.NONE), "notfound", [], polarity="both")
    # Text-like blobs and boxes.
    im = Image.new("L", (400, 300), 255)
    d = ImageDraw.Draw(im)
    for _ in range(120):
        x, y = rng.randrange(400), rng.randrange(300)
        w, h = rng.randrange(2, 30), rng.randrange(2, 30)
        d.rectangle((x, y, x + w, y + h), fill=0 if rng.random() < 0.6 else 255)
    cp.add("none_blobs", threshold(im), "notfound", [], polarity="both")
    # Checkerboard.
    cb = Image.new("1", (256, 256))
    cb.putdata([((x // 4) + (y // 4)) % 2 for y in range(256) for x in range(256)])
    cp.add("none_checker", cb, "notfound", [], polarity="both")
    # Decoy: three finder patterns with random data in between.
    q = qr(rand_text(rng, 30), version=3, error="m")
    m = [bytearray(r) for r in q.matrix]
    n = len(m)
    for r in range(n):
        for c in range(n):
            in_finder = (r < 9 and c < 9) or (r < 9 and c >= n - 8) or (r >= n - 8 and c < 9)
            if not in_finder and r != 6 and c != 6:
                m[r][c] = rng.randrange(2)

    class Fake:  # minimal stand-in for symbol_image
        matrix = m

    cp.add("none_decoy_finders", symbol_image(Fake, 5), "fail", [])


def cat_damage(cp: Corpus, rng: random.Random, large: bool) -> None:
    n = 12 if large else 4
    for i in range(n):
        for beyond in (False, True):
            payload = rand_text(rng, rng.randrange(20, 40))
            q = qr(payload, error="h", mode="byte", version=rng.randrange(5, 10))
            scale = 4
            im = symbol_image(q, scale)
            nmod = len(q.matrix)
            d = ImageDraw.Draw(im)
            # Damage a square in the lower-right data area (away from finders).
            frac = 0.12 if not beyond else 0.55
            side = max(2, int(nmod * math.sqrt(frac * 0.5)))
            x0 = 4 + nmod - 9 - side - rng.randrange(0, 3)
            y0 = 4 + nmod - 9 - side - rng.randrange(0, 3)
            if beyond:
                x0, y0 = 4 + 9, 4 + 9
                side = nmod - 18
            px = im.load()
            for yy in range(y0, y0 + side):
                for xx in range(x0, x0 + side):
                    if rng.random() < 0.5:  # really flip the module
                        fill = 255 - px[xx * scale, yy * scale]
                        d.rectangle(
                            (xx * scale, yy * scale, xx * scale + scale - 1, yy * scale + scale - 1),
                            fill=fill,
                        )
            name = f"damage_{'beyond' if beyond else 'within'}_{i:02d}"
            if beyond:
                cp.add(name, im, "fail", [])
            else:
                cp.add(name, im, "ok", [code_of(q, payload)])


def oled_photo(
    fb: Image.Image,
    rng: random.Random,
    up: int,
    gaps: bool,
    persp: float,
    angle: float,
    blur: float,
    max_w: int,
) -> Image.Image:
    """Simulate a phone photo of the 128x64 OLED (lit = light)."""
    big = fb.resize((fb.size[0] * up, fb.size[1] * up), Image.NEAREST)
    if gaps:  # dark gaps between OLED pixels
        d = ImageDraw.Draw(big)
        for x in range(0, big.size[0], up):
            d.line((x, 0, x, big.size[1]), fill=60)
        for y in range(0, big.size[1], up):
            d.line((0, y, big.size[0], y), fill=60)
    bez = up * 8
    panel = Image.new("L", (big.size[0] + 2 * bez, big.size[1] + 2 * bez), 25)
    panel.paste(big, (bez, bez))
    pw, ph = panel.size
    W, H = int(pw * 1.25), int(ph * 1.5)
    a = math.radians(angle)
    pts = []
    for ux, uy in ((-0.5, -0.5), (0.5, -0.5), (0.5, 0.5), (-0.5, 0.5)):
        x = ux * pw + rng.uniform(-persp, persp) * pw
        y = uy * ph + rng.uniform(-persp, persp) * ph
        pts.append((W / 2 + x * math.cos(a) - y * math.sin(a), H / 2 + x * math.sin(a) + y * math.cos(a)))
    out = warp(panel, pts, (W, H), fill=90)
    if blur > 0:
        out = out.filter(ImageFilter.GaussianBlur(blur))
    if W > max_w:  # the firmware downscales large images
        out = out.resize((max_w, int(H * max_w / W)), Image.BILINEAR)
    return threshold(out, 128)


def cat_oled(cp: Corpus, rng: random.Random, large: bool) -> None:
    cases = []
    for v in range(1, 10):
        cases.append((v, 1))
    for v in range(1, 4):
        cases.append((v, 2))
    reps = 3 if large else 1
    idx = 0
    for v, ppm in cases:
        for rep in range(reps):
            for inverted in (False, True):
                if not large and inverted and (v + ppm) % 3 != 0 and v not in (1, 9):
                    continue
                payload = otpauth(rng) if v >= 5 else rand_text(rng, rng.randrange(5, 14 + 4 * v))
                try:
                    q = qr(payload, version=v, error="l" if v >= 7 else rng.choice("LM"), mode="byte")
                except Exception:
                    payload = payload[: 10 * v]
                    q = qr(payload, version=v, error="l", mode="byte")
                n = len(q.matrix)
                # Framebuffer: lit = 255. Normal display: lit background with
                # dark modules; inverted: lit modules on unlit background.
                fb = Image.new("L", (128, 64), 0)
                quiet = min(4, (64 - n * ppm) // (2 * ppm))
                qimg = symbol_image(q, ppm, border=quiet, invert=False)
                if inverted:
                    qimg = qimg.point(lambda x: 255 - x)
                ox = (128 - qimg.size[0]) // 2
                oy = (64 - qimg.size[1]) // 2
                fb.paste(qimg.point(lambda x: 230 if x else 0), (ox, oy))
                up = rng.choice([5, 6, 7, 8])
                gaps = rng.random() < 0.3 and up >= 6
                persp = rng.uniform(0.0, 0.06)
                angle = rng.uniform(-25, 25) if rep or idx % 2 else rng.uniform(-5, 5)
                # Beyond ~0.2 * up an isolated lit (or unlit) OLED pixel is
                # erased by blur + global threshold: no decoder can help.
                blur = rng.uniform(0.0, 0.18 * up)
                photo = oled_photo(fb, rng, up, gaps, persp, angle, blur, 724 if large else 600)
                tag = f"oled_v{v}_p{ppm}_{'inv' if inverted else 'nrm'}_{rep}"
                # In a photo the lit OLED pixels are light: a normal display
                # shows dark modules on a lit background (normal polarity).
                cp.add(tag, photo, "ok", [code_of(q, payload, inverted=inverted)])
                idx += 1


def cat_perf(cp: Corpus, rng: random.Random, large: bool) -> None:
    """724x724 images (the firmware's working size) for timing."""
    S = 724
    payload = otpauth(rng) + b"&" + rand_text(rng, 60)
    q = qr_fit(payload, 10, error="m", mode="byte")
    side = (len(q.matrix) + 8) * 7.0
    quad = jitter_quad(S / 2, S / 2, side, 23, 0.06, rng)
    out = warp(symbol_image(q, 6), quad, (S, S)).filter(ImageFilter.GaussianBlur(1.2))
    cp.add("perf_photo_v10_724", threshold(out, 120), "ok", [code_of(q, payload)])
    payload = rand_text(rng, 1800)
    q = qr(payload, version=40, error="l", mode="byte")
    side = (len(q.matrix) + 8) * 3.6
    quad = jitter_quad(S / 2, S / 2, side, 4, 0.01, rng)
    cp.add("perf_v40_724", threshold(warp(symbol_image(q, 4), quad, (S, S))), "ok", [code_of(q, payload)])
    payload = otpauth(rng) + b"&image=" + rand_text(rng, 40)
    q = qr(payload, version=9, error="l", mode="byte")
    fb = Image.new("L", (128, 64), 0)
    qimg = symbol_image(q, 1, border=4)
    fb.paste(qimg.point(lambda x: 230 if x else 0), ((128 - qimg.size[0]) // 2, (64 - qimg.size[1]) // 2))
    photo = oled_photo(fb, rng, 8, False, 0.04, 8.0, 1.0, S)
    canvas = Image.new("1", (S, S), 0)
    canvas.paste(photo, (0, (S - photo.size[1]) // 2))
    cp.add("perf_oled_v9_724", canvas, "ok", [code_of(q, payload)])
    noise = Image.frombytes("L", (S, S), bytes(rng.choice((0, 255)) for _ in range(S * S)))
    cp.add("perf_noise_724", noise.convert("1", dither=Image.NONE), "notfound", [], polarity="both")
    # Hostile: hundreds of finder-like patterns at random positions/sizes.
    im = Image.new("L", (S, S), 255)
    d = ImageDraw.Draw(im)
    for _ in range(400):
        m = rng.choice([2, 3, 4, 5, 6])
        x, y = rng.randrange(0, S - 7 * m), rng.randrange(0, S - 7 * m)
        d.rectangle((x, y, x + 7 * m - 1, y + 7 * m - 1), fill=0)
        d.rectangle((x + m, y + m, x + 6 * m - 1, y + 6 * m - 1), fill=255)
        d.rectangle((x + 2 * m, y + 2 * m, x + 5 * m - 1, y + 5 * m - 1), fill=0)
    cp.add("perf_hostile_finders_724", threshold(im), "notfound", [], polarity="both")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=pathlib.Path, default=HERE / "vectors")
    ap.add_argument("--large", action="store_true", help="generate the large optional set")
    ap.add_argument("--seed", type=int, default=20261017)
    args = ap.parse_args()
    rng = random.Random(args.seed + (1 if args.large else 0))
    out = args.out
    if out.exists():
        for f in out.glob("*.pbm"):
            f.unlink()
    cp = Corpus(out)
    for cat in (
        cat_all_versions,
        cat_modes,
        cat_scales,
        cat_rotations,
        cat_perspective,
        cat_blur,
        cat_noise,
        cat_lighting,
        cat_inverted,
        cat_multi,
        cat_negative,
        cat_damage,
        cat_oled,
        cat_perf,
    ):
        before, bbytes = cp.count, cp.bytes
        cat(cp, rng, args.large)
        print(
            f"{cat.__name__:20s} {cp.count - before:4d} images {(cp.bytes - bbytes) / 1024:7.0f} KiB",
            file=sys.stderr,
        )
    cp.finish()
    print(f"{cp.count} images, {cp.bytes / 1024:.0f} KiB -> {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
