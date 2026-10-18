# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Generate tests/c/frsa/frsa_vectors.h (committed).

    uv run python tests/c/frsa/gen_vectors.py > tests/c/frsa/frsa_vectors.h

Sources:
* RSA keys generated here from a fixed seed (reproducible), components and
  expected results computed with CPython big integers and cross-checked with
  the ``cryptography`` package;
* tests/vectors/rsa/wycheproof_rsa.json (trimmed Wycheproof, see its
  ``source`` field for the upstream commit);
* number-theory vectors: Carmichael numbers, strong pseudoprimes to base 2,
  Jaeschke's psi_k strong pseudoprimes to the first k prime bases, Mersenne
  primes, and a large Chernick Carmichael number found from the seed.
"""

import hashlib
import json
import os
import random
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

HERE = os.path.dirname(os.path.abspath(__file__))
WYCHEPROOF = os.path.join(HERE, "..", "..", "vectors", "rsa", "wycheproof_rsa.json")
RNG = random.Random(0x20261017)

SMALL_PRIMES = [p for p in range(3, 2000) if all(p % d for d in range(2, int(p**0.5) + 1))]


def _odd_primes(count):
    out, c = [], 3
    while len(out) < count:
        if all(c % p for p in out if p * p <= c):
            out.append(c)
        c += 2
    return out


SIEVE_PRIMES = _odd_primes(2048)
SIEVE_PRODUCT = 1
for _p in SIEVE_PRIMES:
    SIEVE_PRODUCT *= _p


def mr_round(w, b):
    """FIPS 186-5 B.3.1, one round with base b. Returns 1 / 0."""
    m, a = w - 1, 0
    while m % 2 == 0:
        m //= 2
        a += 1
    z = pow(b, m, w)
    if z in (1, w - 1):
        return 1
    for _ in range(a - 1):
        z = z * z % w
        if z == w - 1:
            return 1
        if z == 1:
            return 0
    return 0


def is_prime(n):
    if n < 2:
        return False
    for p in [2, *SMALL_PRIMES[:50]]:
        if n % p == 0:
            return n == p
    return all(mr_round(n, RNG.randrange(2, n - 1)) for _ in range(40))


def rand_prime(bits, e=None, mod4=None):
    while True:
        c = RNG.getrandbits(bits) | (3 << (bits - 2)) | 1
        if mod4 is not None and c % 4 != mod4:
            continue
        if e is not None and _gcd(e, c - 1) != 1:
            continue
        if is_prime(c):
            return c


def _gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def sieve_ref(c):
    if c < 3 or c % 2 == 0:
        return 0
    return 1 if _gcd(c, SIEVE_PRODUCT) == 1 else 0


def blen(x):
    return max(1, (x.bit_length() + 7) // 8)


def be(x, n=None):
    return x.to_bytes(blen(x) if n is None else n, "big")


# ---------------------------------------------------------------------------
# C emission helpers
# ---------------------------------------------------------------------------

_arrays = []
_counter = [0]


_seen = {}


def arr(data: bytes) -> str:
    """Emit a (deduplicated) byte array, return 'name, len'."""
    data = bytes(data)
    if data not in _seen:
        name = f"v{_counter[0]}"
        _counter[0] += 1
        body = ",".join(str(b) for b in data) if data else "0"
        _arrays.append(f"static const uint8_t {name}[]={{{body}}};")
        _seen[data] = name
    return f"{_seen[data]}, {len(data)}"


def make_key(p, q, e):
    n = p * q
    nl = blen(n)
    cl = (nl + 1) // 2
    dp = pow(e, -1, p - 1)
    dq = pow(e, -1, q - 1)
    qinv = pow(q, -1, p)
    d = pow(e, -1, (p - 1) * (q - 1) // _gcd(p - 1, q - 1))
    # cross-check with the cryptography package (it rejects some e values)
    if e in (3, 65537):
        priv = rsa.RSAPrivateNumbers(
            p, q, d, rsa.rsa_crt_dmp1(d, p), rsa.rsa_crt_dmq1(d, q), qinv, rsa.RSAPublicNumbers(e, n)
        ).private_key()
        if n.bit_length() >= 1024:
            sig = priv.sign(b"abc", padding.PKCS1v15(), hashes.SHA256())
            assert pow(int.from_bytes(sig, "big"), e, n) > 0
    return n, nl, cl, dp, dq, qinv, d


def main():
    out = []
    w = out.append

    # ---------------- generated keys ----------------
    key_specs = [
        (512, 65537, False),
        (768, 3, False),
        (1023, 65537, False),
        (1024, 65537, False),
        (1024, 65537, True),  # p < q
        (1024, 0x7FFFFFFF, False),
        (1024, 0xFFFFFFFF, False),  # composite e, needs 2 limbs
        (1024, 0x80000001, False),
        (1536, 17, False),
        (2047, 65537, False),
        (2048, 65537, False),
        (2048, 65537, True),
        (2048, 3, False),
    ]
    keys = []
    for bits, e, swap in key_specs:
        pb = (bits + 1) // 2
        qb = bits - pb
        while True:
            p = rand_prime(pb, e)
            q = rand_prime(qb, e)
            if p != q and (p * q).bit_length() in (bits, bits - 1):
                break
        if swap == (p > q):
            p, q = q, p
        n, nl, cl, dp, dq, qinv, d = make_key(p, q, e)
        msgs = []
        for _ in range(2):
            m = RNG.randrange(0, n)
            msgs.append((m, pow(m, d, n)))
        msgs.append((n - 1, pow(n - 1, d, n)))
        keys.append((p, q, e, n, nl, cl, dp, dq, qinv, msgs))

    w(
        "typedef struct {\n  const uint8_t *m;\n  size_t mlen;\n"
        "  const uint8_t *s;\n  size_t slen;\n} kat_msg;\n"
    )
    w(
        "typedef struct {\n  const uint8_t *p;\n  size_t plen;\n  const uint8_t *q;\n  size_t qlen;\n"
        "  uint32_t e;\n  const uint8_t *n;\n  size_t nlen;\n  const uint8_t *dp;\n  size_t dplen;\n"
        "  const uint8_t *dq;\n  size_t dqlen;\n  const uint8_t *qinv;\n  size_t qinvlen;\n"
        "  const kat_msg *msgs;\n  size_t nmsgs;\n} kat_key;\n"
    )
    kat_lines = []
    for i, (p, q, e, n, nl, cl, dp, dq, qinv, msgs) in enumerate(keys):
        mlines = [f"{{{arr(be(m, nl))}, {arr(be(s, nl))}}}" for m, s in msgs]
        _arrays.append(f"static const kat_msg kat_msgs_{i}[] = {{{', '.join(mlines)}}};")
        kat_lines.append(
            f"  {{{arr(be(p))}, {arr(be(q))}, 0x{e:x}u, {arr(be(n, nl))}, {arr(be(dp, cl))}, "
            f"{arr(be(dq, cl))}, {arr(be(qinv, cl))}, kat_msgs_{i}, {len(msgs)}}},"
        )

    # ---------------- Wycheproof ----------------
    with open(WYCHEPROOF) as f:
        wp = json.load(f)
    w(
        "typedef struct {\n  const uint8_t *in;\n  size_t inlen;\n  const uint8_t *out;\n  size_t outlen;\n"
        "  int tc;\n  int valid_format;\n} wp_case;\n"
    )
    w(
        "typedef struct {\n  const uint8_t *p;\n  size_t plen;\n  const uint8_t *q;\n  size_t qlen;\n"
        "  uint32_t e;\n  const uint8_t *n;\n  size_t nlen;\n  const uint8_t *dp;\n  size_t dplen;\n"
        "  const uint8_t *dq;\n  size_t dqlen;\n  const uint8_t *qinv;\n  size_t qinvlen;\n"
        "  const wp_case *cases;\n  size_t ncases;\n} wp_key;\n"
    )
    wp_lines = []
    gi = 0

    def wp_key_line(k, cases_name, ncases, crt=True):
        # Decrypt keys only carry p, q, e, n: the test derives dp/dq/qinv with
        # frsa_complete() (checked against the KAT keys) to keep the header small.
        h = bytes.fromhex
        crt_part = (
            f"{arr(h(k['dp']))}, {arr(h(k['dq']))}, {arr(h(k['qinv']))}"
            if crt
            else "NULL, 0, NULL, 0, NULL, 0"
        )
        return (
            f"  {{{arr(h(k['p']))}, {arr(h(k['q']))}, 0x{k['e']:x}u, "
            f"{arr(h(k['n']))}, {crt_part}, {cases_name}, {ncases}}},"
        )

    for g in wp["decrypt"]:
        k = g["key"]
        n = int(k["n"], 16)
        d = pow(k["e"], -1, (int(k["p"], 16) - 1) * (int(k["q"], 16) - 1))
        nl = len(k["n"]) // 2
        lines = []
        for t in g["tests"]:
            # The padding-variant cases (tcId 9..25) only matter for the
            # Python unpadding tests; for the raw private operation they are
            # ordinary random inputs, so the C header keeps a few of them.
            if 12 <= t["tcId"] <= 25:
                continue
            ct = bytes.fromhex(t["ct"])
            c = int.from_bytes(ct, "big") if ct else 0
            ok = len(ct) == nl and c < n
            # The expected plaintext block is not stored: em^e == ct (checked
            # with frsa_public) identifies the unique correct em < n.
            assert not ok or pow(pow(c, d, n), k["e"], n) == c
            lines.append(f"{{{arr(ct)}, NULL, 0, {t['tcId']}, {1 if ok else 0}}}")
        _arrays.append(f"static const wp_case wp_dec_cases_{gi}[] = {{{', '.join(lines)}}};")
        wp_lines.append(wp_key_line(k, f"wp_dec_cases_{gi}", len(lines), crt=False))
        gi += 1

    hash_fn = {"SHA-256": hashlib.sha256, "SHA-384": hashlib.sha384, "SHA-512": hashlib.sha512}
    prefix = {
        "SHA-256": "3031300d060960864801650304020105000420",
        "SHA-384": "3041300d060960864801650304020205000430",
        "SHA-512": "3051300d060960864801650304020305000440",
    }
    sign_lines = []
    for si, g in enumerate(wp["sign"]):
        k = g["key"]
        nl = len(k["n"]) // 2
        lines = []
        for t in g["tests"][:3]:
            digest = hash_fn[g["sha"]](bytes.fromhex(t["msg"])).digest()
            t_ = bytes.fromhex(prefix[g["sha"]]) + digest
            em = b"\x00\x01" + b"\xff" * (nl - len(t_) - 3) + b"\x00" + t_
            sig = bytes.fromhex(t["sig"])
            lines.append(f"{{{arr(em)}, {arr(sig)}, {t['tcId']}, 1}}")
        _arrays.append(f"static const wp_case wp_sig_cases_{si}[] = {{{', '.join(lines)}}};")
        sign_lines.append(wp_key_line(k, f"wp_sig_cases_{si}", len(lines)))

    # ---------------- modpow ----------------
    w(
        "typedef struct {\n  const uint8_t *b;\n  size_t blen;\n  const uint8_t *x;\n  size_t xlen;\n"
        "  const uint8_t *m;\n  size_t mlen;\n  const uint8_t *r;\n  size_t rlen;\n} mp_case;\n"
    )
    mp_lines = []
    mod_sizes = [3, 5, 255, 0x10001, 2**61 - 1]
    for m in mod_sizes:
        for x in (0, 1, 2, 65537, m - 1):
            b = RNG.randrange(0, 4 * m)
            mp_lines.append((be(b), be(x) if x else b"", be(m), be(pow(b, x, m), blen(m))))
    for mbytes in (8, 33, 64, 129, 256):
        for xbytes in (0, 1, 3, 128, 256):
            m = RNG.getrandbits(8 * mbytes) | 1 | (1 << (8 * mbytes - 1))
            b = RNG.getrandbits(8 * RNG.choice((1, mbytes, 256)))
            x = RNG.getrandbits(8 * xbytes) if xbytes else 0
            xb = x.to_bytes(xbytes, "big")
            mp_lines.append((be(b), xb, be(m), be(pow(b, x, m), mbytes)))
    # leading zeros on modulus / base, base == m, base multiple of m
    m = RNG.getrandbits(1024) | 1 | (1 << 1023)
    mp_lines.append((b"\x00\x00" + be(m - 5), be(12345), b"\x00" + be(m), be(pow(m - 5, 12345, m), 129)))
    mp_lines.append((be(m), be(7), be(m), be(0, 128)))
    mp_lines.append((be(3 * m), be(7), be(m), be(0, 128)))
    mp_lines.append((be(m + 2), b"\xff" * 128, be(m), be(pow(2, int("ff" * 128, 16), m), 128)))
    mp_out = [f"{{{arr(b)}, {arr(x)}, {arr(mm)}, {arr(r)}}}" for b, x, mm, r in mp_lines]

    # ---------------- sieve ----------------
    sieve_vals = [3, 5, 7, 17881, 17891, 17903, 1, 9, 15, 2**61 - 1, 2**127 - 1, 2**521 - 1]
    sieve_vals += [SIEVE_PRIMES[-1] * SIEVE_PRIMES[-2], 17891 * 17903, 3 * (2**127 - 1), 17881 * (2**127 - 1)]
    for _ in range(12):
        sieve_vals.append(rand_prime(RNG.choice((512, 1024))))
    for _ in range(24):
        c = RNG.getrandbits(1024) | 1
        sieve_vals.append(c)
    big = rand_prime(1024) * rand_prime(1024)
    sieve_vals.append(big)
    sieve_vals.append(big * 3 if (big * 3).bit_length() <= 2048 else big)
    sieve_vals.append(SIEVE_PRODUCT % (1 << 2048) | 1)
    sv_lines = [f"{{{arr(be(c))}, {sieve_ref(c)}}}" for c in sieve_vals]
    zz = bytes(2) + be(2**127 - 1)
    sv_lines.append(f"{{{arr(zz)}, 1}}")
    sv_lines.append(f"{{{arr(be(2**127))}, 0}}")
    sv_lines.append(f"{{{arr(bytes(1))}, 0}}")

    # ---------------- Miller-Rabin ----------------
    carmichael = [561, 1105, 1729, 2465, 2821, 6601, 8911, 41041, 825265, 321197185, 5394826801]
    spsp2 = [2047, 3277, 4033, 4681, 8321, 15841, 29341, 42799, 49141, 52633, 65281, 74665, 80581]
    psi = {
        3825123056546413051: [2, 3, 5, 7, 11, 13, 17, 19, 23],
        318665857834031151167461: [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37],
        3317044064679887385961981: [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41],
        3215031751: [2, 3, 5, 7],
    }
    for n_, bases in psi.items():
        assert not is_prime(n_)
        assert all(mr_round(n_, b) == 1 for b in bases), n_
    for n_ in spsp2:
        assert not is_prime(n_) and mr_round(n_, 2) == 1, n_
    for n_ in carmichael:
        assert not is_prime(n_)
    # Large Chernick Carmichael number (6k+1)(12k+1)(18k+1), ~ 900 bits
    while True:
        k_ = RNG.getrandbits(298)
        a1, a2, a3 = 6 * k_ + 1, 12 * k_ + 1, 18 * k_ + 1
        if is_prime(a1) and is_prime(a2) and is_prime(a3):
            chernick = a1 * a2 * a3
            break
    mr_cases = []
    for n_ in carmichael + spsp2 + [chernick]:
        for b in sorted({2, 3, 5, n_ - 2, RNG.randrange(2, n_ - 1), RNG.randrange(2, n_ - 1)}):
            if 1 < b < n_ - 1:
                mr_cases.append((n_, b))
    for n_, bases in psi.items():
        for b in [*bases, 43, 47, RNG.randrange(2, n_ - 1)]:
            mr_cases.append((n_, b))
    primes = [5, 7, 11, 13, 17881, 2**31 - 1, 2**61 - 1, 2**89 - 1, 2**127 - 1, 2**521 - 1]
    primes += [2**607 - 1, 2**1279 - 1]
    primes += [rand_prime(512), rand_prime(1024, mod4=3), rand_prime(1024, mod4=1), rand_prime(2048)]
    # primes with many trailing zeros in p - 1 (exercise the squaring loop)
    while True:
        c = (RNG.getrandbits(900) << 60) + 1
        if is_prime(c):
            primes.append(c)
            break
    for n_ in primes:
        for b in sorted({2, 3, n_ - 2, RNG.randrange(2, n_ - 1)}):
            if 1 < b < n_ - 1:
                mr_cases.append((n_, b))
    p1, p2 = rand_prime(512), rand_prime(1024)
    composites = [p1 * rand_prime(512), p2 * p2, p1 * p1 * p1, (2**61 - 1) * (2**89 - 1)]
    for n_ in composites:
        if n_.bit_length() <= 2048:
            for b in (2, 3, RNG.randrange(2, n_ - 1)):
                mr_cases.append((n_, b))
    mr_lines = [f"{{{arr(be(n_))}, {arr(be(b))}, {mr_round(n_, b)}}}" for n_, b in mr_cases]
    assert any(mr_round(n_, 2) == 1 for n_ in spsp2)

    # ---------------- complete() error cases ----------------
    ce = []
    pa, qa = rand_prime(512), rand_prime(512)
    ce.append((be(pa), be(pa), 65537, -2))  # p == q
    ce.append((be(pa + 1), be(qa), 65537, -1))  # even p
    ce.append((be(pa), be(qa), 65536, -1))  # even e
    ce.append((be(pa), be(qa), 1, -1))  # e = 1
    while True:  # p = 1 mod 3 -> gcd(3, p - 1) = 3
        pb_ = rand_prime(512)
        if pb_ % 3 == 1:
            break
    ce.append((be(pb_), be(qa), 3, -2))
    ce.append((be(rand_prime(200)), be(rand_prime(200)), 65537, -1))  # n < 512 bits
    ce.append((be(rand_prime(1032)), be(rand_prime(1016)), 65537, -1))  # p > 128 bytes
    ce.append((be(rand_prime(1024)), be(rand_prime(600)), 65537, -1))
    ce.append((b"", be(qa), 65537, -1))
    ce.append((b"\x00" * 4, be(qa), 65537, -1))
    ce.append((b"\x00\x00" + be(pa), be(qa), 65537, 0))  # leading zeros are fine
    ce_lines = [f"{{{arr(p_)}, {arr(q_)}, 0x{e_:x}u, {r_}}}" for p_, q_, e_, r_ in ce]

    # ---------------- output ----------------
    print("// SPDX-License-Identifier: GPL-3.0-only")
    print("// Copyright (C) 2026 The feuristic contributors")
    print("//")
    print("// GENERATED by tests/c/frsa/gen_vectors.py -- do not edit.")
    print(f"// Wycheproof: {wp['source']['repo']} @ {wp['source']['commit']}")
    print()
    print("#ifndef FRSA_VECTORS_H\n#define FRSA_VECTORS_H\n")
    print("#include <stddef.h>\n#include <stdint.h>\n")
    for line in out:
        print(line)
    print("typedef struct {\n  const uint8_t *c;\n  size_t clen;\n  int expected;\n} sv_case;\n")
    print(
        "typedef struct {\n  const uint8_t *w;\n  size_t wlen;\n  const uint8_t *b;\n  size_t blen;\n"
        "  int expected;\n} mr_case;\n"
    )
    print(
        "typedef struct {\n  const uint8_t *p;\n  size_t plen;\n  const uint8_t *q;\n  size_t qlen;\n"
        "  uint32_t e;\n  int expected;\n} ce_case;\n"
    )
    for a in _arrays:
        print(a)
    print()
    print("static const kat_key KAT_KEYS[] = {\n" + "\n".join(kat_lines) + "\n};")
    print("static const wp_key WP_DECRYPT[] = {\n" + "\n".join(wp_lines) + "\n};")
    print("static const wp_key WP_SIGN[] = {\n" + "\n".join(sign_lines) + "\n};")
    print("static const mp_case MP_CASES[] = {\n  " + ",\n  ".join(mp_out) + "\n};")
    print("static const sv_case SV_CASES[] = {\n  " + ",\n  ".join(sv_lines) + "\n};")
    print("static const mr_case MR_CASES[] = {\n  " + ",\n  ".join(mr_lines) + "\n};")
    print("static const ce_case CE_CASES[] = {\n  " + ",\n  ".join(ce_lines) + "\n};")
    print("\n#endif  // FRSA_VECTORS_H")
    sys.stderr.write(
        f"keys={len(kat_lines)} wp_dec={len(wp_lines)} wp_sig={len(sign_lines)} modpow={len(mp_out)} "
        f"sieve={len(sv_lines)} mr={len(mr_lines)} complete_err={len(ce_lines)}\n"
    )


if __name__ == "__main__":
    main()
