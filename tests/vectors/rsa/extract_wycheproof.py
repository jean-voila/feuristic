# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Trim Wycheproof RSA PKCS#1 v1.5 vectors into tests/vectors/rsa/wycheproof_rsa.json.

Usage (inputs downloaded with curl from github.com/C2SP/wycheproof at COMMIT)::

    uv run python tests/vectors/rsa/extract_wycheproof.py <dir-with-json> > \
        tests/vectors/rsa/wycheproof_rsa.json

Only the fields feuristic needs are kept: CRT key components (p, q, dp, dq,
qinv recovered from n/e/d for the signature-generation files), messages,
ciphertexts/signatures, results and flags. The source files' SHA-256 digests
are recorded so the extraction is reproducible.
"""

import hashlib
import json
import os
import sys

from cryptography.hazmat.primitives.asymmetric import rsa

COMMIT = "7a325932231bd7a724c791c8b0d65ea4d6d2f435"
DECRYPT = "rsa_pkcs1_2048_test.json"
SIGN = ("rsa_pkcs1_1024_sig_gen_test.json", "rsa_pkcs1_2048_sig_gen_test.json")
HASHES = ("SHA-256", "SHA-384", "SHA-512")


def _int(h: str) -> int:
    return int(h, 16) if h else 0


def _key(n: int, e: int, d: int, p: int = 0, q: int = 0) -> dict:
    if not p:
        p, q = rsa.rsa_recover_prime_factors(n, e, d)
    assert p * q == n
    size = (n.bit_length() + 7) // 8
    half = (size + 1) // 2
    dp = pow(e, -1, p - 1)
    dq = pow(e, -1, q - 1)
    qinv = pow(q, -1, p)
    return {
        "n": n.to_bytes(size, "big").hex(),
        "e": e,
        "p": p.to_bytes(half, "big").hex(),
        "q": q.to_bytes(half, "big").hex(),
        "dp": dp.to_bytes(half, "big").hex(),
        "dq": dq.to_bytes(half, "big").hex(),
        "qinv": qinv.to_bytes(half, "big").hex(),
    }


def main() -> None:
    src = sys.argv[1]
    out = {
        "source": {
            "repo": "https://github.com/C2SP/wycheproof",
            "commit": COMMIT,
            "path": "testvectors_v1",
            "files": {},
        },
        "decrypt": [],
        "sign": [],
        "skipped": [],
    }
    files = (DECRYPT, *SIGN)
    for name in files:
        with open(os.path.join(src, name), "rb") as f:
            out["source"]["files"][name] = hashlib.sha256(f.read()).hexdigest()

    with open(os.path.join(src, DECRYPT)) as f:
        data = json.load(f)
    for g in data["testGroups"]:
        k = g["privateKey"]
        key = _key(
            _int(k["modulus"]),
            _int(k["publicExponent"]),
            _int(k["privateExponent"]),
            _int(k["prime1"]),
            _int(k["prime2"]),
        )
        assert _int(key["dp"]) == _int(k["exponent1"])
        assert _int(key["dq"]) == _int(k["exponent2"])
        assert _int(key["qinv"]) == _int(k["coefficient"])
        tests = [
            {
                "tcId": t["tcId"],
                "comment": t["comment"],
                "flags": t["flags"],
                "msg": t["msg"],
                "ct": t["ct"],
                "result": t["result"],
            }
            for t in g["tests"]
        ]
        out["decrypt"].append({"key": key, "tests": tests})

    for name in SIGN:
        with open(os.path.join(src, name)) as f:
            data = json.load(f)
        for g in data["testGroups"]:
            if g["sha"] not in HASHES:
                continue
            k = g["privateKey"]
            n, e = _int(k["modulus"]), _int(k["publicExponent"])
            p, q = rsa.rsa_recover_prime_factors(n, e, _int(k["privateExponent"]))
            half_bits = 8 * (((n.bit_length() + 7) // 8 + 1) // 2)
            if max(p.bit_length(), q.bit_length()) > half_bits:
                # unbalanced factors (Wycheproof e=3 keys): unsupported by frsa
                out["skipped"].append({"file": name, "sha": g["sha"], "reason": "unbalanced factors"})
                continue
            key = _key(n, e, 0, max(p, q), min(p, q))
            tests = [
                {"tcId": t["tcId"], "msg": t["msg"], "sig": t["sig"], "result": t["result"]}
                for t in g["tests"]
            ]
            out["sign"].append({"file": name, "sha": g["sha"], "key": key, "tests": tests})

    json.dump(out, sys.stdout, separators=(",", ":"), sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
