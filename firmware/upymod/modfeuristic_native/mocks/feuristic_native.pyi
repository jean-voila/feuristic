# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
# Type stub for the firmware-only C module `feuristic_native`
# (firmware/upymod/modfeuristic_native/modfeuristic_native.c).
from typing import Union

AnyBytes = Union[bytes, bytearray, memoryview]

def rsa_complete(p: AnyBytes, q: AnyBytes, e: int) -> tuple[bytes, bytes, bytes, bytes]:
    """
    Compute (n, dp, dq, qinv) from the RSA primes p, q (big-endian, at
    most 128 bytes each) and the odd public exponent e (3 <= e < 2^32).
    n is minimally encoded; dp, dq and qinv are (len(n) + 1) // 2 bytes.
    Raises ValueError on invalid or inconsistent input.
    """

def rsa_private(
    p: AnyBytes,
    q: AnyBytes,
    dp: AnyBytes,
    dq: AnyBytes,
    qinv: AnyBytes,
    e: int,
    n: AnyBytes,
    block: AnyBytes,
) -> bytes | None:
    """
    Raw RSA private operation block^d mod n (CRT, constant time,
    randomly blinded). `block` must be len(n) bytes and < n; n must be
    minimally encoded. Before the result is released it is verified with
    the public key (result^e mod n == block) and n == p * q is checked;
    returns None if any check fails (fault detected, inconsistent key or
    invalid input). Takes ~0.37 s for RSA-2048 on a Cortex-M4 @ 168 MHz:
    the caller must send keep-alives / CCID time extensions beforehand.
    """

def rsa_public(n: AnyBytes, e: int, block: AnyBytes) -> bytes:
    """
    Raw RSA public operation block^e mod n. `n` must be odd, minimally
    encoded and 512..2048 bits; `block` must be len(n) bytes and < n.
    Raises ValueError otherwise.
    """

def modpow(base: AnyBytes, exp: AnyBytes, mod: AnyBytes) -> bytes:
    """
    base^exp mod mod for an odd modulus 3 <= mod < 2^2048 (all values
    big-endian, at most 256 bytes). The result has len(mod) bytes.
    Constant time in the values of base, exp and mod. One 1024-bit
    modpow with a 1024-bit exponent takes ~160 ms on a Cortex-M4.
    """

def rsa_sieve(candidate: AnyBytes) -> bool:
    """
    Constant-time trial division of an odd prime candidate (at most 256
    bytes) by the first 2048 odd primes (3 .. 17881). Returns False if one
    of them divides it (and for even candidates or candidates < 3).
    """

def rsa_mr_round(candidate: AnyBytes, base: AnyBytes) -> bool:
    """
    One Miller-Rabin round (FIPS 186-5 B.3.1) on the odd candidate w
    (5 <= w < 2^2048) with base b, 1 < b < w - 1. Returns True if w is a
    probable prime for this base. Raises ValueError on invalid input.
    """
