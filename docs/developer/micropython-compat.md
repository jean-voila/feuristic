# Writing code that runs on CPython *and* the device MicroPython

Everything under `src/feuristic/core` and `src/feuristic/apps` (except the
explicitly firmware-only `*/fw_*.py` glue modules and `src/feuristic/ui`) is
**shared code**: it is unit-tested on CPython (`tests/host`) and frozen into
the firmware, where it runs on Trezor's MicroPython 1.28 fork with a reduced
feature set. Shared code must follow these rules. `tools/check_upy_compat.py`
enforces the mechanical ones in CI.

## Allowed

* `async def` / `await` (await only coroutines; never `asyncio`).
* f-strings, `str.format`, generators, list/dict comprehensions, closures.
* `int.from_bytes(b, "big")`, `int.to_bytes(n, length, "big")` — positional
  byte order, **no** `signed=` keyword.
* `bytes.hex()`, `bytes.fromhex()`, `bytearray`, `memoryview`, slicing.
* `isinstance`, simple class hierarchies, `@property`, `super()`.
* `from micropython import const` (a CPython shim exists in `tests/host/shims`).
* Typing **only** under `if TYPE_CHECKING:` (from `typing import TYPE_CHECKING`
  is shimmed on the device) and in string annotations.

## Forbidden (not compiled into the firmware)

`struct`, `collections`, `math`, `re`, `json`, `binascii`, `hashlib`, `os`,
`io`, `time` (use `feuristic.platform.time`), `random` (use
`feuristic.platform.crypto.random_bytes`), `dataclasses`, `enum`, `abc`,
`functools`, `itertools`, `typing` at runtime, `frozenset`, `str.center`,
`str.splitlines`, three-argument `pow()`, complex numbers, `__slots__`
semantics, `int.bit_length()` (not enabled on the device), `print()` in production paths (use `feuristic.platform.log`).

## Resource discipline

* Bound every input before allocating (`len(data) > MAX` → error first).
* Prefer pre-allocated `bytearray` buffers in hot paths (CTAPHID, CCID).
* No unbounded recursion in parsers (CBOR/TLV have explicit depth limits).
* Secrets: keep them in `bytearray` when they must be wiped, and call
  `feuristic.core.secure.wipe(buf)` when done.
* Exceptions: raise the typed errors from `feuristic.core.errors`; never leak
  secret material in exception messages.

## Platform facade

Shared code reaches the outside world **only** through `feuristic.platform`:

| Module | Purpose |
|---|---|
| `feuristic.platform.crypto` | hashes, HMAC, PBKDF2, HKDF, AES-GCM/CBC, P-256, Ed25519, X25519, RSA, RNG |
| `feuristic.platform.kv` | key/value persistent storage (norcow on device, dict on host) |
| `feuristic.platform.time` | monotonic `ticks_ms()` |
| `feuristic.platform.log` | debug logging (no-op in release builds) |

Backends are selected at import time: if `trezor` is importable the firmware
backend is used, otherwise the host backend. Host tests may inject a
deterministic RNG and a fake clock (`feuristic.platform.testing`).
