# Security policy

feuristic is security-critical software. Thank you for helping keep its
users safe.

## Reporting a vulnerability

**Do not open a public issue or discussion with vulnerability details.**
When this repository becomes public, maintainers will enable GitHub's
*Security → Report a vulnerability* for private reports. While the repository
remains private, collaborators can use a restricted repository issue.
Do not assume that an external contact address or reporting form is active.
A report should include:

* affected version / commit and model (T2B1, T3B1, emulator);
* a description of the issue and its impact;
* steps or a proof of concept to reproduce it.

We acknowledge reports within 7 days, agree on a disclosure date (90 days
by default, shorter for actively exploited issues) and credit reporters
who wish to be credited. Fixes are released as new firmware versions and
listed in [docs/security-history.md](docs/security-history.md).

Vulnerabilities in upstream components (the Trezor firmware stack,
MicroPython, BearSSL, …) should also be reported to their maintainers; we
will coordinate when they affect feuristic.

## Scope

In scope: everything in this repository (firmware, patches, libraries,
host tools, the backup format and protocol annexes).

Out of scope: the official Trezor bootloader and its "unsafe vendor"
warning, which feuristic cannot change; attacks requiring the user to
approve an operation on the device screen; issues only reproducible on
the emulator's development-only features (debuglink).

## Supported versions

Until 1.0, only the latest release receives security fixes.

## Security model

See [docs/threat-model.md](docs/threat-model.md).
