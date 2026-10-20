<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Import and restoration memory

This is a development budget and a reproducible software measurement procedure.
It does not qualify physical R02, R05, R13 or R14; their hardware procedures
remain [not executed](../acceptance/README.md) on T2B1 and T3B1.

## Separate reception from restoration

The MSC volume remains mounted throughout an import session. Copy every frame
of **one identity**, then confirm on the device. `pause_decode()` succeeds only
at an image/BOT boundary and releases the image workspace, monochrome bitmap
and QR output buffer. Public MSC reads still work; new WRITE(10) commands fail
with NOT READY, ASC/ASCQ `04/07` and their entire transfer residue. The host must
retry those refused copies after the next invitation. Nothing acknowledged as
a successful copy is silently discarded to save memory.

Only then does `ImportSession.take_complete()` assemble and remove that
identity's ciphertext. `StreamingRestore.restore_envelope()` authenticates the
complete envelope and validates **every item in it before any write**. Each
identity is stored atomically by its provider; earlier approved identities stay
restored if a subsequent identity is absent, damaged, refused or fails to save.
The decoder resumes after ciphertext, plaintext and application caches are
released. The user chooses Done explicitly; receiving one identity never proves
that a complete export was received.

`DEVICE_MAX_BYTES = 12 * 1024` and `DEVICE_MAX_BACKUPS = 1` in
`src/feuristic/apps/importer/session.py` bound the hardware reception phase.
They do not change v1's generic 64 KiB envelope or sixteen-item decoder contract.
Native exports contain one item per envelope. Larger, externally constructed
v1 envelopes are outside the hardware reception budget and are rejected
explicitly. The generic host decoder remains available for their inspection.

`PackedReassembler` uses one ciphertext arena and four bytes per frame
(two unsigned 16-bit values: offset and length). An absent frame has zero
length. First-frame allocation covers the balanced fragments produced by the
native exporter, including reverse order. An unbalanced third-party sequence
can grow the bounded arena; order, exact duplicate suppression and conflict
checks remain mandatory. Assembly runs while the large decoder buffers are
absent, avoiding the old coexistence of image scratch, individual fragment
objects and a second complete ciphertext copy.

Between identities, the restoration session retains at most four derived
keys, public full-set sequence bitmaps and a replay ledger of forty bytes per
accepted envelope (eight-byte ID and SHA-256 of the authenticated envelope).
The generic API defaults to 1024 envelopes/sets; the device passes shared
`DEVICE_MAX_ENVELOPES = 192` and `DEVICE_MAX_SETS = 4` bounds, covering its
153 native identities even before shared flash capacity is considered. A fifth
export salt or a 193rd distinct envelope is refused before further mutation;
finish and reopen import to continue. Exact replays remain harmless at the
limit. The device ledger is thus bounded to 7680 bytes. Reusing
an ID with different content or a sequence number with another ID is an error.
The report counts all restored/skipped identities, while retaining only the
four latest examples of each internally. The device currently displays the
number restored; complete restored identities are inspected in their menus.
`close()` wipes cached derived keys.

The five provider registry entries are lazy proxies. Import does not retain
NORMAL-mode CTAP/HID authenticators. FIDO restoration constructs only its
stored state, credential store and largeBlob support; NORMAL exports use the
live authenticator. `session.release_import_stores()` drops loaded OTP,
OpenPGP, PIV and AES singleton caches between identities without clearing the
registry or the restoration key cache. USB transport suspension also drops
pollers and their references before allocating import buffers.

## Native allocations and linker budget

The T2B1 hardware linker result after patch
`0010-Keep-the-T2B1-interpreter-value-stack-in-non-DMA-CCM.patch` places the
4096-byte interpreter value stack and 20084-byte MSC/cache/reorder state in
CCM. The value stack is explicitly zeroed before initialization and is never a
DMA buffer. The MicroPython heap is `0x2000621c..0x20030000`, **171492 bytes**.
These are build results, not runtime free-heap measurements.

The image and QR decoders share scratch memory: a 16384-byte image scratch
block is reused for the 12288-byte QR workspace after image decoding. There
is no additional simultaneous QR allocation.
ARM ABI sizes from the real C implementations are:

| T2B1 internal bitmap side | Image workspace | Bitmap | QR payload | Total scratch/bitmap/payload |
|---|---:|---:|---:|---:|
| 512 | 77392 | 32768 | 3072 | 113232 |
| 384 | 69072 | 18432 | 3072 | 90576 |

The native session object, README, Python objects and allocator rounding must
be added. T2B1 uses side **384**, saving 22656 bytes of these buffers; T3B1 uses
720. Both still accept input PNG or baseline JPEG up to 1024×1024 and 256 KiB.
This is an internal memory adjustment, with no change to QR framing or input
file limits.

## Reproduce decoder comparisons

From the repository root, with development dependencies installed:

```sh
uv run python tools/probe_image_import.py --output build/image-import-probe.json
```

The tool compiles the real portable `fimg` and `fqr` C sources and feeds images
in 64-byte chunks. It checks exact payload equality at sides 512, 384 and 320.
The committed corpus and deterministic synthetic v3/v5/v9 PNG/JPEG variants
cover dimensions 256, 512, 768 and 1024, 15-degree rotation, blur, shadow and
seeded noise. The measured result is **103/103 eligible files decoded exactly
at each side, zero regressions from 512**, with six oversized noisy PNGs
rejected at all sides. JSON includes file sizes, eligibility and individual
results. Synthetic degradation is software evidence; physical OLED/camera
interoperability remains R13/R14.

## Reproduce allocation phases

Build a frozen T2B1 emulator using the [build instructions](building.md).
Copy it to a separate path before rebuilding a debug emulator used by other
tests. Then run, substituting that binary's actual path:

```sh
uv run python tools/probe_import_memory.py \
  --emulator /tmp/feuristic-T2B1-frozen-memory-final \
  --output-side 384 --per-identity --compact \
  --envelope-bytes 5127 --identities 192
uv run pytest tests/host/backup/test_native_export_bounds.py \
  tests/host/backup/test_streaming_restore.py tests/host/backup/test_frames.py
```

The probe labels bootstrap, live decoder, collected ciphertext, decoder-paused
consumption and close. Its payloads are deliberately unauthenticated synthetic
ciphertext; this measures collection and native allocation lifetimes, **not**
KDF, provider mutation or the complete controller. The `-c` script's own
bytecode/globals are included in the heap, unlike frozen production modules.
Do not divide a 64-bit heap result by two to claim a physical fit.

A frozen macOS arm64 measurement with the final packed arena, exact production
README and lazy registry used about 147008 bytes after bootstrap, 259840 with the
384 decoder, 267456 after collecting a 5127-byte identity, and 175328 after
pause/consumption; 192 successive cycles completed with stable allocations.
Those numbers include a 64-bit emulator object ABI and its heap-allocated MSC
state, and therefore cannot establish T2B1 runtime headroom. The exact README
and full restore/provider pipeline must be included in the 32-bit test before
using such a result to remove the candidate memory gate.

The largest native export tests use real provider records, RSA keys, maximum
metadata/certificates and authenticated largeBlob entries. Their complete
v1 envelopes, including full-export sequence/count overhead, measure:

| Identity | Envelope bytes |
|---|---:|
| OpenPGP, three RSA keys and maximum auxiliary fields/PIN references | 5127 |
| FIDO2, 64 associated largeBlob entries | 4847 |
| FIDO2, one maximum associated largeBlob entry | 4721 |
| PIV RSA and 2048-byte certificate | 2500 |
| HOTP, maximum metadata/secret/counter | 379 |
| AES, maximum metadata and counter | 241 |

Every case reconstructs through the device's 12 KiB packed collector in both
large-module and dense profiles, then authenticates and decodes unchanged.
The largest native single identity uses 234 large-module fragments or 33 dense
fragments. A 12 KiB receiver ceiling alone is insufficient proof: simultaneous
objects, contiguous allocations, retained receipts and decoder reallocation
must also pass the runtime probe. No physical runtime RAM measurement is yet
recorded here.

## FAT directory space is separate from envelope RAM

The FAT12 root has 64 directory entries, including precreated files. A maximal
5127-byte OpenPGP backup has 234 large-module frames, so its images must be
copied in batches or with short names while keeping the same import session.
The native regression `test_large_identity_survives_234_images_in_batches_on_64_entry_volume`
uses eight batches of at most 32 short `QR000000.PNG` names, waits for their
received-frame count, deletes only those copied files (E5 directory entries,
freed FAT chains and synchronization), then continues. It authenticates the
reconstructed envelope and reads back the restored 2048-byte certificate and
RSA modulus over CCID. This passes on both T2B1 and T3B1 emulators (21.51 s and 22.36 s). Physical host OS
copy/delete behavior remains R02/R14; an emulator is not a Windows/macOS test.

## Fragmented heaps and the scattered C API

A real i686 frozen emulator exposed a second constraint beyond total free
bytes: after loading and suspending NORMAL, tens of kilobytes could be free
while the largest hole was approximately 16–21 KiB. The old single 69 KiB
workspace allocation therefore failed. `fimg_scattered_sizes()` now describes
the complete scratch plan and `fimg_init_scattered()` accepts caller-owned,
eight-byte-aligned, disjoint blocks of at most 16384 bytes. The native Session
preallocates them before accepting writes, records every successful allocation
for immediate cleanup on failure, and wipes/frees them on pause and close.

The full 32768-byte DEFLATE history is preserved as two 16384-byte pages;
back-references, output draining and Adler-32 span both page boundaries. The
adaptive binarizer ring is split only at complete row boundaries. Neither PNG
bit depth, input dimensions, JPEG support nor file limits are reduced. The
original contiguous `fimg_init()` API remains available.

Validation includes all 286 corpus vectors with five input chunkings and
exact contiguous/scattered status, luma, information and bitmap parity; the
raw inflater is also compared with contiguous/two-page history. ASan/UBSan
checks cover buffer canaries, invalid/overlapping/short memory, reinitialization
and 14336 input/output geometry combinations. All three C suites pass. Three
additional 46-second sanitizer fuzz runs completed 129339 PNG, 19047 inflater
and 132028 JPEG cases without findings, with zlib/libjpeg differential checks.
Both Cortex-M4 and Cortex-M33 portable-library builds pass `-Werror`.

The scattered API removes the single-large-workspace requirement. It alone
does **not** prove that every native allocation and the complete restoration
session fits: the measured 384 bitmap and subsequent scratch allocations
still encounter allocation pressure in the current runtime probe. The
software RAM gate remains open until the frozen 32-bit, off-heap MSC test
completes with the final source snapshot and all maximum provider fixtures.
