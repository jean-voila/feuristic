<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Import and restoration memory

This is a development budget and a reproducible software measurement procedure.
It does not qualify physical R02, R05, R13 or R14; their hardware procedures
remain [not executed](../acceptance/README.md) on T2B1 and T3B1.

## Separate reception from restoration

The MSC volume remains mounted throughout an import session. Copy every frame
of **one identity**, then confirm on the device. `pause_decode()` succeeds only
at an image/BOT boundary and wipes all decoder buffers. It releases the image
pages and payload while retaining the wiped bitmap and shared 12 KiB image/QR
reservation until close. Long-lived receipts cannot fragment those large holes. Public MSC reads still work; new WRITE(10) commands fail
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
stored state, credential store and largeBlob support. Local encrypted exports
disconnect USB, release pollers/applets and share a bounded stored FIDO context
and authenticated largeBlob snapshot. NORMAL returns on completion or cancellation. `session.release_import_stores()` drops loaded OTP,
OpenPGP, PIV and AES singleton caches between identities without clearing the
registry or the restoration key cache. USB transport suspension also drops
pollers and their references before allocating import buffers.

## Native allocations and linker budget

The T2B1 hardware linker result after patch
`0010-Keep-the-T2B1-interpreter-value-stack-in-non-DMA-CCM.patch` places the
4096-byte interpreter value stack, 20084-byte MSC/cache/reorder state and
6496-byte image-context reservation in CCM (99.86% of its 30 KiB budget). The value stack is explicitly zeroed before initialization and is never a
DMA buffer. The MicroPython heap is `0x2000621c..0x20030000`, **171492 bytes**.
These are build results, not runtime free-heap measurements.

The image and QR decoders share scratch memory: a 12288-byte image scratch
block is reused for the 12288-byte QR workspace after image decoding. There
is no additional simultaneous QR allocation.
T2B1 uses an internal bitmap side of **256** (8192 bytes); T3B1 uses 720.
The QR payload buffer is **1024 bytes**, matching the accepted `otpauth://`
URI and FB1 text limit. Session objects, README, Python objects and allocator
rounding must also fit. Both accept input PNG or baseline JPEG up to
1024×1024 and 256 KiB. Framing and input-file limits are unchanged.

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
  --output-side 256 --per-identity --compact \
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

The full 32768-byte DEFLATE history uses logical pages of 1024, 2048 or 4096 bytes.
Its first 12288 bytes share one allocation reused by QR after decoding.
Back-references, output draining and Adler-32 cross every page boundary.
PNG unfiltering retains one previous scanline in 128-byte pages and eight
previous channel bytes, preserving all supported filters and depths while
saving 8192 bytes. The small 256-pixel binarizer uses 512-byte complete-row
pages. The 256-pixel profile uses 1 KiB DEFLATE/JPEG pages; larger profiles
use 2/4 KiB pages. The full history remains 32768 bytes.
JPEG IDCT output is scattered into bounded band pages. The
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
session fits. The software RAM gate requires that the frozen 32-bit, off-heap MSC test
completes with the final source snapshot and all maximum provider fixtures.


## Probe validity under optimized freezing

`tools/memory_probe_source.py` turns probe assertions into explicit checks
before freezing, so `mpy-cross -O3` cannot remove either verification or an
operation inside a check (unlock, SCSI synchronization, collection, pause,
resume or CTAP writes). Host regressions execute the transformed source with
optimization levels 0, 1 and 2. Earlier frozen probe logs made before this
correction are **not complete behavioral evidence**. Allocation failures
observed before their first check still expose real allocation constraints.

The isolated preparation also invalidates generated feuristic `.i`/`.mpy`
cache files and uses fresh source mtimes. Restoring a snapshot must not reuse
bytecode from a later diagnostic variant. Only the isolated `build/emu32-arm`
Python cache is affected. Frozen drivers restrict `sys.path` to `.frozen` so
mounting the fixture filesystem cannot silently load application source.

Frozen import identifiers and printable ASCII characters are enumerated by
`tools/generate_frozen_qstr.py`. MicroPython interns absolute module paths and
single-character string indexing (including Base45 `$`). Keeping those QSTRs
in ROM avoids persistent runtime allocations and the upstream frozen-debug
assertion that otherwise interrupted import/export. The catalog function is
never executed; it contributes identifiers to the compiled frozen pool only.

NORMAL qualification now includes an independent cold process. The temporary
FIDO owner-recovery map uses fixed SHA-256 identifiers instead of retaining
all long user IDs/RP hashes. A digest hit is checked against the actual record
before duplicate recovery can delete anything; a collision fails closed.

## Collection policy and exclusive scratch reuse

Firmware boot configures automatic GC after 2048 allocated bytes per complete
128 KiB of usable heap (minimum 2048). This is 2048 on T2B1. The threshold
scales for large emulator heaps; otherwise scanning 20 MiB every 2 KiB makes
software tests needlessly slow. Waiting only for allocation failure leaves
small persistent objects scattered through decoder holes in the non-moving GC.
Both frozen memory drivers call the same firmware configuration function.

The backup controller and its complete 7680-byte replay ledger are created
before native image allocation. The ledger retains full SHA-256 values and
backup IDs without resizing during import. The generic host API can keep
incremental allocation. Limits and replay/conflict checks are unchanged.

The consumed ciphertext arena is also lent to authenticated decryption.
Ciphertext and tag are views of the untouched complete envelope. Native GCM
decrypts into the separate arena, authenticates before CBOR decoding, and
wipes speculative plaintext on failure. CBOR copies returned values before
the plaintext arena is wiped and reused for provider metadata/record writes.
The 64-entry FIDO merge retains encoded views and decodes only one entry at a
time, avoiding dozens of simultaneously retained maps. Hashing, canonical
encoding, duplicate handling, atomic writes and storage bounds are preserved.

The restore probe reuses one preallocated 512-byte simulated host sector and
feeds actual 65-byte USB frames. Host file reads must not allocate a fresh
512-byte sector on the MCU heap at every image. Its native warning layout,
layout tasks, controller/USB coroutine frames and USB input buffer remain
allocated during the complete maximum-provider/192-receipt test. This measures
retained idle UI memory; it does not emulate physical button timing or validate
OLED readability. Hardware R02/R13/R14/R15 remain unexecuted.
