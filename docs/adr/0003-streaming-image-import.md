<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# ADR-0003: Streaming image import (decode while the file is written)

* Status: accepted (v0.x)
* Date: 2026-10-17
* Context: spec §3.3, §8.2, §10.4, R05, R06; architecture §4, §5
* Implementation: `lib/fmsc` (see `docs/developer/lib-fmsc.md`), `lib/fimg`,
  `lib/fqr`, `src/feuristic/apps/importer`

## Context

Spec §3.3 requires the following of the "Importer un QR / Restaurer" mode.
The device re-enumerates as a Mass Storage device with a FAT12 volume. It
accepts PNG and baseline JPEG images of up to **256 KiB** and 1024 × 1024
pixels. It processes them **in a stream, in bounded memory**, never as a
full-frame RGBA buffer. **Analysis starts after complete reception and
synchronisation of the writes.** Copy, analysis and the actual addition of
the secret are **three separate operations**, and the final write is atomic.
Both revisions must behave the same (principle 1, §11).

Hardware constraints:

* **T2B1** (STM32F427) has about 191 KiB of coreapp RAM. The MicroPython
  heap takes 120–150 KiB of it and must keep running the UI and the
  importer. A 256 KiB file cannot be held in RAM, and neither can a large
  fraction of it.
* T2B1 has only **about 64 KiB of scattered spare flash**. The firmware
  area cannot serve as a scratch spool: the bootloader hashes the image *and
  checks that the padding up to the end of the firmware area is still
  erased*. See upstream `core/embed/sec/image/image.c`,
  `check_image_contents()`: "Check the padding to the end of the area". A
  firmware that writes into its own padding no longer boots. The norcow
  storage (64 KiB of live data, holding the secrets) is not a scratch area
  either.
* **T3B1** (STM32U585) has about 728 KiB of coreapp RAM, enough to spool
  256 KiB.
* The USB host is hostile (threat model §10.9). Image data must be parsed
  unprivileged, in bounded memory, and nothing in it may be interpreted as a
  command (§3.3, §10.4).

The MSC protocol gives the device no notion of "file". It sees sector writes
to LBAs, in an order chosen by the host's filesystem driver. Windows, macOS
and Linux differ in metadata/data ordering, caching delay, flush behaviour
and the junk files they create.

## Decision

1. **Decode on receive.** `lib/fmsc` identifies image files in the sector
   write stream: a cluster starting with a PNG or JPEG signature starts a
   stream. It forwards their bytes in order to the streaming decoders
   (`lib/fimg`, PNG inflate / baseline JPEG). The decoders binarise into a
   **bounded 1-bpp bitmap**. No image byte is stored except a few reordered
   sectors in a small, caller-budgeted reorder buffer.
2. **Completion is decided from filesystem metadata.** A file counts as
   received when a live directory entry references the stream's first
   cluster, its size is at most 256 KiB, its FAT chain is contiguous, every
   byte up to that size was delivered, and the writes were **synchronised**:
   SYNCHRONIZE CACHE (the volume reports a write cache so hosts send it), a
   quiet period, or an eject.
3. **Interpretation happens strictly afterwards.** Until `stream_complete`
   fires, the application holds only an opaque bitmap. QR detection and
   decoding (`lib/fqr`), payload parsing (`otpauth://`, `feuristic-backup`
   frames), the on-screen preview and any storage change run only after
   completion and synchronisation. The decoder must also report a clean end
   (PNG `IEND` / JPEG `EOI`) within the reported size. The three steps of
   §3.3 stay separate:
   *copy* (MSC + streaming decode into the bitmap),
   *analysis* (QR + payload validation, after completion),
   *addition* (user confirmation, then an atomic write by `core.store`).
4. **Same behaviour on both revisions.** T3B1 uses the same streaming path
   even though it could spool the file.

## Consequences

Positive:

* The memory cost is constant and fits T2B1: about 12 KiB of fmsc context,
  plus a 16 KiB cluster cache and a 4–8 KiB reorder buffer, plus the
  decoders' bounded state and the bitmap. Nothing touches flash during an
  import, so there is no wear, no interaction with norcow and no risk to the
  boot checks.
* Hostile input stays in bounded parsers that are fuzzed (`fmsc_fuzz`,
  `fimg_*_fuzz`, `fqr` fuzzers). A malformed image can at worst fail its own
  stream.
* The volume never holds secrets and nothing persists after `fmsc_wipe`
  (§10.4, R15). Image bytes live only in the reorder buffer and the decoder
  state, and both are zeroized.
* Fragmented backups (§8.2) need no special case: each frame is one image
  and one stream. The volume stays mounted between files.

Negative and risks:

* **Non-sequential writes.** The host decides the write order, and the
  decoder needs bytes in order. *Mitigations:* a reorder buffer for small
  reorderings; recognition of identical rewrites, so a bus-reset retry does
  not break a stream; foreign-file markers (AppleDouble, `.DS_Store`, OLE,
  new directories) that end a stream cleanly; and a two-stream design, so
  that a second image arriving before the first image's metadata does not
  destroy the first. Larger reorderings fail the stream with an explicit
  error, and the user copies the file again.
* **Fragmented allocation** cannot be followed: the FAT is usually written
  after the data, so the device cannot know where a fragment continues.
  *Mitigation:* the volume is nearly empty and hosts allocate contiguously.
  A clear `FRAGMENTED` error suggests restarting the mode.
* **Completion detection relies on heuristics** about host behaviour:
  metadata/data ordering, stale entries during overwrites, writeback delays.
  *Mitigations:* positive completion requires every structural condition
  plus a synchronisation event. Negative verdicts wait for a sync, a settle
  period or the eject. The decoder's own end-of-image check is a second
  guard. A host-OS write-pattern simulator in the test suite reproduces
  Windows, macOS and Linux sequences. Acceptance test R05 on Finder,
  Explorer and Linux remains mandatory.
* **Reads return zeros** for image clusters, so the host cannot read back
  what it wrote once its page cache drops it. This is acceptable for a
  write-only, ephemeral import volume; the README text (supplied by the
  application) should say so.
* **One decoder at a time.** The consumer may refuse a second simultaneous
  stream (`BUSY`). The user is asked to copy images one at a time, which
  spec §8.2 already prescribes ("les déposer un par un").

## Rejected alternatives

* **RAM spool (store the file, then decode).** Simple and robust against
  write ordering, but impossible on T2B1 (no 256 KiB of RAM). Using it on
  T3B1 only would make the two revisions behave differently: different
  failure modes, different test matrix. That contradicts principle 1 and
  §11 ("mêmes fonctions"). Rejected.
* **Free-flash spool.** T2B1 has only about 64 KiB of usable spare flash,
  scattered over sectors. The firmware area's padding must stay erased for
  the bootloader's `check_image_contents()`, and norcow sectors hold the
  secrets. Writing there would risk bricking the device or corrupting
  storage, and would add flash wear for every import. Rejected.
* **Media-change tricks** (report the medium as changed or ejected after
  each file, or re-enumerate between files, so the host flushes and
  rewrites in a predictable way). Host behaviour after a forced media change
  varies between OSes; Windows may show "repair this drive?" dialogs. The
  spec also forbids the interface from disappearing before the user ejects
  it. Rejected.
* **Read-back verification** (ask the host to re-read the file). MSC is
  device-passive: the device cannot ask the host to do anything. Rejected.
* **A custom protocol or companion tool** (WebUSB, vendor class). Forbidden
  by spec principle 4 ("aucun compagnon dédié"). Rejected.
