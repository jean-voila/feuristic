---
title: USB mass storage for QR import (lib/fmsc)
description: lib/fmsc implements the temporary USB mass-storage mode and FAT12 volume that receives PNG and JPEG QR images on Trezor Safe 3.
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# `lib/fmsc`: USB Mass Storage for the import mode

`lib/fmsc` holds all the Mass Storage logic of the temporary mode
"Importer un QR / Restaurer" (spec §3.3, §8.2, R05, R06; architecture §4, §5).
The device re-enumerates as an MSC-only device and shows a small FAT12 volume.
The user copies PNG/JPEG images onto it. The library:

1. runs the **Bulk-Only Transport** (BOT 1.0) at packet level,
2. answers the **SCSI** commands that Windows, macOS and Linux send,
3. generates a **virtual FAT12 volume** that has no backing storage,
4. **tracks image writes**. It forwards each image's bytes in order to a
   consumer (the streaming decoder `lib/fimg`) while they are written. It
   reports when a file is completely written *and* synchronised,
5. handles **eject**, and **wipes** its state on request.

Why it streams instead of storing the file: see
[ADR-0003](../adr/0003-streaming-image-import.md).

It is freestanding C99 with no allocation and no recursion. It builds cleanly
with `-Wall -Wextra -Werror -pedantic -Wconversion -Wsign-conversion` on host
clang and on `arm-none-eabi-gcc` 14/15 (Cortex-M4). The code is about
8.9 KB of Thumb-2 at `-Os`. The deepest stack frame is 248 bytes.

```
lib/fmsc/include/fmsc.h      public API, context struct, geometry constants
lib/fmsc/src/fmsc_bot.c      BOT state machine + public entry points
lib/fmsc/src/fmsc_scsi.c     SCSI command set
lib/fmsc/src/fmsc_volume.c   boot sector / FAT / root dir / generated files / cache
lib/fmsc/src/fmsc_tracker.c  import stream tracker
tests/c/fmsc/                unit tests, fake USB host, FAT reader, host-OS simulator
tests/fuzz/fmsc_fuzz.c       libFuzzer target (README-fmsc.md)
```

## 1. Integration (glue contract)

The kernel MSC class only shuttles raw 64-byte bulk packets (architecture
§5.3). The unprivileged glue (`firmware/upymod`, `feuristic_import`) wires
them as follows:

| USB side | call |
|---|---|
| OUT packet received (0..64 bytes) | `fmsc_on_out_packet(ctx, pkt, len)` |
| the IN packet queued by `cb.send_in` was consumed | `fmsc_on_in_ready(ctx)` |
| `CLEAR_FEATURE(ENDPOINT_HALT)` on bulk IN/OUT | `fmsc_on_clear_halt(ctx, ep)` |
| class request *Bulk-Only Mass Storage Reset* (0xFF), or USB bus reset | `fmsc_bot_reset(ctx)` |
| class request *Get Max LUN* (0xFE) | reply `fmsc_get_max_lun()` (= 0) |
| main loop, at least every 100 ms | `fmsc_poll(ctx, now_ms)` |

Callbacks from the library:

* `send_in(data, len)`: queue one IN packet (1..64 bytes, copied). The
  library never calls it again before `fmsc_on_in_ready`. The glue may
  call `fmsc_on_in_ready` from inside `send_in`; the call is deferred safely.
* `stall(ep)`: halt the bulk endpoint until the host clears it. The
  library stalls IN only when no IN packet is pending.
* `stream_start(id) -> bool`, `stream_data(id, offset, data, len)`,
  `stream_complete(id, name, size)`, `stream_error(id, reason)`: see §5.
* `event(ev)`: `FMSC_EVT_EJECTED`, `FMSC_EVT_STOPPED`, `FMSC_EVT_HOST_RESET`.

Callbacks run synchronously and must be short. A callback must not call back
into the library. The one exception is `fmsc_on_in_ready` from `send_in`.
Other re-entrant calls are ignored and counted in
`fmsc_stats_t.reentrant_calls`. That includes `fmsc_wipe`, so state is never
freed under a running call. QR decoding must **not** run inside
`stream_complete`; the callback only records the result. The host is waiting
for a CSW, and hosts time out after 10–30 s.

Session life cycle (application, `apps/importer`):

```
fmsc_init → usb_set_mode(IMPORT) → … import, preview, confirmation …
→ UI asks the user to eject → FMSC_EVT_EJECTED (or STOPPED, policy)
→ usb_set_mode(NORMAL) → fmsc_wipe
```

A cable pull or a cancel from the menu goes straight to `fmsc_wipe`
(spec §3.3: "le stockage temporaire est purgé").

## 2. BOT state machine

```
            valid & meaningful CBW
   ┌──────┐ ─────────────────────▶ reconcile (13 cases, §2.1)
   │ IDLE │ ◀──────────────┐         │          │             │
   └──────┘   CSW consumed │   DATA_OUT      DATA_IN       stall IN ──▶ WAIT_CLEAR_IN
      │                    │   (Do bytes)   (Di bytes)        ▲               │ clear halt IN
      │ CBW not valid      │      │             │ Hi>Di       │               ▼
      ▼                    └──── CSW ◀──────────┴─────────────┘ ◀──────────── CSW
  NEED_RESET (IN+OUT halted, re-halted on every clear-halt, packets dropped)
      │ fmsc_bot_reset()
      ▼
    IDLE
```

* **CBW not valid** (length ≠ 31 or signature ≠ `0x43425355`, or a packet
  over 64 bytes): both pipes are halted and stay halted until a Reset
  Recovery (§6.6.1). A clear-halt without a reset re-halts the pipe.
* **CBW valid but not meaningful** (reserved `bmCBWFlags` bits, LUN ≠ 0,
  reserved LUN bits, `bCBWCBLength` outside 1..16): the device sends a phase
  error CSW. It first halts the pipe of the host's announced data direction,
  if any. The host then performs a Reset Recovery.
* OUT packets received while the device sends data, waits for a clear-halt
  or sends the CSW are dropped (`discarded_packets`). A conforming host sends
  none, and dropping them keeps a packet that slipped past an OUT stall from
  being taken for a CBW.
* A short OUT packet before the announced data end ends the transfer. The
  device answers with a phase error CSW and drops the partial sector.
* `fmsc_bot_reset` aborts the current command and returns to IDLE. Any
  pending eject/stop event is still delivered. The tracker keeps its
  streams: hosts retry the interrupted WRITE, and identical rewrites are
  recognised (§5.3).

### 2.1 The thirteen cases (BOT §6.7)

The SCSI layer describes its intent: direction, length `D` and status. The
BOT layer reconciles it with the host's `dCBWDataTransferLength` `H` and
direction:

| case | situation | device action | CSW status / residue |
|---|---|---|---|
| 1 | Hn = Dn | nothing | command status / 0 |
| 2, 3 | Hn < Di, Hn < Do | nothing (command not executed) | 2 / 0 |
| 4 | Hi > Dn | stall IN | command status / H |
| 5 | Hi > Di | send D bytes, then stall IN | command status / H − D |
| 6 | Hi = Di | send D bytes | command status / 0 |
| 7 | Hi < Di | stall IN, nothing sent | 2 / H |
| 8 | Hi ≠ Do | stall IN | 2 / H |
| 9 | Ho > Dn | stall OUT | command status / H |
| 10 | Ho ≠ Di | stall OUT | 2 / H |
| 11 | Ho > Do | receive D bytes, then stall OUT | command status / H − D |
| 12 | Ho = Do | receive D bytes | command status / 0 |
| 13 | Ho < Do | stall OUT, nothing written | 2 / H |

After an IN stall the CSW is queued once the host clears the halt. After an
OUT stall the CSW is queued at once on IN. A SCSI command that fails (CHECK
CONDITION) has no data phase, so it falls into case 1, 4 or 9 with status 1.

## 3. SCSI

| opcode | command | notes |
|---|---|---|
| 00 | TEST UNIT READY | NOT READY when ejected or stopped |
| 03 | REQUEST SENSE | fixed format, 18 bytes; reports and clears the current sense; with no stored sense it reports a pending UA, then MEDIUM NOT PRESENT / INITIALIZING COMMAND REQUIRED; `DESC=1` → INVALID FIELD |
| 12 | INQUIRY | standard 36 bytes: removable, SPC-2, vendor `FEURISTC`, product `FEURISTIC-IMPORT`, revision from the config; EVPD pages 0x00 and 0x80 (serial from the config) |
| 1A / 5A | MODE SENSE(6)/(10) | no block descriptor, WP = 0; page 0x08 (caching, **WCE = 1**) for page 0x08 or 0x3F; PC = changeable → all-zero mask; PC = saved → SAVING PARAMETERS NOT SUPPORTED; other pages → INVALID FIELD |
| 1B | START STOP UNIT | see below |
| 1E | PREVENT ALLOW MEDIUM REMOVAL | recorded; blocks LoEj |
| 23 | READ FORMAT CAPACITIES | one "formatted media" descriptor |
| 25 | READ CAPACITY(10) | last LBA 32668, 512-byte blocks |
| 28 / 2A | READ(10) / WRITE(10) | range checked; RD/WRPROTECT ≠ 0 → INVALID FIELD |
| 2F | VERIFY(10) | BYTCHK = 0 only (data is not kept) |
| 35 | SYNCHRONIZE CACHE(10) | completion trigger (§5.4) |
| other | | ILLEGAL REQUEST / INVALID COMMAND OPERATION CODE (05/20/00) |

Common rules: a CB length shorter than the opcode's CDB, or NACA set in the
control byte, gives INVALID FIELD IN CDB (05/24/00). The first command other
than INQUIRY and REQUEST SENSE after `fmsc_init` returns UNIT ATTENTION /
POWER ON, RESET (06/29/00). Each command except REQUEST SENSE clears the
previous sense data.

WCE = 1 is deliberate. With it, hosts send SYNCHRONIZE CACHE when they flush
(sync, fsync, unmount, eject), which is the explicit "synchronised" signal of
spec §3.3. The device keeps no write cache, so the flag costs nothing.

**START STOP UNIT** (power condition ≠ 0 is accepted with no effect):

| LoEj | Start | effect |
|---|---|---|
| 1 | 0 | **eject**: refused with 05/53/02 while PREVENT is set. Otherwise the final stream verdict (§5.4) runs, the medium becomes absent for the rest of the session, and `FMSC_EVT_EJECTED` is emitted *after the CSW has been consumed*, so the glue can tear the interface down. A repeated eject is a no-op. |
| 0 | 0 | **stop**: NOT READY (02/04/02) until a START; `FMSC_EVT_STOPPED`. udisks "power off" sends this. Whether it counts as "arrêt propre" is up to the application. |
| x | 1 | start/load: back to ready after a stop. After an eject: 02/3A/00. |

After an eject, TEST UNIT READY, READ, WRITE, READ CAPACITY, READ FORMAT
CAPACITIES, VERIFY and SYNCHRONIZE CACHE return NOT READY / MEDIUM NOT
PRESENT (02/3A/00). INQUIRY and MODE SENSE still answer.

## 4. Volume layout

512-byte sectors, 4 KiB clusters. 4080 clusters: below Microsoft's FAT12
limit (< 4085), and also below BSD/macOS `fsck_msdos`'s, which counts
`clusters + 2 < 4086`. With 4084 clusters `fsck_msdos` would classify the
volume as FAT16.

| LBA | content | source |
|---|---|---|
| 0 | boot sector / BPB, `55 AA` | generated (host writes ignored) |
| 1–12 | FAT1 (12 sectors) | single RAM copy (6 KiB) |
| 13–24 | FAT2 | the same RAM copy |
| 25–28 | root directory, 64 entries | RAM (2 KiB) |
| 29–32668 | data, clusters 2..4081 | see below |

BPB: OEM `MSDOS5.0`, 1 reserved sector, 2 FATs, media `F8`, 32669 sectors,
volume serial from the config, label `FEURISTIC  `, type `FAT12   `.

**Label deviation.** A FAT volume label has 11 characters, and the spec name
`FEURISTIC-IMPORT` has 16. The label is `FEURISTIC` (space padded). The full
name appears where it fits: the SCSI INQUIRY product string, so it shows up
in device managers and `lsblk -o MODEL`. The README text should use it as
well.

Pre-created content:

| entry | details |
|---|---|
| volume label | `FEURISTIC  `, attr 0x08 |
| `README.TXT` | read-only; caller-provided text (≤ 4096 bytes), cluster 3 |
| `.metadata_never_index` | empty, hidden, LFN; stops Spotlight indexing |
| `.Trashes` | empty *file*, hidden, LFN; stops Finder from creating a trash folder |
| `.fseventsd/` | hidden directory (cluster 2) holding `no_log` (empty; 8.3 entry with the lowercase NT flag); stops the fseventsd journal |

Data clusters are not stored, except in two cases:

* **Generated clusters** (2 and 3) are rendered on the fly until the host
  overwrites them.
* **Cluster cache** (caller budget, 0..16 clusters): non-image data written
  by the host, such as directory clusters of new folders, `.DS_Store`,
  AppleDouble files and "System Volume Information". Eviction is LRU, and
  directory clusters (sector 0 starts with a `.` entry) are protected:
  non-directory data never evicts a directory; it is dropped instead
  (`cache_dropped`). All-zero writes to unknown clusters are not cached,
  since unknown clusters already read as zeros.

Everything else reads as zeros, image data included: the host's page cache
serves its own reads.

**FAT mirroring.** FAT1 and FAT2 writes both land in the one RAM copy (last
writer wins), so a host that writes FAT2 first is handled. A FAT2 sector that
differs from the FAT1 sector the host *just* wrote is a divergence; it is
counted in `fat_mirror_diverged` and the FAT2 content is kept.

## 5. Tracker algorithm

### 5.1 Stream start and delivery

A data sector whose cluster offset is 0 and that begins with the PNG
signature `89 50 4E 47 0D 0A 1A 0A` or the JPEG SOI `FF D8 FF` **starts a
stream**:

* Any stream whose first cluster is the same cluster is abandoned
  (`OVERWRITTEN`).
* `cb.stream_start(id)` may refuse the stream (`BUSY`). The stream's
  contiguous tail is then swallowed (*skip window*), so its data neither
  reaches the consumer nor thrashes the cache.
* The previous receiving stream stops receiving and waits for its metadata
  (it becomes *pending*). At most `FMSC_MAX_STREAMS` = 2 streams are tracked.
  When a third one starts, the oldest pending stream is abandoned
  (`SUPERSEDED`).
* The directory is checked at once (§5.4, no trigger). If the metadata was
  written first (Windows), the size is known and an oversized file is
  reported immediately.

The receiving stream accepts the sector at its **frontier** (`next_lba`) and
delivers it with `stream_data(id, offset, data, 512)`. It accepts at most
512 sectors (256 KiB). Delivery is in whole sectors, always in order, with
offsets starting at 0. A file is assumed to be contiguous from its first
cluster (any other layout is `FRAGMENTED` anyway).

A sector at the frontier is **not** taken as stream data when its cluster
offset is 0 and it starts another file: a new image signature (new stream),
or a *foreign marker*. Foreign markers are AppleDouble/AppleSingle
(`00 05 16 07|00 …`), `.DS_Store` (`00 00 00 01 'Bud1'`), an OLE compound file
(Thumbs.db), or a `.` directory entry. The receiving stream then stops
receiving. The following sectors of a foreign cluster go to the cache.

Bytes past the final size may be delivered. That happens with sector or
cluster slack, or when an unrelated non-marker file is written contiguously
before the metadata. The `size` passed to `stream_complete` is
authoritative, and the consumer must ignore bytes at or beyond it.

### 5.2 Out-of-order writes

A sector ahead of the frontier, at most `FMSC_REORDER_WINDOW` (128) sectors
and inside the 256 KiB range, is stored in the caller's **reorder buffer**
(0..64 sectors). The buffer drains when the frontier reaches it. If the
buffer is full, the stream fails with `GAP` (the data would be lost).
Sectors further ahead are treated as unrelated data.

The first sector of a file must arrive before the other sectors of its first
cluster. Earlier sectors cannot yet be attributed to a stream (§8).

### 5.3 Rewrites

Every delivered sector keeps a 16-bit checksum (FNV-1a folded): 1 KiB per
stream. A rewrite of a delivered sector is handled by case:

* **identical**: ignored. This covers bus-reset retries and a re-copy of the
  same file.
* **different, first sector, still an image**: the file was overwritten. The
  old stream fails with `OVERWRITTEN` and a new stream starts.
* **different, other sector**: the stream fails with `REWRITE`, and the
  sector is processed as a fresh write.

The checksum only recognises honest retries. The host controls all bytes
anyway, so it is not a security boundary.

### 5.4 Completion

A stream is *ready* when all of the following hold:

1. A **live** directory entry references its first cluster. The root
   directory and the cached directory clusters are searched. LFN entries,
   volume labels and directories are skipped. A deleted entry (`E5`) does
   not count.
2. The entry's size `S` satisfies 0 < S ≤ 256 KiB. An entry created with
   size 0 and updated later is simply waited for.
3. The FAT chain from the first cluster is contiguous for ⌈S/4096⌉ clusters
   and ends with EOC.
4. All bytes [0, S) were delivered.

Evaluation runs on these **triggers**. The table also shows which negative
verdicts each one may issue:

| trigger | when | may complete | negative verdicts |
|---|---|---|---|
| none | end of a WRITE that touched FAT/root/cached directory; stream start | no | `TOO_LARGE`, `DELETED` (an entry was seen, then only a deleted one) |
| SYNC | SYNCHRONIZE CACHE | yes | + `FRAGMENTED` |
| QUIET | no write for `quiet_ms` (e.g. 2 s) | yes | none |
| SETTLE | no write for `settle_ms` (e.g. 15 s) | yes | + `FRAGMENTED`, `MISSING_DATA` |
| EJECT | START STOP UNIT LoEj | yes | everything; any other unfinished stream → `INCOMPLETE` |

`stream_complete` fires at most once per stream id. The stream record is
freed *before* the callback runs, so the callback never observes a half-done
state.

Negative verdicts are held back for two reasons:

* A FAT12 entry can straddle two FAT sectors that the host writes in
  separate commands. An evaluation between them would see a bogus link, so
  `FRAGMENTED` waits for a sync or the settle period.
* Linux writes data and metadata in writeback passes up to 5 s apart, and a
  host may sync one file while another file's data is still cached. So
  `MISSING_DATA` waits for the settle period or the eject.

**Stale entries.** On Linux, `cp new.png existing.png` can write the new data
before the new metadata. The device then still holds the *previous* file's
entry, which references the same first cluster. The tracker remembers the
(first cluster, size) of the last 4 finished streams. When a new stream
starts on such a cluster and finds an entry with that size, the entry is
treated as *stale* until it changes. A stale entry may confirm a completion,
but it never causes `TOO_LARGE`, `FRAGMENTED`, `MISSING_DATA` or `DELETED`.

### 5.5 Host-OS behaviours covered by the simulator (tests/c/fmsc/test_tracker.c)

| behaviour | scenario |
|---|---|
| Windows: FAT, root entry with final size, then data; SYNC | `test_windows_metadata_first` |
| data, FAT2 before FAT1, entry; completion by quiet period | `test_windows_data_first_quiet` |
| macOS: entry with size 0, page-sized data, FAT, entry update, AppleDouble right after the image, `.DS_Store` | `test_macos_sequence` |
| Linux: one ascending 240-sector sweep over two files, whole FAT copies, root; SYNC | `test_linux_writeback_two_files` |
| LFN names (3 entries; > 63 chars truncated) | `test_lfn_names` |
| six files in one session | `test_multiple_sequential` |
| replace after completion; identical re-copy | `test_overwrite_after_complete` |
| Linux overwrite with a bigger file, data before metadata (stale entry) | `test_linux_overwrite_bigger_stale_entry` |
| overwrite mid-transfer | `test_overwrite_mid_transfer` |
| delete before completion | `test_delete_before_complete` |
| > 256 KiB (metadata first / data first), exactly 256 KiB | `test_too_large` |
| fragmented chain | `test_fragmented` |
| FAT entry straddling two FAT sectors, written one sector per command | `test_fat_entry_straddling_sectors` |
| reordering within the budget (sector- and cluster-level), beyond it, no budget | `test_out_of_order_*` |
| metadata complete, data missing; settle verdict | `test_missing_data_settle` |
| 60 s writeback delay before metadata | `test_quiet_needs_metadata` |
| eject before completion; eject as the completion trigger | `test_eject_paths` |
| BOT reset in the middle of a WRITE, retried command | `test_bus_reset_mid_transfer` |
| consumer busy; re-copy later | `test_consumer_busy` |
| second image before the first one's metadata; third one supersedes | `test_overlapping_streams` |
| image inside a new subfolder | `test_subdirectory` |
| "System Volume Information" + IndexerVolumeGuid | `test_windows_junk` |
| 1000-byte file written as a 4 KiB page | `test_slack_bytes` |

## 6. RAM budget

`sizeof(fmsc_ctx_t)` = **11 888 bytes** on Cortex-M4 (`arm-none-eabi-gcc`),
and 11 936 bytes on a 64-bit host:

| item | bytes |
|---|---|
| FAT copy | 6144 |
| root directory | 2048 |
| 2 streams × (1024 B checksums + name + state) | ≈ 2200 |
| sector / response buffer | 512 |
| reorder metadata (64 slots), cache metadata (16 slots) | ≈ 700 |
| BOT/SCSI state, config copy, statistics | ≈ 300 |

Caller memory, in addition: cache `cache_clusters × 4096`, suggested 4 →
16 KiB; reorder `reorder_sectors × 512`, suggested 8–16 → 4–8 KiB. The
suggested T2B1 total is 12 + 16 + 4 = **32 KiB**. The 24 KiB target
excluding cache is met with room to spare: 11.6 KiB + 4 KiB reorder.

`fmsc_wipe` zeroizes the context, the cache and the reorder buffer with
volatile stores. Consumed reorder slots and the sector buffer are zeroized
as soon as they are used.

## 7. Error and event reference

| `fmsc_stream_error_t` | meaning | suggested UI |
|---|---|---|
| `BUSY` | consumer refused (still decoding another image) | "Une image à la fois" |
| `SUPERSEDED` | two newer images arrived first | "Copiez les images une par une" |
| `OVERWRITTEN` | the file was replaced while being copied | silent (new stream follows) |
| `REWRITE` | delivered data changed | "Copie interrompue, recommencez" |
| `GAP` | reordering beyond the budget | "Copie interrompue, recommencez" |
| `TOO_LARGE` | > 256 KiB | "Fichier trop grand (max 256 Kio)" |
| `FRAGMENTED` | non-contiguous allocation | "Volume fragmenté : supprimez des fichiers" |
| `MISSING_DATA` | metadata says more than was written | "Copie incomplète" |
| `DELETED` | deleted before completion | silent |
| `INCOMPLETE` | ejected before completion | "Import annulé" |

## 8. Known limitations

* **Contiguity.** A fragmented image cannot be imported. The volume is
  nearly empty, so hosts allocate contiguously. Once many files have been
  copied and deleted in one session, holes can appear; the error message
  should suggest ejecting and starting over.
* **First sector first.** Sectors of an image's first cluster written
  before its first sector are lost. Linux, macOS and Windows write a file's
  first page first.
* **Large reorderings** beyond the reorder budget end the stream (`GAP`) or
  leave it incomplete (`MISSING_DATA` at settle/eject).
* **Root directory: 64 entries.** One image with an LFN and its macOS
  AppleDouble twin take about 6 entries, so a long fragmented-backup restore
  may fill the root. Use short filenames such as `QR000001.PNG` and batches
  of at most 32 images (smaller when host metadata uses additional entries).
  After the device's received-frame count confirms a batch, delete those
  copies from the import drive, keeping the original images. Deletion frees
  directory entries and clusters without discarding collected frame bytes.
  Continue on the same mounted volume until the identity is complete:
  ejecting/re-entering would discard its incomplete collector. The native
  MSC functional test delivers a maximal OpenPGP envelope in 234 QR images,
  reusing the directory and clusters across eight batches on both emulator
  models, then verifies the stored certificate and RSA public key over CCID.
  Finder/Explorer metadata behavior still needs physical host acceptance.
* **Subdirectories** are seen only while their first cluster stays cached.
  Entries in their second and later clusters are not searched.
* **Non-image files** written right after an image, contiguously and before
  any metadata, may be delivered as image slack and not kept. The volume is
  ephemeral and exists only to receive images.
* **Reads of image clusters return zeros.** Quick Look or thumbnailers that
  bypass the page cache see an empty file.
* **JPEG EXIF thumbnails.** In a data-first write, a thumbnail that begins
  exactly at a 4 KiB boundary (`FF D8 FF`) is taken for a new file
  (probability about 1/4096 per photo with a thumbnail). The first stream
  then waits for metadata it will match with only part of its data
  (`MISSING_DATA`). Photos that size usually exceed 256 KiB anyway.
* **Windows "Safely remove"** may power the device down without a SCSI
  START STOP UNIT. Acceptance test R05 must check which events Windows 10/11
  produce. If needed, the application can treat USB suspend after
  confirmation as a clean stop.
* The quiet period completes a file whose metadata is consistent. If a host
  wrote an intermediate consistent state (size, chain and data for a prefix)
  and then paused longer than `quiet_ms`, the prefix would be reported. The
  consumer's own check (decoder end ≤ `size`, PNG `IEND` / JPEG `EOI` seen)
  rejects it, and the user copies the file again.
