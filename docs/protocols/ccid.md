<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# USB CCID reader of the feuristic virtual card

Status: **normative** for feuristic v0.x. Implementation:
`src/feuristic/apps/card/ccid.py` (message layer),
`src/feuristic/apps/card/dispatcher.py` (ISO 7816-4 card),
`src/feuristic/apps/card/card.py` (`Card`, the glue-facing object).
Requirements: product spec §2.1, §3.1, §10.5; architecture §5.

The Safe 3 exposes one USB CCID interface (spec §3.1, NORMAL mode) with one
slot holding a permanently inserted virtual card. The card is
multi-application (OpenPGP, PIV, the feuristic AES/RNG profile), and its
applications are selected by AID. References: *USB Device Class: Smart
Card CCID, Rev 1.1* (CCID), ISO/IEC 7816-3/-4.

## 1. Split between kernel and coreapp

The kernel class only moves raw bulk packets (architecture §5.3). It must
do the following:

* expose the interface and class descriptors below;
* forward every bulk-OUT packet (≤ 64 B) unchanged to the coreapp
  (`SYSHANDLE_USB_CCID`), and send every bulk-IN packet the coreapp writes;
  **a zero-length write means "send a ZLP"**;
* send `RDR_to_PC_NotifySlotChange` `50 03` (card present, changed) on the
  interrupt IN endpoint after `SET_CONFIGURATION`;
* handle the class-specific control requests: `ABORT` (0x01) is ACKed with
  no data stage and may be forwarded to `Card.control_abort(slot, seq)` (the
  bulk `PC_to_RDR_Abort` is what actually cancels). `GET_CLOCK_FREQUENCIES`
  (0x02) and `GET_DATA_RATES` (0x03) are STALLed, because
  `bNumClockSupported` and `bNumDataRatesSupported` are 0;
* on USB reset, unconfiguration or a mode switch, notify the coreapp, which
  calls `Card.usb_reset()`.

Message assembly, all CCID semantics and APDU processing run unprivileged
in Python. Hostile input is never parsed in the kernel.

## 2. Descriptors

Interface: `bInterfaceClass 0x0B`, subclass 0, protocol 0 (bulk), 3
endpoints: bulk OUT 64 B, bulk IN 64 B, interrupt IN 8 B (bInterval 255 ms
suggested).

CCID class descriptor (54 bytes, Table 5.1-1). These values come from
`ccid.class_descriptor()`, and the C descriptor must match
`ccid.class_descriptor_bytes()` byte for byte:

| Offset | Field | Value | Notes |
|---|---|---|---|
| 0 | bLength | `0x36` | |
| 1 | bDescriptorType | `0x21` | |
| 2 | bcdCCID | `0x0110` | Rev 1.1 |
| 4 | bMaxSlotIndex | `0x00` | one slot |
| 5 | bVoltageSupport | `0x07` | 5 V / 3 V / 1.8 V (virtual) |
| 6 | dwProtocols | `0x00000002` | T=1 only |
| 10 | dwDefaultClock | `4000` kHz | |
| 14 | dwMaximumClock | `4000` kHz | |
| 18 | bNumClockSupported | `0` | |
| 19 | dwDataRate | `10752` bps | 4 MHz / 372 |
| 23 | dwMaxDataRate | `10752` bps | |
| 27 | bNumDataRatesSupported | `0` | |
| 28 | dwMaxIFSD | `254` | |
| 32 | dwSynchProtocols | `0` | |
| 36 | dwMechanical | `0` | |
| 40 | dwFeatures | `0x000400FE` | see below |
| 44 | dwMaxCCIDMessageLength | `4106` | 10 + 4096 |
| 48 | bClassGetResponse | `0xFF` | echo CLA |
| 49 | bClassEnvelope | `0xFF` | echo CLA |
| 50 | wLcdLayout | `0x0000` | no LCD |
| 52 | bPINSupport | `0x00` | no PIN pad (PINs are entered on the host or on the device menu) |
| 53 | bMaxCCIDBusySlots | `1` | |

`dwFeatures = 0x000400FE`:

* 0x02 automatic parameter configuration from the ATR;
* 0x04 automatic activation on insertion;
* 0x08 automatic voltage selection;
* 0x10 automatic clock change;
* 0x20 automatic baud rate change;
* 0x40 automatic parameter negotiation, so libccid never sends PPS or
  `SetParameters` on its own;
* 0x80 automatic PPS;
* 0x00040000 **short and extended APDU level exchange**.

With APDU-level exchange the host sends whole command APDUs in
`PC_to_RDR_XfrBlock`, so no T=1 block protocol runs on USB.

Size: one message carries at most 4096 bytes of `abData`. An extended APDU
with more data (up to 4 + 3 + 4096 + 2 = 4105 bytes, feuristic's
`MAX_COMMAND_DATA` = 4096) is split by the host with the XfrBlock
`wLevelParameter` chaining of CCID §6.1.4 (`0x0001` begin, `0x0003`
continue, `0x0002` end; the reader answers `bChainParameter = 0x10` to each
non-final block). A response longer than 4096 bytes is returned in blocks
with `bChainParameter` `0x01`/`0x03`/`0x02`, and the host requests each
continuation with an empty XfrBlock where `wLevelParameter = 0x0010`.

## 3. ATR

```
3B DA 11 FF 81 B1 FE 75 1F 03  00 31 C1 73 C0 01 C0 05 90 00  84
```

| Bytes | Meaning |
|---|---|
| `3B` | TS, direct convention |
| `DA` | T0: TA1, TC1, TD1 present; K = 10 historical bytes |
| `11` | TA1: Fi = 372, Di = 1 |
| `FF` | TC1: minimal extra guard time |
| `81` | TD1: TD2 follows, T=1 |
| `B1` | TD2: TA3, TB3, TD3 follow, T=1 |
| `FE` | TA3: IFSC = 254 |
| `75` | TB3: BWI = 7 (≈ 11 s at 4 MHz), CWI = 5 |
| `1F` | TD3: TA4 follows, T=15 (global) |
| `03` | TA4: class A and B, clock stop not supported |
| historical | see below |
| `84` | TCK (XOR of T0…last historical byte) |

Historical bytes (ISO/IEC 7816-4 §8.1.1), also returned by OpenPGP
`GET DATA 5F52`:

* `00`: category indicator; the status indicator is the last 3 bytes.
* `31 C1`: card service data. Selection by full DF name and by partial DF
  name; card without MF.
* `73 C0 01 C0`: card capabilities.
  * Byte 1: selection by full/partial DF name.
  * Byte 2: data unit = 1 byte.
  * Byte 3: **command chaining (b8) and extended Lc/Le (b7)**; no logical
    channels.

  GnuPG and OpenSC read byte 3 to decide whether to use extended APDUs.
* `05 90 00`: life cycle *operational (activated)*, SW `9000`.

The T=1 parameters returned by `GetParameters` follow the ATR:
`11 10 FF 75 00 FE 00` (bmFindexDindex, bmTCCKST1 = LRC/direct,
bGuardTimeT1, bmWaitingIntegersT1, bClockStop, bIFSC, bNadValue).

## 4. Command support (CCID §6.1)

| Command | Behaviour |
|---|---|
| `62` IccPowerOn | `bPowerSelect` 0–3 accepted (else bError 7). Cold/warm reset: every applet is reset. DataBlock carrying the ATR. |
| `63` IccPowerOff | Card inactive and applets reset (PIN verification lost). SlotStatus. |
| `65` GetSlotStatus | SlotStatus. |
| `6F` XfrBlock | APDU exchange (short/extended, chaining as in §2). ICC inactive → `bStatus 0x41`, `bError ICC_MUTE (0xFE)`. |
| `6C` GetParameters | Parameters (`bProtocolNum` 1). |
| `6D` ResetParameters | Defaults; Parameters. |
| `61` SetParameters | T=1 only (T=0 → bError 7). Length 7 (else bError 1). Rejected fields: bmTCCKST1 other than `10`/`11` (bError 11), BWI > 9 (13), clock stop (14), IFSC 0 or 255 (15), NAD ≠ 0 (16). |
| `73` SetDataRateAndClockFrequency | Length 8. Answers with the fixed values in use. |
| `72` Abort | Cancels a pending APDU: the aborted XfrBlock gets `bError CMD_ABORTED (0xFF)`, then SlotStatus for the Abort. |
| `6B` Escape | `RDR_to_PC_Escape`, `bError CMD_NOT_SUPPORTED (0)`. |
| `6E` IccClock, `6A` T0APDU, `69` Secure, `71` Mechanical, unknown | Failed, `bError 0`, in the matching response type. |

Common rules:

* `bSeq` is echoed.
* `bSlot` ≠ 0 → `bStatus 0x42` (no ICC), `bError 5`.
* `bStatus` bits 0–1: 0 active, 1 inactive; bits 6–7: 0 OK, 1 failed,
  2 time extension.

Framing:

* A message ends when `10 + dwLength` bytes have arrived. Hosts send no
  OUT ZLP; a stray ZLP is ignored.
* A packet shorter than 64 bytes ends a transfer. If `dwLength` has not
  been reached, the message is truncated and gets `bError 1`.
* `dwLength` > 4096 → `bError 1`, and the rest of the transfer is
  discarded up to the next short packet.
* Headers shorter than 10 bytes are dropped silently (`bSeq` is unknown).

Busy: while an APDU is processed, any other command except Abort gets
`bError CMD_SLOT_BUSY (0xE0)`.

## 5. Time extension (WTX)

Every APDU that waits for the user (signature, decipher, key generation,
…) or takes long (RSA key generation) keeps the host waiting. While
`Card.pending` is set, the glue writes `Card.time_extension()` every
**`WTX_INTERVAL_MS` = 1000 ms**. The message is a DataBlock with
`bStatus = 0x80`, `bError = WTX_MULTIPLIER = 1`, `dwLength = 0` and the
`bSeq` of the pending command.

How hosts handle this:

* libccid (Linux, and macOS's ifd-ccid fork) reads bulk-IN with a timeout
  of at least `DEFAULT_COM_READ_TIMEOUT` = 3 s, or more after the ATR
  (BWI = 7). Each time-extension message restarts the read; libccid only
  logs the multiplier, or multiplies its current timeout by it, so 1 keeps
  the timeout bounded.
* The Windows `usbccid` driver also honours time extension.

A 1 s period gives a 3× margin. The device-side prompt timeout is 30 s
(`core.interaction.DEFAULT_TIMEOUT_MS`), after which the applet answers
`6985`.

## 6. Glue contract (`fw_ccid.py`)

```python
card = Card([openpgp, piv, aes], fallback=aes)    # fallback: card-level GET CHALLENGE
# reader loop
for p in card.receive(packet):        # immediate answers
    write(p)                          # b"" → ZLP
if card.pending and not worker_running:
    spawn(worker())
# worker
task = card.process_pending()
# race(task, sleep(WTX_INTERVAL_MS)); on timeout write card.time_extension() and loop
for p in await task:
    write(p)
```

* `Card.receive()` stays callable while the worker runs (busy answers,
  Abort). After an Abort, `process_pending()` returns `[]` for the stale
  job.
* Whole-message transports (emulator UDP carrying complete CCID messages)
  use `await Card.handle_message(raw) -> [messages]`.
* `Card.usb_reset()` on bus reset, mode switch or device lock.
* Interrupt IN: `Card.notify_slot_change()` → `50 03`.

## 7. Card-level behaviour (dispatcher)

* CLA values `0x00–0x1F` and `0x80–0xFE` are accepted on the basic channel
  without SM.
* Logical channels (non-zero `b2-b1`, or `0x40–0x7F`) → `6881`. Secure
  messaging bits → `6882`. `0x20–0x3F` and `0xFF` → `6E00`. A malformed
  APDU → `6700`.
* `SELECT` by DF name, `P1 = 04`:
  * `P2` `00`/`04`/`0C`; anything else → `6A86`.
  * Partial AIDs are allowed (first registered applet wins).
  * Unknown AID → `6A82`, and the current selection is kept.
  * Re-selecting the same applet keeps its PIN state; switching applet
    drops it.
  * Other selection methods (`P1` ≠ `04`) → `6A82`, because the card has
    no MF.
* Nothing selected: commands go to the `fallback` applet if there is one,
  else `6D00`.
* Command chaining (CLA b5): parts are concatenated, at most 4096 bytes in
  total (else `6700`). An INS/P1/P2/CLA mismatch mid-chain → `6883`, and
  the chain is dropped.
* Response chaining: data beyond `Ne` → `61xx`, then `GET RESPONSE`
  (`INS C0`, `P1P2 0000`; anything else → `6A86`). The final part carries
  the real SW.
  * An absent `Le` means `Ne` = 256 (short) or 65536 (extended).
  * Extended APDUs get up to 65536 bytes in one response.
  * `GET RESPONSE` with nothing pending → `6985`.
* Errors raised by applets:

  | Error | SW |
  |---|---|
  | `InvalidInput` | `6A80` |
  | user refusal or timeout | `6985` |
  | `StorageFull` | `6A84` |
  | `PinBlocked` | `6983` |
  | anything else | `6F00` |

## 8. Host notes

* **Linux:** pcscd + libccid only drive readers listed in libccid's
  `Info.plist` (`ifdVendorID`/`ifdProductID`). The pid.codes VID/PID
  `0x1209:0x0001`, and any later dedicated PID, must be added locally
  (`/usr/lib/pcsc/drivers/ifd-ccid.bundle/Contents/Info.plist`, or the
  class driver `ifd-ccid.bundle` with `ifdDriverOptions 0x0004`) until it
  is upstreamed to libccid.
* **macOS:** the built-in CryptoTokenKit CCID driver binds by interface
  class. GnuPG should use PC/SC (`disable-ccid` in `scdaemon.conf`).
* **Windows:** the inbox `usbccid.sys` class driver binds by interface
  class.
