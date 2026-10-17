<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# feuristic time synchronisation protocol, version 1

Status: **normative** for feuristic v0.x. Implementation:
`src/feuristic/apps/timesync/protocol.py`. Product requirements: spec §3.2,
§4, acceptance criterion R07.

The key words MUST, MUST NOT, SHOULD and MAY are to be interpreted as in
RFC 2119.

## 1. Purpose and scope

The Trezor Safe 3 has no battery-backed real-time clock. TOTP (RFC 6238)
needs the UNIX time, so the user gives the device the time once per power
session through a minimal, public, versioned text protocol over a USB
CDC-ACM serial port. No feuristic companion application is needed: any
serial terminal or a one-line shell command works.

The device keeps the time from its monotonic tick counter for as long as it
stays powered. After a power cut the time is lost and TOTP screens show
"Time to synchronise" ("Heure à synchroniser") instead of a code.

## 2. Transport

* The user starts the mode on the device: **Settings → TOTP time → Sync
  over USB** (*Réglages → Heure TOTP → Synchroniser par USB*).
* The device re-enumerates as **CDC-ACM only** (USB mode `TIMESYNC`,
  docs/architecture.md §5.2): one communication interface with an interrupt
  IN endpoint and one data interface with bulk IN/OUT endpoints of 64 bytes.
  FIDO2 and the smart-card interface are unavailable while the mode is
  active.
* Line coding (baud rate, parity, stop bits) set by the host is accepted and
  ignored. DTR/RTS are not required.
* The mode ends, and the device re-enumerates as FIDO HID + CCID, after a
  successful `TIME` command, when the user cancels on the device, or after an
  idle timeout chosen by the firmware (SHOULD be at least 120 s).

## 3. Framing

* The byte stream is split into **lines**. A line ends at LF (`0x0A`), CR
  (`0x0D`) or CR LF. Empty lines are ignored, so CR LF is not answered twice.
  CR alone is accepted because interactive terminals (`screen`, PuTTY) send
  CR on Enter.
* A line MUST NOT contain more than **64 bytes** before its terminator. The
  device discards a longer line up to the next terminator and answers
  `ERR 6`. The device never buffers more than 64 bytes of an unterminated
  line.
* Lines MUST contain only printable ASCII (`0x20`–`0x7E`); anything else is
  a syntax error (`ERR 1`).
* Every non-empty line receives **exactly one** response line terminated by
  LF. Responses are sent in request order.

## 4. Messages

ABNF (RFC 5234):

```abnf
request      = time-request / hello-request
time-request = "TIME" SP version SP unix-seconds
hello-request= "HELLO"
version      = 1*3DIGIT            ; must have the value 1
unix-seconds = 1*20DIGIT           ; seconds since 1970-01-01T00:00:00Z, no sign

response     = ok-response / err-response / hello-response
ok-response  = "OK" SP 1*20DIGIT LF
err-response = "ERR" SP 1DIGIT LF
hello-response = "FEURISTIC TIME 1" LF
```

Keywords are case-sensitive and upper case. Tokens are separated by exactly
one space (`0x20`); leading/trailing spaces and tabs are syntax errors.
Leading zeros in numbers are allowed.

### 4.1 `TIME 1 <unix-seconds>`

Sets the session clock. On success the device answers `OK <unix-seconds>`
with the value actually applied, which is the requested value plus the
whole seconds spent on a confirmation screen (§5), if one was shown.

The version token is checked **before** the rest of the line, so a future
`TIME 2 ...` with another syntax receives `ERR 2`, never `ERR 1`.

### 4.2 `HELLO` (discovery, optional for hosts)

Answered with `FEURISTIC TIME 1`. Host tools MAY send it to check that the
serial port belongs to a feuristic device in time-sync mode and which
protocol versions it speaks. It changes nothing on the device.

### 4.3 Error codes

| Code | Meaning |
|---|---|
| `ERR 1` | Syntax error: unknown command, wrong token count or separator, non-digit number, non-printable byte |
| `ERR 2` | Unsupported protocol version (the version token is a number other than 1) |
| `ERR 3` | Time out of range: before 2024-01-01T00:00:00Z (`1704067200`), after 2100-01-01T00:00:00Z (`4102444800`), or more than 20 digits |
| `ERR 4` | Refused on the device: the user declined the confirmation or did not answer in time |
| `ERR 5` | Busy: a confirmation is already displayed, or the time was already set in this session and the device is leaving the mode |
| `ERR 6` | Line too long (more than 64 bytes before the terminator) |

Hosts MUST treat any other code as a generic failure.

## 5. Security policy

The device compares the requested time with its current session time:

| Situation | Action |
|---|---|
| Clock not set yet in this power session | applied directly |
| Within −60 s … +300 s of the session time | applied directly |
| More than **60 s earlier** than the session time | physical confirmation required (spec §4) |
| More than **300 s later** than the session time | shown and confirmed before acceptance (spec §4) |

The confirmation screen shows the current and new times in UTC
(`YYYY-MM-DD HH:MM:SS UTC`) and the signed difference. Declining, or not
answering before the prompt times out, gives `ERR 4` and leaves the clock
unchanged; the host MAY send another `TIME` line. While the screen is
displayed further `TIME` lines get `ERR 5`.

Moving the clock back matters for security because it can make the device
show codes that were already used; moving it far forward can be used to
compute codes for later. Both therefore need a decision on the device.

## 6. Device-side sequence (firmware glue)

```
menu "Sync over USB"
  └─ usb_set_mode(TIMESYNC)                # ≥ 100 ms detach, CDC-ACM enumerates
     session = TimeSyncSession(ui)
     repeat
        packet ← CDC bulk OUT (≤ 64 B)     # keep reading during confirmations
        for each response in await session.feed(packet): CDC bulk IN ← response
     until session.done or menu cancel or idle timeout
     flush IN, wait ≥ 100 ms                # let the host read "OK …"
  └─ usb_set_mode(NORMAL)                   # FIDO HID + CCID again
     notify "Time set until power-off" / "Time sync cancelled"
```

## 7. Host examples

Replace the device path with yours: macOS `/dev/cu.usbmodem*`, Linux
`/dev/ttyACM0`, Windows `COMn` (see Device Manager → Ports).

### 7.1 Linux

```sh
stty -F /dev/ttyACM0 raw -echo
exec 3<>/dev/ttyACM0
printf "TIME 1 %s\n" "$(date +%s)" >&3
head -n 1 <&3          # prints: OK 1800000000
exec 3>&-
```

The one-line form, without reading the answer:

```sh
stty -F /dev/ttyACM0 raw; printf "TIME 1 %s\n" "$(date +%s)" > /dev/ttyACM0
```

Your user needs access to the port (group `dialout` or `uucp` depending on
the distribution).

### 7.2 macOS

```sh
DEV=$(ls /dev/cu.usbmodem* | head -n 1)
stty -f "$DEV" raw -echo
printf "TIME 1 %s\n" "$(date +%s)" > "$DEV"
```

Interactive, to see the answer:

```sh
screen /dev/cu.usbmodem* 115200
# type:  TIME 1 <seconds> then Enter   (get the seconds with `date +%s`)
# quit:  Ctrl-A then K, then y
```

### 7.3 Windows (PowerShell)

```powershell
$port = New-Object System.IO.Ports.SerialPort "COM5", 115200
$port.NewLine = "`n"
$port.ReadTimeout = 60000          # leave time for a confirmation on the device
$port.Open()
$now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$port.WriteLine("TIME 1 $now")
$port.ReadLine()                   # OK <seconds>  or  ERR <code>
$port.Close()
```

### 7.4 Python (pyserial)

```python
import serial, time
with serial.Serial("/dev/ttyACM0", timeout=60) as s:
    s.write(b"TIME 1 %d\n" % int(time.time()))
    print(s.readline().decode().strip())
```

## 8. Example exchanges

```
> HELLO
< FEURISTIC TIME 1
> TIME 1 1800000000
< OK 1800000000
```

```
> time 1 1800000000
< ERR 1
> TIME 2 1800000000
< ERR 2
> TIME 1 1600000000
< ERR 3
> TIME 1 1799990000            (session clock reads 1800000000: confirmation shown)
< ERR 4                        (user declined)
```

## 9. Versioning

A future incompatible protocol uses another version number in the `TIME`
command and announces it in the `HELLO` response (for example
`FEURISTIC TIME 1 2`). A v1 device answers `ERR 2` to any other version.
