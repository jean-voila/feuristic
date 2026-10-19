<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Emulator and standard host tools

Build/start a visible test instance:

```sh
make emu MODEL=T3B1
make emu-run MODEL=T3B1
```

The default persistent profile is `/tmp/feuristic-emu`; set
`TREZOR_PROFILE_DIR` to a dedicated absolute directory to use another one.
Treat its files as test secrets. Stop with Ctrl-C. Never point an emulator at
production material. Use [functional fixtures](../../tests/functional/harness/emulator.py)
for isolated profiles and automatic cleanup.

| Interface | Base offset | Default manual port (base 21324) |
|---|---:|---:|
| Debuglink | +1 | 21325 |
| FIDO HID | +2 | 21326 |
| CDC time | +3 | 21327 |
| CCID | +7 | 21331 |
| MSC | +8 | 21332 |

`TREZOR_UDP_PORT` selects a manual instance's base. Datagram transport is
loopback development transport, not a real OS USB device. Packet harnesses
are in `tests/functional/harness/`; CCID supports whole-message transport as
well as packets. The emulator obtains entropy from `/dev/urandom` by default;
this is not the MCU/Optiga entropy path.

Onboarding uses the same screens and a test PIN. Debuglink can press buttons,
read layouts and enter text, so it must never be enabled in a release image.
For a T3B1 instance on the manual default ports:

```sh
uv run python tools/emu_probe.py read
uv run python tools/emu_probe.py right middle read
```

The probe currently implements `left`, `right`, `middle`, `read`, and
`sleep:<ms>` only; do not rely on additional actions mentioned in its docstring.
Select time sync on the screen before sending:

```sh
uv run python tools/feuristic_time.py --udp 21327
```

## PC/SC bridge

On Linux install/start the PC/SC virtual reader as in [testing.md](testing.md).
Unlock the emulator and keep it in normal mode, then in another terminal:

```sh
uv run python tools/vpcd_bridge.py --ccid-port 21331
opensc-tool --list-readers
opensc-tool -s 0084000020
```

The bridge connects TCP 35963 by default and forwards APDUs to UDP CCID. A
virtual reader must be present and `pcscd` running. Stop the bridge before
switching the emulator's mode. GnuPG should use PC/SC (`disable-ccid` in an
isolated `scdaemon.conf`). `--verbose` logs raw APDUs and can reveal PINs and
sensitive input; enable only with disposable data.

The emulator cannot validate electrical USB enumeration, bootloader unlock,
button hardware timing, physical OLED/camera readability, peak MCU RAM,
Optiga behavior or power cuts during flash programming. Those remain
[hardware acceptance gates](../acceptance/README.md).
