# SPDX-License-Identifier: GPL-3.0-only
"""R05/R06 (emulated): QR import over the temporary mass-storage mode."""

import io

import segno
from harness.emulator import PORT_CCID, PORT_FIDO, PORT_MSC
from harness.msc import Fat12Writer, MscClient

URI = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"


def qr_png(data: str, scale: int = 6) -> bytes:
    buf = io.BytesIO()
    segno.make(data, error="m").save(buf, kind="png", scale=scale, border=4)
    return buf.getvalue()


def qr_jpeg(data: str) -> bytes:
    from PIL import Image

    img = Image.open(io.BytesIO(qr_png(data, 8))).convert("L")
    out = io.BytesIO()
    img.save(out, "JPEG", quality=90)
    return out.getvalue()


def _open_import(debug):
    debug.select("Authentication")
    debug.wait_title("Authentication")
    debug.select("OTP")
    debug.wait_for(lambda s: s.title in ("One-time passwords", "OTP"))
    debug.select("Add QR over USB")


def _wait_msc(emu, timeout=20):
    emu.wait_ready(PORT_MSC, timeout)
    msc = MscClient(emu.port(PORT_MSC))
    msc.start()
    return msc


def test_volume_appears_only_in_import_mode_and_is_fat12(ready, emu):
    import socket

    from fido2.ctap2 import Ctap2
    from harness.ccid import CcidClient
    from harness.fido import open_device

    # Warm both complete protocol stacks before IMPORT purges their modules.
    dev = open_device(emu.port(PORT_FIDO))
    card = CcidClient(emu.port(PORT_CCID))
    try:
        assert "FIDO_2_1" in Ctap2(dev).info.versions
        card.power_on()
        assert card.transmit(bytes.fromhex("00A4040006D27600012401"))[1] == 0x9000
    finally:
        dev.close()
        card.close()
    # not present in normal mode
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(0.5)
        s.sendto(b"PINGPING", ("127.0.0.1", emu.port(PORT_MSC)))
        try:
            s.recvfrom(64)
            raise AssertionError("MSC interface present in normal mode")
        except (TimeoutError, ConnectionRefusedError, OSError):
            pass
    _open_import(ready)
    msc = _wait_msc(emu)
    try:
        inq = msc.inquiry()
        assert inq[16:32] == b"FEURISTIC-IMPORT"
        sectors, bs = msc.read_capacity()
        assert bs == 512 and sectors > 30000
        boot = msc.read(0)
        assert boot[54:62] == b"FAT12   "
        for interface in (PORT_FIDO, PORT_CCID):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(0.3)
                s.sendto(b"PINGPING", ("127.0.0.1", emu.port(interface)))
                try:
                    s.recvfrom(64)
                    raise AssertionError("normal USB interface present in import mode")
                except (TimeoutError, ConnectionRefusedError, OSError):
                    pass
        assert msc.eject() == 0
    finally:
        msc.close()
    ready.wait_title("One-time passwords", timeout=20)  # back to the menu after eject
    # Both long-lived polling tasks must resume, not merely the USB sockets.
    dev = open_device(emu.port(PORT_FIDO))
    card = CcidClient(emu.port(PORT_CCID))
    try:
        assert "FIDO_2_1" in Ctap2(dev).info.versions
        card.power_on()
        data, sw = card.transmit(bytes.fromhex("0084000020"))
        assert sw == 0x9000 and len(data) == 32
    finally:
        dev.close()
        card.close()


def _import_otp(ready, emu, image: bytes, name: str):
    _open_import(ready)
    msc = _wait_msc(emu)
    try:
        Fat12Writer(msc).write_file(name, image)
        # confirmation of the new account on the device
        s = ready.wait_for(lambda s: "Example" in s.text(), timeout=30)
        ready.approve()
        ready.wait_for(lambda s: "Eject" in s.text() or "jectez" in s.text(), timeout=30)
        assert msc.eject() == 0
    finally:
        msc.close()
    ready.wait_title("One-time passwords", timeout=30)
    return s


def test_import_otp_png(ready, emu):
    _import_otp(ready, emu, qr_png(URI), "QR.PNG")
    assert "Example" in ready.screen().text()
    ready.both()  # the freshly imported account
    ready.select("View code")
    # app_otp is a suspended caller during import: it must catch the new
    # TimeNotSynchronised class after the old OTP modules were unloaded.
    ready.wait_for(lambda screen: "Sync over USB" in screen.text())


def test_import_otp_jpeg(ready, emu):
    _import_otp(ready, emu, qr_jpeg(URI), "QR.JPG")
    assert "Example" in ready.screen().text()


def test_rejects_non_qr_image(ready, emu):
    from PIL import Image

    img = Image.new("L", (200, 200), 255)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    _open_import(ready)
    msc = _wait_msc(emu)
    try:
        Fat12Writer(msc).write_file("BLANK.PNG", buf.getvalue())
        ready.wait_for(lambda s: "No QR" in s.text(), timeout=30)
        ready.both()  # cancel: nothing imported, the device asks for an eject
        ready.wait_for(lambda s: "Eject" in s.text(), timeout=30)
        assert msc.eject() == 0
    finally:
        msc.close()


def test_import_survives_power_cut(ready, emu):
    """Unplugging during an import leaves storage untouched (spec §3.3)."""
    _open_import(ready)
    msc = _wait_msc(emu)
    try:
        Fat12Writer(msc).write_file("QR.PNG", qr_png(URI))
        ready.wait_for(lambda s: "Example" in s.text(), timeout=30)
    finally:
        msc.close()
    emu.restart()  # power cut before confirmation
    from conftest import enter_pin
    from harness.debug import Debug
    from harness.emulator import PORT_DEBUG

    d = Debug(emu.port(PORT_DEBUG))
    try:
        d.wait_for(lambda s: s.component != "", timeout=20)
        d.both()
        enter_pin(d)
        d.wait_title("feuristic", timeout=20)
        d.select("Authentication")
        d.select("OTP")
        s = d.wait_for(lambda s: s.title == "One-time passwords")
        assert s.choice == "Add QR over USB"  # no account was added
    finally:
        d.close()
