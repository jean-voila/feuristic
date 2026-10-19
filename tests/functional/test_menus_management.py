# SPDX-License-Identifier: GPL-3.0-only
"""R01/R03/R09/R10/R12/R15: real two-button management workflows."""

import time
from contextlib import closing

import pytest
from conftest import enter_pin, onboard
from harness.ccid import CcidClient
from harness.emulator import PORT_CCID

PIV_AID = bytes.fromhex("A000000308")
OPENPGP_AID = bytes.fromhex("D27600012401")


def _open_crypto(debug, app):
    debug.select("Cryptography")
    debug.wait_title("Cryptography")
    debug.select(app)


def _approve(debug, hold=False):
    """Scroll to the final button; destructive screens require an actual hold."""
    for _ in range(60):
        screen = debug.screen()
        buttons = debug._buttons(screen)
        middle = buttons.get("middle_btn") or {}
        if middle.get("component") == "HoldToConfirm":
            assert hold, "destructive confirmation requires an explicit held approval"
            debug.hold_both(2200)
            return
        if middle.get("text"):
            assert not (buttons.get("right_btn") or {}).get("text")
            if hold:
                debug.hold_both(2200)
            else:
                debug.both()
            return
        debug.right()
    raise AssertionError(f"confirmation has no final button: {debug.screen().data}")


def _find_text(debug, text):
    """Property dialogs deliberately paginate each field on the small screen."""
    for _ in range(30):
        screen = debug.screen()
        if text in " ".join(screen.text().split()):
            return
        buttons = debug._buttons(screen)
        if any((buttons.get(side) or {}).get("text") for side in ("middle_btn", "right_btn")):
            break
        debug.right()
    raise AssertionError(f"{text!r} missing from properties: {debug.screen().data}")


def _text(debug, title, value):
    debug.wait_title(title)
    debug.input(value)
    time.sleep(0.3)


def _piv_menu(debug):
    _open_crypto(debug, "PIV")
    debug.wait_title("PIV")
    # First visit must reveal the factory credential warnings.
    assert "Default PIV PIN" in " ".join(debug.screen().text().split())
    _approve(debug)
    debug.wait_for(lambda s: s.choice == "Identities")


def _piv_slot(debug):
    debug.select("Identities")
    debug.wait_title("Identities")
    debug.select("9A PIV Authentication")
    debug.wait_title("9A PIV Authentication")


def test_fido_pin_set_change_and_cancel(ready):
    d = ready
    d.select("Authentication")
    d.select("Passkeys")
    d.wait_title("Passkeys")
    d.select("Services")
    d.wait_title("No passkey stored")
    _approve(d)
    d.wait_title("Passkeys")
    d.select("FIDO PIN")
    d.select("Set FIDO PIN")
    enter_pin(d)
    _text(d, "New FIDO PIN", "123456")
    _text(d, "Repeat FIDO PIN", "123456")
    d.wait_for(lambda s: s.choice == "Change FIDO PIN")
    d.select("Change FIDO PIN")
    enter_pin(d)
    _text(d, "Current FIDO PIN", "123456")
    _text(d, "New FIDO PIN", "654321")
    _text(d, "Repeat FIDO PIN", "654321")
    d.wait_for(lambda s: s.choice == "Change FIDO PIN")
    d.select("Change FIDO PIN")
    d.wait_for(lambda s: s.component == "PinKeyboard")
    d.hold_left()
    d.wait_title("FIDO PIN")
    d.hold_left()
    d.wait_title("Passkeys")


def test_aes_create_rename_disable_and_cancel_delete(ready):
    d = ready
    _open_crypto(d, "AES")
    d.wait_title("AES")
    d.select("Create key")
    d.wait_title("Key identifier")
    d.select("#1")
    _text(d, "Key name (1-16 ASCII)", "test-key")
    d.wait_title("Confirmation")
    d.select("Confirm every operation")
    enter_pin(d)
    d.wait_title("Create key")
    _approve(d)
    d.wait_title("AES #1 test-key")
    d.select("Rename")
    _text(d, "Key name (1-16 ASCII)", "renamed-key")
    enter_pin(d)
    d.wait_title("AES #1 renamed-key")
    d.select("Disable")
    enter_pin(d)
    d.wait_title("Disable")
    _approve(d)
    d.wait_title("AES #1 renamed-key")
    d.select("Information")
    d.wait_title("AES")
    _find_text(d, "Disabled")
    _approve(d)
    d.wait_title("AES #1 renamed-key")
    d.select("Delete")
    enter_pin(d)
    d.wait_title("Delete AES key?")
    d.hold_left()
    d.wait_title("AES #1 renamed-key")
    d.select("Information")
    d.wait_title("AES")
    _find_text(d, "renamed-key")
    _approve(d)
    d.wait_title("AES #1 renamed-key")
    d.select("Delete")
    enter_pin(d)
    d.wait_title("Delete AES key?")
    _approve(d, hold=True)
    d.wait_title("AES")
    d.select("Keys")
    d.wait_title("No AES key yet")


def test_openpgp_local_pin_applies_to_ccid_and_cancel_is_safe(ready, emu):
    d = ready
    _open_crypto(d, "OpenPGP")
    d.wait_title("OpenPGP")
    d.select("Card PINs")
    d.select("User PIN (PW1)")
    d.select("Set new value")
    enter_pin(d)
    enter_pin(d, "654321")
    enter_pin(d, "654321")
    d.wait_title("Card PINs")
    d.select("User PIN (PW1)")
    d.select("Set new value")
    d.wait_for(lambda s: s.component == "PinKeyboard")
    d.hold_left()
    d.wait_title("Card PINs")
    with closing(CcidClient(emu.port(PORT_CCID))) as card:
        card.power_on()
        assert card.transmit(bytes.fromhex("00A4040006") + OPENPGP_AID)[1] == 0x9000
        assert card.transmit(bytes.fromhex("0020008106") + b"654321")[1] == 0x9000
        assert card.transmit(bytes.fromhex("0020008106") + b"123456")[1] == 0x63C2


def test_openpgp_generate_requires_clock(ready):
    d = ready
    _open_crypto(d, "OpenPGP")
    d.wait_title("OpenPGP")
    d.select("Generate keys")
    d.wait_title("Generate keys")
    assert "Synchronise the time" in " ".join(d.screen().text().split())
    _approve(d)
    d.wait_title("OpenPGP")


def test_piv_local_pin_and_puk_apply_to_ccid(ready, emu):
    d = ready
    _piv_menu(d)
    d.select("PIV settings")
    d.select("Set PIV PIN")
    enter_pin(d)
    enter_pin(d, "654321")
    enter_pin(d, "654321")
    d.wait_title("PIV settings")
    d.select("Set PIV PUK")
    enter_pin(d)
    enter_pin(d, "87654321")
    enter_pin(d, "87654321")
    d.wait_title("PIV settings")
    with closing(CcidClient(emu.port(PORT_CCID))) as card:
        card.power_on()
        assert card.transmit(bytes.fromhex("00A4040005") + PIV_AID)[1] == 0x9000
        assert card.transmit(bytes.fromhex("0020008008") + b"654321\xff\xff")[1] == 0x9000
        assert card.transmit(bytes.fromhex("0020008008") + b"123456\xff\xff")[1] == 0x63C2


def test_piv_key_generate_cancel_delete_preserves_key(ready):
    d = ready
    _piv_menu(d)
    _piv_slot(d)
    d.select("Generate key")
    d.select("ECC P-256")
    enter_pin(d)
    d.wait_title("Generate PIV key?")
    _approve(d, hold=True)
    d.wait_title("9A PIV Authentication", timeout=20)
    _find_text(d, "Key, no certificate")
    _approve(d)
    d.wait_title("9A PIV Authentication")
    d.select("Delete slot")
    enter_pin(d)
    d.wait_title("Delete PIV slot?")
    d.hold_left()
    d.wait_title("9A PIV Authentication")
    d.select("Information")
    d.wait_title("9A PIV Authentication")
    _find_text(d, "Key, no certificate")
    _approve(d)
    d.wait_title("9A PIV Authentication")
    d.select("Delete slot")
    enter_pin(d)
    d.wait_title("Delete PIV slot?")
    _approve(d, hold=True)
    d.wait_title("Identities")
    d.select("9A PIV Authentication")
    d.select("Information")
    d.wait_title("9A PIV Authentication")
    _find_text(d, "Empty")


def test_rng_status_and_retest(ready):
    d = ready
    _open_crypto(d, "Randomness")
    d.wait_title("Randomness")
    d.select("Status")
    d.wait_title("Randomness")
    _find_text(d, "Not tested yet")
    _approve(d)
    d.wait_for(lambda s: s.choice == "Status")
    d.select("Run self-test")
    enter_pin(d)
    d.wait_title("Run self-test")
    _approve(d)
    d.wait_for(lambda s: s.choice == "Status")
    d.select("Status")
    d.wait_title("Randomness")
    _find_text(d, "Healthy")


@pytest.mark.parametrize("app", ["AES", "OpenPGP", "PIV", "Aléa"])
def test_french_management_menus(debug, app):
    onboard(debug, lang="Français")
    debug.wait_title("feuristic")
    debug.select("Cryptographie")
    debug.select(app)
    debug.wait_title(app)
    if app == "PIV":
        assert "PIN PIV par défaut" in " ".join(debug.screen().text().split())
        _approve(debug)
        debug.wait_for(lambda s: s.choice == "Identités")
    assert "Pas encore disponible" not in " ".join(debug.screen().text().split())
    debug.hold_left()
    debug.wait_title("Cryptographie")


def test_openpgp_local_generation_and_targeted_delete_visible_to_ccid(ready, emu):
    import socket

    from harness.emulator import PORT_VCP

    d = ready
    d.select("Settings")
    d.select("TOTP time")
    d.select("Sync over USB")
    emu.wait_ready(PORT_VCP, 20)
    now = int(time.time())
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
        stream.settimeout(20)
        stream.connect(("127.0.0.1", emu.port(PORT_VCP)))
        stream.send(f"TIME 1 {now}\n".encode())
        while True:
            reply = stream.recv(64)
            if reply != b"PONGPONG":
                assert reply == f"OK {now}\n".encode()
                break
    d.wait_title("TOTP time", timeout=20)
    d.hold_left()
    d.wait_title("Settings")
    d.hold_left()
    d.wait_title("feuristic")
    _open_crypto(d, "OpenPGP")
    d.select("Generate keys")
    d.select("Ed25519 / Curve25519")
    enter_pin(d)
    d.wait_title("Generate all three keys?")
    _approve(d, hold=True)
    d.wait_title("View keys", timeout=30)
    d.select("Signature")
    d.wait_title("Signature")
    _find_text(d, "Ed25519")
    _approve(d)
    d.wait_title("View keys")
    d.hold_left()
    d.wait_title("OpenPGP")
    with closing(CcidClient(emu.port(PORT_CCID))) as card:
        card.power_on()
        assert card.transmit(bytes.fromhex("00A4040006") + OPENPGP_AID)[1] == 0x9000
        fingerprints, sw = card.transmit(bytes.fromhex("00CA00C500"))
        assert sw == 0x9000 and len(fingerprints) == 60
        assert all(fingerprints[i : i + 20] != bytes(20) for i in (0, 20, 40))
        public, sw = card.transmit(bytes.fromhex("0047810002B60000"))
        assert sw == 0x9000 and public.startswith(bytes.fromhex("7F49"))
        d.select("Delete keys")
        d.select("Decryption")
        enter_pin(d)
        d.wait_title("Delete OpenPGP keys?")
        _approve(d, hold=True)
        d.wait_title("OpenPGP")
        after, sw = card.transmit(bytes.fromhex("00CA00C500"))
        assert sw == 0x9000
        assert after[:20] == fingerprints[:20]
        assert after[20:40] == bytes(20)
        assert after[40:] == fingerprints[40:]


def test_fido_service_account_protections_and_confirmed_delete(ready, emu):
    from concurrent.futures import ThreadPoolExecutor

    from fido2.ctap import CtapError
    from fido2.ctap2 import Ctap2
    from harness.emulator import PORT_FIDO
    from harness.fido import open_device

    d = ready
    device = open_device(emu.port(PORT_FIDO))
    try:
        ctap = Ctap2(device)
        with ThreadPoolExecutor(max_workers=1) as executor:
            pending = executor.submit(
                ctap.make_credential,
                b"\x55" * 32,
                {"id": "example.org", "name": "Example"},
                {"id": b"alice", "name": "alice"},
                [{"type": "public-key", "alg": -7}],
                options={"rk": True},
                extensions={"hmac-secret": True, "largeBlobKey": True},
            )
            d.wait_title("Create passkey?")
            _approve(d)
            credential_id = pending.result(30).auth_data.credential_data.credential_id
        d.wait_title("feuristic")
        d.select("Authentication")
        d.select("Passkeys")
        d.select("Services")
        d.select("example.org (1)")
        d.select("alice")
        d.select("Protection info")
        d.wait_title("Protection info")
        _find_text(d, "Presence only")
        _approve(d)
        d.wait_title("alice")
        d.select("Delete passkey")
        enter_pin(d)
        d.wait_title("Delete passkey?")
        d.hold_left()
        d.wait_title("alice")
        d.select("Delete passkey")
        enter_pin(d)
        d.wait_title("Delete passkey?")
        _approve(d, hold=True)
        d.wait_title("No passkey stored")
        with pytest.raises(CtapError) as exc:
            ctap.get_assertion("example.org", b"\x55" * 32, [{"type": "public-key", "id": credential_id}])
        assert exc.value.code == CtapError.ERR.NO_CREDENTIALS
    finally:
        device.close()


def _final_confirmation(debug, hold):
    for _ in range(40):
        screen = debug.screen()
        buttons = debug._buttons(screen)
        middle = buttons.get("middle_btn") or {}
        if middle.get("text") or middle.get("component") == "HoldToConfirm":
            assert (middle.get("component") == "HoldToConfirm") is hold
            assert not (buttons.get("right_btn") or {}).get("text")
            assert (buttons.get("right_btn") or {}).get("component") != "HoldToConfirm"
            return
        debug.right()
    raise AssertionError("no two-button confirmation on final page")


def test_confirmations_require_both_buttons_and_danger_requires_continuous_hold(ready):
    d = ready
    _open_crypto(d, "AES")
    d.select("Keys")
    d.wait_title("No AES key yet")
    _final_confirmation(d, hold=False)
    d.right()
    assert d.screen().title == "No AES key yet"
    from trezorlib import messages

    d._press(messages.DebugPhysicalButton.RIGHT_BTN, hold_ms=1300)
    assert d.screen().title == "No AES key yet"
    d.both()
    d.wait_title("AES")
    d.select("Delete all AES keys?")
    enter_pin(d)
    d.wait_title("Delete all AES keys?")
    _final_confirmation(d, hold=True)
    d.right()
    assert d.screen().title == "Delete all AES keys?"
    d.both()
    assert d.screen().title == "Delete all AES keys?"
    d.hold_both(300)
    assert d.screen().title == "Delete all AES keys?"
    d.hold_left()
    d.wait_title("AES")
    d.select("Delete all AES keys?")
    enter_pin(d)
    d.wait_title("Delete all AES keys?")
    _final_confirmation(d, hold=True)
    d.hold_both(2200)
    d.wait_title("AES")
