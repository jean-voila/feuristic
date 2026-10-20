# SPDX-License-Identifier: GPL-3.0-only
"""Device backup menus and independent encrypted-QR restore over real MSC."""

import binascii
import hashlib
import io
import struct
import time

import cbor2
import segno
from conftest import enter_pin
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from harness.ccid import CcidClient
from harness.emulator import PORT_CCID, PORT_MSC
from harness.msc import Fat12Writer, MscClient
from trezorlib import messages

PHRASE = "correct horse battery staple"


def _png(text):
    out = io.BytesIO()
    segno.make(text, error="m").save(out, kind="png", scale=5, border=4)
    return out.getvalue()


def _backup_frames(
    account="alice@example.com",
    bid=b"backup01",
    seq=None,
    count=None,
    item=None,
    chunk_size=156,
    created=None,
):
    """Independent format encoder: no firmware Python modules used."""
    salt, nonce = bytes(range(16)), bid + (seq or 0).to_bytes(4, "big")
    kind = 1 if seq is None else 2
    header = cbor2.dumps({1: kind, 2: bid, 3: 1, 4: 600000, 5: salt, 6: 1, 7: nonce}, canonical=True)
    aad = b"FEBK\x01" + len(header).to_bytes(2, "big") + header
    item = item or {
        "type": "otp",
        "v": 1,
        "kind": "totp",
        "issuer": "Example",
        "account": account,
        "secret": b"12345678901234567890",
        "algorithm": "SHA1",
        "digits": 6,
        "period": 30,
    }
    content = {"v": 1, "kind": "identity" if seq is None else "full", "items": [item]}
    if seq is not None:
        content.update(seq=seq, count=count)
    if created is not None:
        content["created"] = created
    plaintext = cbor2.dumps(content, canonical=True)
    key = hashlib.pbkdf2_hmac("sha256", PHRASE.encode(), salt, 600000)
    raw = aad + AESGCM(key).encrypt(nonce, plaintext, aad)
    total = (len(raw) + chunk_size - 1) // chunk_size
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
    texts = []
    for index in range(total):
        body = bid + (index + 1).to_bytes(2, "big") + total.to_bytes(2, "big")
        body += raw[index * chunk_size : (index + 1) * chunk_size]
        body += binascii.crc32(body).to_bytes(4, "big")
        encoded = ""
        for offset in range(0, len(body), 2):
            pair = body[offset : offset + 2]
            value = int.from_bytes(pair, "big")
            encoded += alphabet[value % 45] + alphabet[(value // 45) % 45]
            if len(pair) == 2:
                encoded += alphabet[value // 2025]
        texts.append("FB1:" + encoded)
    return texts


def _open_restore(debug, emu):
    debug.select("Backup")
    debug.wait_title("Backup")
    debug.select("Restore")
    emu.wait_ready(PORT_MSC, 20)
    msc = MscClient(emu.port(PORT_MSC))
    msc.start()
    return msc


def _paused_write(msc):
    """A physical BOT host sees OUT halt before sending write data."""
    tag = msc.tag
    msc.tag += 1
    cdb = b"\x2a\x00\x00\x00\x00\x19\x00\x00\x01\x00"
    cbw = struct.pack("<IIIBBB", 0x43425355, tag, 512, 0, 0, 10) + cdb.ljust(16, b"\0")
    msc._send_packet(cbw)
    stalled = False
    while True:
        frame = msc._recv_frame()
        if frame == b"\x03":
            stalled = True
        elif frame[:1] == b"\x00":
            sig, actual_tag, residue, status = struct.unpack("<IIIB", frame[1:])
            assert (sig, actual_tag, residue, status) == (0x53425355, tag, 512, 1)
            break
    assert stalled
    msc.clear_halt(False)
    sense = msc.request_sense()
    assert (sense[2] & 15, sense[12], sense[13]) == (2, 4, 7)


def _text_entry(debug, text, emu=None):
    try:
        debug.wait_for(lambda s: "PassphraseKeyboard" in tuple(s._find(s.data, "component")))
    except Exception:
        if emu is not None:
            raise AssertionError(emu.log()[-3000:]) from None
        raise
    debug.input(text)


def _approve_hold(debug):
    for _ in range(40):
        buttons = debug._buttons(debug.screen())
        right = buttons.get("right_btn") or {}
        if right.get("text") or right.get("component") == "HoldToConfirm":
            debug._press(messages.DebugPhysicalButton.RIGHT_BTN, hold_ms=2200)
            return
        middle = buttons.get("middle_btn") or {}
        if middle.get("text") or middle.get("component") == "HoldToConfirm":
            debug.hold_both(2200)
            return
        debug.right()
    raise AssertionError(f"no hold-to-confirm button: {debug.screen().data}")


def _qr_text(screen):
    for text in screen._find(screen.data, "text"):
        if isinstance(text, str) and text.startswith("FB1:"):
            return text
    return None


def _frame(text):
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
    encoded = text[4:]
    raw = b""
    for offset in range(0, len(encoded), 3):
        group = encoded[offset : offset + 3]
        value = sum(alphabet.index(ch) * 45**i for i, ch in enumerate(group))
        raw += value.to_bytes(2 if len(group) == 3 else 1, "big")
    assert binascii.crc32(raw[:-4]) == int.from_bytes(raw[-4:], "big")
    return int.from_bytes(raw[8:10], "big"), int.from_bytes(raw[10:12], "big"), raw[12:-4]


def _open_export(debug):
    debug.select("Export an identity")
    debug.wait_title("Choose identity type")
    debug.select("One-time passwords")
    debug.wait_title("One-time passwords")
    debug.both()
    debug.wait_title("QR readability")
    debug.select("Large modules")
    debug.wait_title("Export identity")
    _approve_hold(debug)
    debug.wait_title("Enter backup passphrase")
    debug.approve()
    _text_entry(debug, PHRASE)
    _text_entry(debug, PHRASE)
    enter_pin(debug)
    debug.wait_title("Backup", timeout=30)
    debug.approve()
    debug.wait_title("Identity 1 of 1")
    debug.approve()
    return debug.wait_for(lambda s: _qr_text(s) is not None, timeout=10)


def test_empty_backup_categories(ready):
    ready.select("Backup")
    ready.wait_title("Backup")
    ready.select("Export an identity")
    ready.wait_title("Nothing to export")
    ready.wait_title("Backup", timeout=10)


def test_restore_rejects_plain_otp_and_requires_eject(ready, emu):
    msc = _open_restore(ready, emu)
    try:
        uri = "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example"
        Fat12Writer(msc).write_file("OTP.PNG", _png(uri))
        ready.wait_for(lambda s: "Use OTP import" in s.text(), timeout=30)
        ready.hold_left()
        ready.wait_for(lambda s: "Eject" in s.text())
        ready.both()  # an acknowledgement must not detach MSC early
        time.sleep(0.3)
        assert msc.inquiry()[16:32] == b"FEURISTIC-IMPORT"
        assert msc.eject() == 0
    finally:
        msc.close()
    ready.wait_title("Backup", timeout=20)


def test_restore_fragmented_backup_then_export_and_cancel(ready, emu):
    msc = _open_restore(ready, emu)
    try:
        writer = Fat12Writer(msc)
        texts = _backup_frames()
        assert len(texts) > 1
        # Reverse order and a duplicate exercise actual image-decoder/MSC glue.
        writer.write_file("LAST.PNG", _png(texts[-1]))
        ready.wait_for(lambda s: "QR received" in s.text(), timeout=30)
        writer.write_file("DUP.PNG", _png(texts[-1]))
        ready.wait_for(lambda s: "Already received" in s.text(), timeout=30)
        for index, text in enumerate(texts[:-1]):
            writer.write_file(f"QR{index}.PNG", _png(text))
        ready.wait_for(lambda s: "Backup sequence" in s.text() and "complete" in s.text(), timeout=30)
        _paused_write(msc)  # refused immediately, no lost/acknowledged data
        ready.approve()  # explicit ready action, before phrase or writes
        _text_entry(ready, "incorrect backup passphrase", emu)
        try:
            ready.wait_title("Wrong passphrase", timeout=30)
        except Exception:
            raise AssertionError(emu.log()[-4000:]) from None
        _text_entry(ready, PHRASE, emu)
        ready.wait_title("Restore backup", timeout=30)
        ready.approve()
        ready.wait_for(lambda s: "copy was refused" in " ".join(s.text().split()), timeout=30)
        ready.approve()
        ready.wait_for(lambda s: "Copy all QR" in " ".join(s.text().split()), timeout=30)
        ready.approve()  # Done: finish this import session, then eject
        ready.wait_for(lambda s: "Eject" in s.text(), timeout=30)
        assert msc.eject() == 0
    finally:
        msc.close()
    ready.wait_title("Backup", timeout=20)
    first = _open_export(ready)
    text = _qr_text(first)
    index, total, chunk = _frame(text)
    assert index == 1 and total > 1
    # The first QR cannot finish an incomplete sequence.
    ready.both()
    ready.wait_title("View every QR before finishing")
    ready.approve()
    ready.wait_for(lambda s: _qr_text(s) == text)
    ready.right()
    ready.wait_for(lambda s: _qr_text(s) is not None and _frame(_qr_text(s))[0] == 2)
    ready.left()
    ready.wait_for(lambda s: _qr_text(s) == text)
    chunks = [chunk]
    for index in range(2, total + 1):
        ready.right()
        page = ready.wait_for(
            lambda s, index=index: _qr_text(s) is not None and _frame(_qr_text(s))[0] == index,
            timeout=10,
        )
        chunks.append(_frame(_qr_text(page))[2])
    ready.both()
    ready.wait_title("Backup", timeout=15)
    # Independently authenticate/decrypt the complete sequence displayed.
    raw = b"".join(chunks)
    hlen = int.from_bytes(raw[5:7], "big")
    off = 7 + hlen
    header = cbor2.loads(raw[7:off])
    key = hashlib.pbkdf2_hmac("sha256", PHRASE.encode(), header[5], 600000)
    restored = cbor2.loads(AESGCM(key).decrypt(header[7], raw[off:], raw[:off]))
    assert restored["items"][0]["secret"] == b"12345678901234567890"
    # A separate session can be cancelled directly from its first live QR.
    _open_export(ready)
    ready.hold_left()
    ready.wait_title("Backup", timeout=15)
    # A live QR must also disappear without input, after the real 60 s.
    _open_export(ready)
    started = time.monotonic()
    ready.wait_title("Backup", timeout=70)
    assert 58 <= time.monotonic() - started <= 68
    assert "RuntimeError: session closed" not in emu.log()


def test_restore_cancel_before_phrase_keeps_storage_empty(ready, emu):
    msc = _open_restore(ready, emu)
    try:
        writer = Fat12Writer(msc)
        for index, text in enumerate(_backup_frames()):
            writer.write_file(f"QR{index}.PNG", _png(text))
        ready.wait_for(lambda s: "Backup sequence" in s.text() and "complete" in s.text(), timeout=30)
        ready.hold_left()
        ready.wait_for(lambda s: "Eject" in s.text())
        assert msc.eject() == 0
    finally:
        msc.close()
    ready.wait_title("Backup", timeout=20)
    ready.select("Export an identity")
    ready.wait_title("Nothing to export")


def test_full_restore_streams_identities_reuses_phrase_and_warns_before_early_finish(ready, emu):
    msc = _open_restore(ready, emu)
    try:
        writer = Fat12Writer(msc)
        for index, text in enumerate(_backup_frames(seq=1, count=2)):
            writer.write_file(f"A{index}.PNG", _png(text))
        ready.wait_for(lambda s: "Backup sequence" in s.text() and "complete" in s.text(), timeout=30)
        ready.approve()
        _text_entry(ready, PHRASE)
        ready.wait_title("Incomplete full export", timeout=30)
        ready.approve()
        ready.wait_title("Restore backup")
        ready.approve()
        ready.wait_for(lambda s: "Copy all QR" in " ".join(s.text().split()), timeout=30)
        ready.approve()  # Done with one out of two identities must warn
        ready.wait_title("Incomplete full export")
        ready.hold_left()  # keep collecting the rest of the set
        ready.wait_for(lambda s: "Copy all QR" in " ".join(s.text().split()))
        assert msc.inquiry()[16:32] == b"FEURISTIC-IMPORT"
        for index, text in enumerate(_backup_frames("bob@example.com", b"backup02", 2, 2)):
            writer.write_file(f"B{index}.PNG", _png(text))
        ready.wait_for(lambda s: "Backup sequence" in s.text() and "complete" in s.text(), timeout=30)
        ready.approve()
        # Same salt: no second passphrase dialog or PBKDF2 session.
        ready.wait_title("Restore backup", timeout=10)
        ready.approve()
        ready.wait_for(lambda s: "Copy all QR" in " ".join(s.text().split()), timeout=30)
        ready.approve()
        ready.wait_for(lambda s: "Eject" in s.text(), timeout=10)
        assert msc.eject() == 0
    finally:
        msc.close()
    ready.wait_title("Backup", timeout=20)
    ready.select("Export an identity")
    ready.wait_title("Choose identity type")
    ready.select("One-time passwords")
    ready.wait_title("One-time passwords")
    assert "alice@example.com" in ready.screen().choice
    ready.right()
    assert "bob@example.com" in ready.screen().choice


def test_large_identity_survives_234_images_in_batches_on_64_entry_volume(ready, emu):
    # Maximal native OpenPGP schema, independently encoded/encrypted. A single
    # fixture RSA key is reused in its three roles; it is only public test data.
    numbers = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_numbers()
    secret = numbers.p.to_bytes(128, "big") + numbers.q.to_bytes(128, "big")
    key = {
        "attr": bytes.fromhex("010800002000"),
        "secret": secret,
        "fpr": b"f" * 20,
        "ca": b"c" * 20,
        "date": 0xFFFFFFFF,
        "origin": 1,
    }
    pin = {"kdf": 1_000_000, "salt": b"s" * 16, "hash": b"h" * 32, "len": 127}
    item = {
        "type": "openpgp",
        "v": 1,
        "keys": [key, key, key],
        "name": b"N" * 39,
        "lang": b"enfrdeen",
        "sex": b"9",
        "url": b"u" * 254,
        "login": b"l" * 254,
        "private": [bytes((i,)) * 254 for i in range(4)],
        "cert": b"c" * 2048,
        "pw1": pin,
        "pw3": pin,
        "rc": pin,
        "pw1_status": 0,
        "dsc": 0xFFFFFF,
    }
    texts = _backup_frames(item=item, seq=192, count=192, chunk_size=22, created=0xFFFFFFFF)
    assert len(texts) == 234
    msc = _open_restore(ready, emu)
    try:
        writer = Fat12Writer(msc)
        assert writer.root_entries == 64
        for start in range(0, len(texts), 32):
            end = min(start + 32, len(texts))
            names = []
            for index in range(start, end):
                name = f"QR{index:06}.PNG"  # short 8.3, no LFN directory entries
                writer.write_file(name, _png(texts[index]))
                names.append(name)
            if end < len(texts):
                progress = f"{end} of {len(texts)} QR received"
                ready.wait_for(lambda s, expected=progress: expected in s.text(), timeout=30)
                for name in names:
                    writer.delete_file(name)
                # Deletion and cluster reuse must not purge already received
                # frame bytes, or cause an IMPORT→NORMAL re-enumeration.
                assert msc.inquiry()[16:32] == b"FEURISTIC-IMPORT"
                assert f"{end} of {len(texts)} QR received" in ready.screen().text()
        ready.wait_for(lambda s: "Backup sequence" in s.text() and "complete" in s.text(), timeout=30)
        ready.approve()
        _text_entry(ready, PHRASE)
        ready.wait_title("Incomplete full export", timeout=30)
        ready.approve()
        ready.wait_title("Restore backup")
        ready.approve()
        ready.wait_for(lambda s: "1 identities restored" in s.text(), timeout=30)
        ready.approve()
        ready.wait_title("Incomplete full export")
        ready.approve()
        ready.wait_for(lambda s: "Eject" in s.text(), timeout=10)
        assert msc.eject() == 0
    finally:
        msc.close()
    ready.wait_title("Backup", timeout=20)
    # A real application read confirms that the authenticated assembled item
    # reached protected storage, rather than only showing a progress counter.
    emu.wait_ready(PORT_CCID, 20)
    card = CcidClient(emu.port(PORT_CCID))
    try:
        card.power_on()
        assert card.transmit(bytes.fromhex("00A4040006D27600012401"))[1] == 0x9000
        cert, sw = card.transmit(bytes.fromhex("00CA7F2100"))
        assert sw == 0x9000 and cert == item["cert"]
        pub, sw = card.transmit(bytes.fromhex("0047810002B60000"))
        assert sw == 0x9000 and numbers.public_numbers.n.to_bytes(256, "big") in pub
    finally:
        card.close()
