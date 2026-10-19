# SPDX-License-Identifier: GPL-3.0-only
"""R09/R10/R11 interop: real GnuPG, OpenSC and PC/SC tools against the emulator.

Requires Linux with pcscd, vsmartcard-vpcd, opensc, gnupg/scdaemon (CI job
"interop"); enable with FEURISTIC_INTEROP=1. The emulated CCID reader is
bridged into pcscd by tools/vpcd_bridge.py.
"""

import os
import selectors
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest
from harness.emulator import PORT_CCID

pytestmark = [
    pytest.mark.interop,
    pytest.mark.skipif(os.environ.get("FEURISTIC_INTEROP") != "1", reason="set FEURISTIC_INTEROP=1"),
]

ROOT = Path(__file__).resolve().parents[3]


def run(*cmd, env=None, timeout=60, check=True):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env, check=False)
    if check and r.returncode != 0:
        raise AssertionError(f"{cmd} failed ({r.returncode}):\n{r.stdout}\n{r.stderr}")
    return r.stdout + r.stderr


@pytest.fixture
def reader(ready, emu):
    bridge = subprocess.Popen(
        [sys.executable, str(ROOT / "tools" / "vpcd_bridge.py"), "--ccid-port", str(emu.port(PORT_CCID))]
    )
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            out = run("opensc-tool", "--list-readers", check=False)
            if "Virtual PCD" in out and "Yes" in out:
                break
            time.sleep(0.5)
        else:
            raise AssertionError("virtual reader never showed a card:\n" + out)
        yield ready
    finally:
        bridge.terminate()
        bridge.wait(10)


@pytest.fixture
def gnupg_home():
    d = tempfile.mkdtemp(prefix="feuristic-gnupg-")
    Path(d, "scdaemon.conf").write_text("disable-ccid\npcsc-shared\ncard-timeout 5\n")
    env = dict(os.environ, GNUPGHOME=d)
    yield env
    run("gpgconf", "--kill", "all", env=env, check=False)
    shutil.rmtree(d, ignore_errors=True)


def test_get_challenge_with_opensc_tool(reader):
    out = run("opensc-tool", "-s", "00 84 00 00 20")
    assert "90 00" in out.replace("SW1=0x90, SW2=0x00", "90 00")


def test_gnupg_card_status(reader, gnupg_home):
    out = run("gpg", "--card-status", env=gnupg_home)
    assert "OpenPGP" in out
    assert "Version ..........: 3.4" in out or "3.4" in out


def gpg_interactive(args, answers, env, timeout=300):
    """Drive gpg through --command-fd/--status-fd: ``answers`` maps a prompt
    keyword (e.g. ``cardedit.prompt``) to a list of replies consumed in order."""
    proc = subprocess.Popen(
        ["gpg", "--no-tty", "--command-fd", "0", "--status-fd", "1", "--pinentry-mode", "loopback", *args],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
    )
    transcript = []
    pending = b""
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise AssertionError("GnuPG timed out:\n" + "".join(transcript)[-4000:])
                chunk = os.read(proc.stdout.fileno(), 4096)
                if not chunk:
                    break
                pending += chunk
                while b"\n" in pending:
                    raw, pending = pending.split(b"\n", 1)
                    line = raw.decode(errors="replace") + "\n"
                    transcript.append(line)
                    parts = line.split()
                    if (
                        len(parts) >= 3
                        and parts[0] == "[GNUPG:]"
                        and parts[1] in ("GET_LINE", "GET_HIDDEN", "GET_BOOL")
                    ):
                        queue = answers.get(parts[2])
                        reply = queue.pop(0) if queue else ("n" if parts[1] == "GET_BOOL" else "")
                        proc.stdin.write((reply + "\n").encode())
                        proc.stdin.flush()
        transcript.append(pending.decode(errors="replace"))
        assert proc.wait(10) == 0, "".join(transcript)[-4000:]
        return "".join(transcript)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(10)


def test_gnupg_generate_and_sign(reader, gnupg_home):
    """Generate on the card with GnuPG's normal flow (admin PIN + device confirmation)."""
    stop = threading.Event()

    def approve():
        while not stop.is_set():
            s = reader.screen()
            if s.title not in ("", "feuristic") and s.component != "PinKeyboard":
                reader.approve()
            stop.wait(0.3)

    t = threading.Thread(target=approve, daemon=True)
    t.start()
    try:
        out = gpg_interactive(
            ["--card-edit"],
            {
                "cardedit.prompt": ["admin", "generate", "quit"],
                "cardedit.genkeys.backup_enc": ["n"],
                "cardedit.genkeys.replace_keys": ["y"],
                "passphrase.enter": ["123456", "12345678", "123456", "123456"],
                "keygen.valid": ["0"],
                "keygen.name": ["Feu Test"],
                "keygen.email": ["feu@example.com"],
                "keygen.comment": [""],
            },
            gnupg_home,
        )
        assert "KEY_CREATED" in out, out[-4000:]
        sig = subprocess.run(
            ["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "123456", "--sign", "-a"],
            input="hello feuristic",
            capture_output=True,
            text=True,
            timeout=120,
            env=gnupg_home,
            check=False,
        )
        assert "BEGIN PGP MESSAGE" in sig.stdout, sig.stderr
        ver = subprocess.run(
            ["gpg", "--verify"],
            input=sig.stdout,
            capture_output=True,
            text=True,
            timeout=60,
            env=gnupg_home,
            check=False,
        )
        assert "Good signature" in ver.stderr
    finally:
        stop.set()
        t.join(10)
        assert not t.is_alive(), "GnuPG approval worker did not finish"


def test_opensc_piv_detected(reader):
    out = run("pkcs15-tool", "--dump", check=False)
    assert "PIV" in out
