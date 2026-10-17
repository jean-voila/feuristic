# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""In-process FIDO2 device simulator for python-fido2.

The simulated device is the real feuristic stack: CTAPHID state machine
(:class:`CtapHid`) + :class:`HidServer` + :class:`Fido2App`. Coroutines are
driven by a tiny cooperative loop: the test interaction may ``await
Sleep(ms)``, which advances the fake platform clock and lets the CTAPHID
layer emit keepalives / time out, while python-fido2 keeps reading packets
through :class:`SimConnection` (a ``CtapHidConnection``), so the unmodified
``Ctap2``, ``ClientPin``, ``CredentialManagement``, ``LargeBlobs`` and
``Ctap1`` classes run against it.
"""

from collections import deque

from fido2.hid import CtapHidDevice
from fido2.hid.base import CtapHidConnection, HidDescriptor

from feuristic.apps.fido2.app import Fido2App
from feuristic.apps.fido2.context import Context
from feuristic.apps.fido2.ctaphid import CtapHid, HidServer
from feuristic.core.errors import UserTimeout
from feuristic.core.interaction import Interaction
from feuristic.platform import testing

MS = bytes(range(32))


class Sleep:
    def __init__(self, ms: int) -> None:
        self.ms = ms

    def __await__(self):
        yield self


class SimUI(Interaction):
    """Scripted interaction. Answers (consumed by confirm and select):

    * ``True`` / ``False`` / int / ``None`` — immediate answer;
    * ``("wait", ms, answer)`` — answer after ``ms`` of (simulated) time;
    * ``"hang"`` — wait until the host cancels (then refuse), at most 60 s;
    * ``"timeout"`` — raise :class:`UserTimeout`;
    * ``"slow-false"`` — refuse after the prompt timeout elapsed.
    """

    def __init__(self, answers=(), default=True) -> None:
        self.answers = list(answers)
        self.default = default
        self.prompts = []
        self.selects = []
        self.notifications = []
        self.cancelled = lambda: False

    def push(self, *answers) -> None:
        self.answers.extend(answers)

    def kinds(self) -> list:
        return [p.kind for p in self.prompts]

    async def _resolve(self, ans, timeout_ms=30_000):
        if isinstance(ans, tuple) and ans and ans[0] == "wait":
            waited = 0
            while waited < ans[1]:
                if self.cancelled():
                    return False
                await Sleep(100)
                waited += 100
            return ans[2]
        if ans == "hang":
            waited = 0
            while waited < 60_000:
                if self.cancelled():
                    return False
                await Sleep(100)
                waited += 100
            return False
        if ans == "timeout":
            raise UserTimeout
        if ans == "slow-false":
            await Sleep(timeout_ms)
            return False
        return ans

    async def confirm(self, prompt) -> bool:
        self.prompts.append(prompt)
        ans = self.answers.pop(0) if self.answers else self.default
        return await self._resolve(ans, prompt.timeout_ms)

    async def select(self, title, options, timeout_ms=30_000):
        self.selects.append((title, list(options)))
        if self.answers:
            ans = self.answers.pop(0)
        else:
            ans = 0 if self.default else None
        return await self._resolve(ans, timeout_ms)

    async def notify(self, kind, title, fields=()) -> None:
        self.notifications.append((kind, title, tuple(fields)))


def now() -> int:
    return testing.CLOCK.now_ms()


class Device:
    """The simulated authenticator (storage persists across power cycles)."""

    def __init__(self, ui=None, ms=MS, wink=True) -> None:
        self.ms = ms
        self.ui = ui if ui is not None else SimUI()
        self.wink = wink
        self.out = deque()
        self.jobs = []
        self.power_cycle()

    def power_cycle(self) -> None:
        self.ctx = Context(self.ms, self.ui)
        self.app = Fido2App(self.ctx)
        self.hid = CtapHid(version=(0, 1, 0), wink=self.wink)
        self.server = HidServer(self.hid, self.app)
        self.ui.cancelled = self.server.cancel_requested
        self.out.clear()
        self.jobs = []

    @property
    def auth(self):
        return self.app.auth

    # -- packet I/O --------------------------------------------------------------
    def _drain(self) -> None:
        self.out.extend(self.server.packets())

    def _start_jobs(self) -> None:
        while True:
            job = self.server.next_job()
            if job is None:
                return
            self.jobs.append(job)

    def write(self, pkt: bytes) -> None:
        self.server.feed(pkt, now())
        self._drain()
        self._start_jobs()

    def step(self) -> None:
        for job in list(self.jobs):
            try:
                y = job.send(None)
            except StopIteration:
                self.jobs.remove(job)
                self._drain()
                self._start_jobs()
                continue
            assert isinstance(y, Sleep), y
            testing.CLOCK.advance(y.ms)
            self.server.poll(now())
            self._drain()

    def run_until_idle(self, max_steps: int = 100_000) -> None:
        n = 0
        while self.jobs and n < max_steps:
            self.step()
            n += 1

    def read(self, max_steps: int = 100_000) -> bytes:
        n = 0
        while not self.out:
            if not self.jobs:
                raise TimeoutError("device idle: no packet to read")
            self.step()
            n += 1
            if n > max_steps:
                raise TimeoutError("device busy for too long")
        return self.out.popleft()

    def read_all(self) -> list:
        self.run_until_idle()
        self._drain()
        out = list(self.out)
        self.out.clear()
        return out

    def advance(self, ms: int) -> None:
        testing.CLOCK.advance(ms)
        self.server.poll(now())
        self._drain()


class SimConnection(CtapHidConnection):
    def __init__(self, device: Device) -> None:
        self.device = device

    def write_packet(self, data: bytes) -> None:
        assert len(data) == 64
        self.device.write(data)

    def read_packet(self) -> bytes:
        return self.device.read()

    def close(self) -> None:
        return


def open_hid(device: Device) -> CtapHidDevice:
    desc = HidDescriptor("feuristic-sim", 0x1209, 0x0001, 64, 64, "feuristic security key", "sim")
    return CtapHidDevice(desc, SimConnection(device))


# -- raw CTAPHID helpers ---------------------------------------------------------


def init_packet(cid: int, cmd: int, data: bytes = b"", bcnt=None) -> bytes:
    n = len(data) if bcnt is None else bcnt
    p = cid.to_bytes(4, "big") + bytes((0x80 | cmd, n >> 8, n & 0xFF)) + data[:57]
    return p + bytes(64 - len(p))


def cont_packet(cid: int, seq: int, data: bytes) -> bytes:
    p = cid.to_bytes(4, "big") + bytes((seq,)) + data[:59]
    return p + bytes(64 - len(p))


def frames(cid: int, cmd: int, data: bytes) -> list:
    out = [init_packet(cid, cmd, data)]
    off = 57
    seq = 0
    while off < len(data):
        out.append(cont_packet(cid, seq, data[off : off + 59]))
        off += 59
        seq += 1
    return out


def parse_response(packets: list) -> tuple:
    """Reassemble one response: ``(cid, cmd, payload)`` (first message only)."""
    first = packets[0]
    cid = int.from_bytes(first[:4], "big")
    cmd = first[4] & 0x7F
    n = (first[5] << 8) | first[6]
    data = first[7 : 7 + n]
    for p in packets[1:]:
        if len(data) >= n:
            break
        data += p[5 : 5 + n - len(data)]
    return cid, cmd, data[:n]


def allocate_channel(device: Device, nonce: bytes = b"12345678") -> int:
    device.write(init_packet(0xFFFFFFFF, 0x06, nonce))
    pkt = device.read()
    assert pkt[:4] == b"\xff\xff\xff\xff" and pkt[4] == 0x86
    assert pkt[7:15] == nonce
    return int.from_bytes(pkt[15:19], "big")


# -- CTAP2 helpers -----------------------------------------------------------------

import hashlib  # noqa: E402

RP = {"id": "example.com", "name": "Example"}
USER = {"id": b"user-1", "name": "alice", "displayName": "Alice A."}
ES256 = {"type": "public-key", "alg": -7}
EDDSA = {"type": "public-key", "alg": -8}


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


CDH = sha256(b"client data")


def make(ctap2, rp=None, user=None, algs=(ES256,), rk=False, **kw):
    options = kw.pop("options", None)
    if rk:
        options = dict(options or {}, rk=True)
    return ctap2.make_credential(
        kw.pop("cdh", CDH), rp or RP, user or USER, list(algs), options=options, **kw
    )


def descriptor(att) -> dict:
    return {"type": "public-key", "id": att.auth_data.credential_data.credential_id}


def verify_attestation(att, cdh=CDH) -> None:
    """packed self attestation: signed with the credential key."""
    assert att.fmt == "packed"
    pk = att.auth_data.credential_data.public_key
    assert att.att_stmt["alg"] == pk.ALGORITHM
    assert "x5c" not in att.att_stmt
    pk.verify(bytes(att.auth_data) + cdh, att.att_stmt["sig"])


def aio_run(coro):
    """Drive a coroutine to completion (``Sleep`` advances the fake clock)."""
    try:
        while True:
            y = coro.send(None)
            assert isinstance(y, Sleep), y
            testing.CLOCK.advance(y.ms)
    except StopIteration as e:
        return e.value
