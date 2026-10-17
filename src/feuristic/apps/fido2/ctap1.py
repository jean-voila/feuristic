# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""FIDO U2F (CTAP1) raw messages over CTAPHID_MSG.

References: FIDO U2F Raw Message Formats v1.2 (§4 registration, §5
authentication, §6 version), FIDO U2F HID Protocol v1.2 (ISO 7816-4 APDU
framing, short and extended length encodings), CTAP 2.1 §10 (interoperation
of CTAP2 credentials with U2F).

* REGISTER (INS 0x01): P-256 key wrapped into a 61-byte key handle with
  ``fido2/u2f-wrap`` (AES-256-GCM, AAD = application parameter, see
  :mod:`.credentials`). Attestation: per-credential *self attestation*
  certificate (:mod:`.x509`) — no vendor key, no cross-RP identifier.
* AUTHENTICATE (INS 0x02): control byte 0x07 check-only (6985 if the key
  handle is ours, 6A80 otherwise), 0x03 enforce-user-presence-and-sign,
  0x08 dont-enforce-user-presence-and-sign. CTAP2 credentials (ES256,
  credProtect level 1) are accepted too (CTAP 2.1 §10.2).
* VERSION (INS 0x03): ``"U2F_V2"``.

User presence follows the U2F polling model: a request needing presence
returns SW_CONDITIONS_NOT_SATISFIED (6985) at once and arms a *presence
latch*; the firmware glue runs the confirmation dialog concurrently
(:meth:`U2f.dialog_job`); the host's next identical request (browsers
re-poll every ~200 ms) consumes the approval. A refused dialog answers the
next identical request with CTAPHID ERROR CHANNEL_BUSY, which stops
Chrome's polling (same behaviour as upstream Trezor firmware).

Firefox's / Chrome's "dummy" registrations (application parameter
``"A" * 32``, all zeros, or SHA-256("make.me.blink")) — sent to let the
user pick a token while telling them it is (not) registered — show an
informational prompt and then complete normally with a throw-away
stateless key handle.
"""

from micropython import const

from ...core.errors import UserCancelled, UserTimeout
from ...core.interaction import NORMAL, SENSITIVE, Prompt
from ...platform import crypto
from ...platform import time as ptime
from . import credentials as cr
from . import x509
from .status import CTAP1_ERR_CHANNEL_BUSY

INS_REGISTER = const(0x01)
INS_AUTHENTICATE = const(0x02)
INS_VERSION = const(0x03)

SW_NO_ERROR = const(0x9000)
SW_WRONG_LENGTH = const(0x6700)
SW_CONDITIONS_NOT_SATISFIED = const(0x6985)
SW_WRONG_DATA = const(0x6A80)
SW_INS_NOT_SUPPORTED = const(0x6D00)
SW_CLA_NOT_SUPPORTED = const(0x6E00)

AUTH_ENFORCE = const(0x03)
AUTH_CHECK_ONLY = const(0x07)
AUTH_DONT_ENFORCE = const(0x08)

REGISTER_ID = const(0x05)
U2F_FLAG_UP = const(0x01)

# CTAPHID command bytes (without the 0x80 init bit) of the responses
HID_MSG = const(0x03)
HID_ERROR = const(0x3F)

POLL_WINDOW_MS = const(3_000)
DIALOG_TIMEOUT_MS = const(30_000)

BOGUS_APPIDS = (
    b"A" * 32,  # Chrome
    bytes(32),  # Firefox
    # SHA-256("make.me.blink"), Firefox authenticator-rs
    b"\xe8\x45\x41\xea\xf2\x07\xf7\xd7\x5a\xd0\x51\x43\x47\x70\xf6\xd1"
    b"\xa9\xbf\x62\xf7\xea\x9b\xe5\x14\xfd\x4e\x0c\xa8\x27\x2b\x1d\xeb",
)

_IDLE = const(0)
_PENDING = const(1)  # dialog requested, not started by the glue yet
_RUNNING = const(2)
_CONFIRMED = const(3)
_DENIED = const(4)


class ApduError(Exception):
    def __init__(self, sw: int) -> None:
        super().__init__(sw)
        self.sw = sw


def sw_bytes(sw: int) -> bytes:
    return bytes((sw >> 8, sw & 0xFF))


def parse_apdu(apdu) -> tuple:
    """Return ``(cla, ins, p1, p2, data)`` of a short or extended APDU."""
    apdu = bytes(apdu)
    if len(apdu) < 4:
        raise ApduError(SW_WRONG_LENGTH)
    cla, ins, p1, p2 = apdu[0], apdu[1], apdu[2], apdu[3]
    rest = apdu[4:]
    if not rest:
        data = b""
    elif rest[0] == 0 and len(rest) >= 3:
        # extended length: 00 Lc1 Lc2 data [Le1 Le2]  or  00 Le1 Le2
        lc = (rest[1] << 8) | rest[2]
        if len(rest) == 3:
            data = b""
        else:
            data = rest[3 : 3 + lc]
            trailing = len(rest) - 3 - lc
            if len(data) != lc or trailing not in (0, 2):
                raise ApduError(SW_WRONG_LENGTH)
    elif len(rest) == 1:
        data = b""  # short Le only
    else:
        lc = rest[0]
        data = rest[1 : 1 + lc]
        trailing = len(rest) - 1 - lc
        if len(data) != lc or trailing not in (0, 1):
            raise ApduError(SW_WRONG_LENGTH)
    return cla, ins, p1, p2, data


class U2f:
    """U2F message handler bound to an :class:`~.ctap2.Authenticator`."""

    def __init__(self, auth) -> None:
        self.auth = auth
        self._clear()

    # -- presence latch --------------------------------------------------------
    def _clear(self) -> None:
        self._state = _IDLE
        self._key = None
        self._prompt = None
        self._touched = 0

    def reset_dialog(self) -> None:
        """Forget any pending U2F approval (another command took over)."""
        self._clear()

    def dialog_pending(self) -> bool:
        return self._state == _PENDING

    def dialog_stale(self) -> bool:
        """True when the host stopped polling for the running dialog (the glue
        may then close the dialog task)."""
        return (
            self._state in (_PENDING, _RUNNING)
            and ptime.ticks_diff(ptime.ticks_ms(), self._touched) >= POLL_WINDOW_MS
        )

    def dialog_job(self):
        """Coroutine running the pending confirmation dialog, or ``None``."""
        if self._state != _PENDING:
            return None
        self._state = _RUNNING
        return self._run_dialog(self._key, self._prompt)

    async def _run_dialog(self, key, prompt) -> None:
        try:
            ok = bool(await self.auth.ctx.ui.confirm(prompt))
        except (UserTimeout, UserCancelled):
            ok = False
        if self._key == key and self._state == _RUNNING:
            self._state = _CONFIRMED if ok else _DENIED
            self._touched = ptime.ticks_ms()

    def _presence(self, key: bytes, prompt: Prompt) -> int:
        now = ptime.ticks_ms()
        live = ptime.ticks_diff(now, self._touched) < POLL_WINDOW_MS
        if self._key == key and live:
            if self._state == _CONFIRMED:
                self._clear()
                return _CONFIRMED
            if self._state == _DENIED:
                return _DENIED
            self._touched = now
            return _PENDING
        if self._state in (_PENDING, _RUNNING) and live:
            return _PENDING  # another request's dialog is on screen
        self._state = _PENDING
        self._key = key
        self._prompt = prompt
        self._touched = now
        return _PENDING

    # -- dispatcher ------------------------------------------------------------
    def handle(self, apdu) -> tuple:
        """Process one CTAPHID_MSG payload; return ``(hid_cmd, payload)``."""
        try:
            cla, ins, p1, _p2, data = parse_apdu(apdu)
            if cla != 0:
                raise ApduError(SW_CLA_NOT_SUPPORTED)
            if ins == INS_REGISTER:
                return self._register(data)
            if ins == INS_AUTHENTICATE:
                return self._authenticate(p1, data)
            if ins == INS_VERSION:
                if data:
                    raise ApduError(SW_WRONG_LENGTH)
                return HID_MSG, b"U2F_V2" + sw_bytes(SW_NO_ERROR)
            raise ApduError(SW_INS_NOT_SUPPORTED)
        except ApduError as e:
            return HID_MSG, sw_bytes(e.sw)

    @staticmethod
    def _rp_label(cred, app_param: bytes) -> str:
        if cred is not None and cred.rp_id:
            return cred.rp_id
        return app_param[:8].hex()

    def _register(self, data: bytes) -> tuple:
        if len(data) != 64:
            raise ApduError(SW_WRONG_LENGTH)
        challenge = data[:32]
        app_param = data[32:]
        if app_param in BOGUS_APPIDS:
            title = (
                "fido2.title.already_registered"
                if self.auth.last_auth_valid
                else "fido2.title.not_registered"
            )
            prompt = Prompt("fido2.u2f_bogus", title, (), NORMAL, DIALOG_TIMEOUT_MS)
        else:
            prompt = Prompt(
                "fido2.u2f_register",
                "fido2.title.u2f_register",
                (("fido2.rp", self._rp_label(None, app_param)),),
                SENSITIVE,
                DIALOG_TIMEOUT_MS,
            )
        r = self._presence(crypto.sha256(b"\x01" + data), prompt)
        if r == _PENDING:
            raise ApduError(SW_CONDITIONS_NOT_SATISFIED)
        if r == _DENIED:
            return HID_ERROR, bytes((CTAP1_ERR_CHANNEL_BUSY,))
        key = crypto.p256_generate()
        kh = self.auth.store.u2f_wrap(app_param, key)
        pub = crypto.p256_public(key)
        cert = x509.self_signed_p256(key)
        sig = crypto.ecdsa_sig_to_der(
            crypto.p256_sign_digest(key, crypto.sha256(b"\x00" + app_param + challenge + kh + pub))
        )
        return HID_MSG, (
            bytes((REGISTER_ID,)) + pub + bytes((len(kh),)) + kh + cert + sig + sw_bytes(SW_NO_ERROR)
        )

    def _authenticate(self, p1: int, data: bytes) -> tuple:
        if len(data) < 65 or len(data) != 65 + data[64]:
            raise ApduError(SW_WRONG_LENGTH)
        challenge = data[:32]
        app_param = data[32:64]
        kh = data[65:]
        cred = self.auth.store.lookup(kh, app_param)
        if cred is not None and (cred.alg != cr.ALG_ES256 or cred.cred_protect != cr.PROTECT_UV_OPTIONAL):
            cred = None  # CTAP 2.1 §10.2: only unprotected ES256 credentials
        self.auth.last_auth_valid = cred is not None
        if cred is None:
            raise ApduError(SW_WRONG_DATA)
        if p1 == AUTH_CHECK_ONLY:
            raise ApduError(SW_CONDITIONS_NOT_SATISFIED)
        if p1 == AUTH_ENFORCE:
            prompt = Prompt(
                "fido2.u2f_authenticate",
                "fido2.title.u2f_sign_in",
                (("fido2.rp", self._rp_label(cred, app_param)),),
                SENSITIVE,
                DIALOG_TIMEOUT_MS,
            )
            r = self._presence(crypto.sha256(b"\x02" + data), prompt)
            if r == _PENDING:
                raise ApduError(SW_CONDITIONS_NOT_SATISFIED)
            if r == _DENIED:
                return HID_ERROR, bytes((CTAP1_ERR_CHANNEL_BUSY,))
            flags = U2F_FLAG_UP
        elif p1 == AUTH_DONT_ENFORCE:
            flags = 0
        else:
            raise ApduError(SW_WRONG_DATA)
        counter = self.auth.state.next_signature_counter().to_bytes(4, "big")
        sig = cred.sign(app_param + bytes((flags,)) + counter + challenge)
        return HID_MSG, bytes((flags,)) + counter + sig + sw_bytes(SW_NO_ERROR)
