# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""feuristic AES-256-GCM / RNG cryptographic profile v1 (ISO/IEC 7816-8).

Normative description: ``docs/protocols/aes-gcm-iso7816-v1.md`` (spec §2.1
requires the key-selection and parameter encodings to be published and
versioned). Summary:

* AID ``F0 66 65 75 72 69 73 74 69 63 01`` — category ``F`` (proprietary,
  unregistered, ISO/IEC 7816-4 §12.2.3) ‖ ASCII ``feuristic`` ‖ profile
  version ``01``.
* ``MANAGE SECURITY ENVIRONMENT`` SET (``00 22 81 B8`` encipherment /
  ``00 22 41 B8`` decipherment / ``00 22 F1 B8`` both, ISO/IEC 7816-4 §11.5.11
  P1 semantics) with a confidentiality template: ``80 01 47`` (algorithm
  reference: AES-256-GCM, optional) and ``83 01 kid`` or ``84 01 kid``
  (key identifier 1..16).
* ``PERFORM SECURITY OPERATION`` ENCIPHER ``00 2A 84 80`` with data
  ``[81 AAD] 80 plaintext`` → ``82 nonce(12) 80 ciphertext 83 tag(16)``;
  DECIPHER ``00 2A 80 84`` with data ``[81 AAD] 82 nonce 80 ciphertext
  83 tag`` → plaintext, released **only after the tag verifies** (spec §7).
* The nonce is never chosen by the host (a ``82`` in ENCIPHER → ``6A80``):
  see :mod:`feuristic.apps.card.aes.keys` for its construction.
* Limits: plaintext/ciphertext ≤ :data:`MAX_MESSAGE` bytes, AAD ≤
  :data:`MAX_AAD` bytes (one operation ≤ 3840 data bytes, so every command
  fits the dispatcher's 4096-byte de-chained data limit); input arrives by
  command chaining and long output leaves by response chaining (both handled
  by the dispatcher).
* ``GET CHALLENGE`` ``00 84 00 00 Le`` (Le 1..32) through
  :mod:`feuristic.apps.card.aes.rng`.

Security decisions (documented in the annex §8):

* No separate AES PIN: AES keys live in the PIN-protected storage (device
  unlocked with the device PIN, spec §10.1) and every operation, or the
  first one of a card session per key policy, is confirmed **on the
  device**. A host-entered AES PIN would be typed on the (possibly
  compromised) host and add nothing against malware already in the session;
  the physical confirmation does.
* "Session" = until the card is reset (``Applet.reset``: device lock,
  USB re-enumeration, power loss) or any AES key changes.
"""

from micropython import const

from ....core import tlv
from ....core.errors import InvalidInput, StorageCorrupted, StorageFull
from ....core.i18n import t
from ....core.interaction import SENSITIVE, Prompt
from ....platform import crypto
from .. import apdu
from ..apdu import ApduError, Response
from ..applet import Applet
from . import keys as _keys
from . import rng as _rng
from . import strings
from .const import AID

strings.register()

PROFILE_VERSION = const(1)
ALG_AES256_GCM = const(0x47)

INS_MSE = const(0x22)
INS_PSO = const(0x2A)
INS_GET_CHALLENGE = const(0x84)

MSE_SET_ENCIPHER = const(0x81)  # SET for verification/encipherment/external auth/key agreement
MSE_SET_DECIPHER = const(0x41)  # SET for computation/decipherment/internal auth/key agreement
MSE_SET_BOTH = const(0xF1)
CRT_CT = const(0xB8)  # confidentiality template

PSO_ENCIPHER = const(0x8480)
PSO_DECIPHER = const(0x8084)

TAG_PLAIN_OR_CIPHER = const(0x80)
TAG_AAD = const(0x81)
TAG_NONCE = const(0x82)
TAG_TAG = const(0x83)

MAX_MESSAGE = const(3584)
MAX_AAD = const(256)
NONCE_LEN = const(12)
TAG_LEN = const(16)

#: tag verification failed (ISO 7816-4 class 69 "command not allowed":
#: integrity check of the protected data failed). No plaintext is released.
SW_AUTH_TAG_FAILED = const(0x6988)

_ENC = const(0)
_DEC = const(1)


def _sw(sw: int):
    raise ApduError(sw)


def _fields(data: bytes, allowed) -> dict:
    out = {}
    for tag, value in tlv.iterate(data):
        if tag not in allowed or tag in out:
            _sw(apdu.SW_WRONG_DATA)
        out[tag] = value
    return out


def select_response() -> bytes:
    """FCI: ``6F { 84 AID, A5 { 80 version, 81 alg, 82 max msg, 83 max AAD, 84 keys, 85 challenge } }``."""
    prop = (
        tlv.build(0x80, bytes((PROFILE_VERSION,)))
        + tlv.build(0x81, bytes((ALG_AES256_GCM,)))
        + tlv.build(0x82, MAX_MESSAGE.to_bytes(2, "big"))
        + tlv.build(0x83, MAX_AAD.to_bytes(2, "big"))
        + tlv.build(0x84, bytes((_keys.MAX_KEYS,)))
        + tlv.build(0x85, bytes((_rng.MAX_CHALLENGE,)))
    )
    return tlv.build(0x6F, tlv.build(0x84, AID) + tlv.build(0xA5, prop))


class AesApplet(Applet):
    AID = AID
    EXACT_SELECT = False
    NAME = "aes"

    def __init__(self, ui, store=None, master_secret=None, rng=None) -> None:
        """``store``: :class:`~feuristic.apps.card.aes.keys.AesKeyStore`;
        ``master_secret``: 32 bytes or a callable returning them (nonce
        prefix derivation); ``rng``: :class:`~feuristic.apps.card.aes.rng.RngService`."""
        super().__init__(ui)
        self._store = store
        self._ms = master_secret
        self._rng = rng
        self._env = [None, None]  # per direction: key id
        self._session_ok = set()  # key ids confirmed for this card session
        self._epoch = None

    @property
    def store(self):
        return _keys.default() if self._store is None else self._store

    @property
    def rng(self):
        return _rng.default() if self._rng is None else self._rng

    def deselect(self) -> None:
        self._env = [None, None]

    def reset(self) -> None:
        self.deselect()
        self._session_ok = set()

    async def select(self, cmd) -> Response:
        if cmd.p2 == 0x0C:
            return Response()
        return Response(select_response())

    # -- dispatch ------------------------------------------------------------------
    async def process(self, cmd) -> Response:
        try:
            return await self._dispatch(cmd)
        except ApduError as e:
            return Response(b"", e.sw)
        except StorageFull:
            return Response(b"", apdu.SW_NOT_ENOUGH_MEMORY)
        except StorageCorrupted:
            return Response(b"", apdu.SW_MEMORY_FAILURE)
        except InvalidInput:
            return Response(b"", apdu.SW_WRONG_DATA)

    async def _dispatch(self, cmd) -> Response:
        cla = cmd.cla & 0xEF
        if cla & 0x0C:
            _sw(apdu.SW_SECURE_MESSAGING_NOT_SUPPORTED)
        if cla & 0x03:
            _sw(apdu.SW_LOGICAL_CHANNEL_NOT_SUPPORTED)
        if cla != 0x00:
            _sw(apdu.SW_CLA_NOT_SUPPORTED)
        store = self.store
        if self._epoch != store.epoch:
            if self._epoch is not None:  # a key changed: environment and confirmations are void
                self._env = [None, None]
                self._session_ok = set()
            self._epoch = store.epoch
        if cmd.ins == INS_GET_CHALLENGE:
            return self.rng.get_challenge(cmd)
        if cmd.ins == INS_MSE:
            return self._mse(cmd)
        if cmd.ins == INS_PSO:
            if cmd.p1p2 == PSO_ENCIPHER:
                return await self._encipher(cmd)
            if cmd.p1p2 == PSO_DECIPHER:
                return await self._decipher(cmd)
            _sw(apdu.SW_INCORRECT_P1P2)
        _sw(apdu.SW_INS_NOT_SUPPORTED)
        return Response()  # pragma: no cover

    # -- MSE -------------------------------------------------------------------------
    def _usable_key(self, kid: int):
        k = self.store.get(kid) if 1 <= kid <= _keys.MAX_KEYS else None
        if k is None or not k.enabled:
            _sw(apdu.SW_REFERENCE_NOT_FOUND)
        return k

    def _mse(self, cmd) -> Response:
        if cmd.p1 not in (MSE_SET_ENCIPHER, MSE_SET_DECIPHER, MSE_SET_BOTH) or cmd.p2 != CRT_CT:
            _sw(apdu.SW_INCORRECT_P1P2)
        f = _fields(cmd.data, (0x80, 0x83, 0x84))
        if 0x80 in f and f[0x80] != bytes((ALG_AES256_GCM,)):
            _sw(apdu.SW_WRONG_DATA)
        if (0x83 in f) == (0x84 in f):  # exactly one key reference
            _sw(apdu.SW_WRONG_DATA)
        ref = f.get(0x83, f.get(0x84))
        if len(ref) != 1:
            _sw(apdu.SW_WRONG_DATA)
        kid = ref[0]
        self._usable_key(kid)
        if cmd.p1 in (MSE_SET_ENCIPHER, MSE_SET_BOTH):
            self._env[_ENC] = kid
        if cmd.p1 in (MSE_SET_DECIPHER, MSE_SET_BOTH):
            self._env[_DEC] = kid
        return Response()

    # -- PSO -------------------------------------------------------------------------
    def _master_secret(self) -> bytes:
        ms = self._ms() if callable(self._ms) else self._ms
        if ms is None:
            _sw(apdu.SW_UNKNOWN)
        return ms

    def operation_prompt(self, k, decrypt: bool, length: int) -> Prompt:
        fields = [
            ("aes.field.operation", t("aes.op.decrypt" if decrypt else "aes.op.encrypt")),
            ("aes.field.key", f"#{k.kid} {k.name}"),
            ("aes.field.length", t("aes.unit.bytes", length)),
            ("aes.field.fingerprint", k.fingerprint()),
        ]
        if k.policy == _keys.POLICY_SESSION:
            fields.append(("aes.field.policy", t("aes.session_note")))
        kind = "aes.decrypt" if decrypt else "aes.encrypt"
        title = "aes.prompt.decrypt" if decrypt else "aes.prompt.encrypt"
        p = Prompt(kind, title, fields, SENSITIVE, fingerprint=k.fingerprint())
        p.key_id = k.kid
        return p

    async def _confirm(self, k, decrypt: bool, length: int) -> None:
        if k.policy == _keys.POLICY_SESSION and k.kid in self._session_ok:
            return
        if not await self.ui.confirm(self.operation_prompt(k, decrypt, length)):
            _sw(apdu.SW_SECURITY_STATUS_NOT_SATISFIED)
        if k.policy == _keys.POLICY_SESSION:
            self._session_ok.add(k.kid)

    def _env_key(self, direction: int):
        kid = self._env[direction]
        if kid is None:
            _sw(apdu.SW_CONDITIONS_NOT_SATISFIED)
        return self._usable_key(kid)

    async def _encipher(self, cmd) -> Response:
        k = self._env_key(_ENC)
        # a host-supplied nonce (82) or tag (83) is rejected: the device alone
        # chooses encryption nonces (spec §7)
        f = _fields(cmd.data, (TAG_PLAIN_OR_CIPHER, TAG_AAD))
        if TAG_PLAIN_OR_CIPHER not in f:
            _sw(apdu.SW_WRONG_DATA)
        pt = f[TAG_PLAIN_OR_CIPHER]
        aad = f.get(TAG_AAD, b"")
        if len(pt) > MAX_MESSAGE or len(aad) > MAX_AAD:
            _sw(apdu.SW_WRONG_LENGTH)
        ms = self._master_secret()
        await self._confirm(k, False, len(pt))
        k = self._env_key(_ENC)  # state may have changed during the prompt
        nonce = self.store.allocate_nonce(ms, k)  # persisted before use
        ct, tag = crypto.aes256_gcm_encrypt(k.key, nonce, pt, aad)
        out = tlv.build(TAG_NONCE, nonce) + tlv.build(TAG_PLAIN_OR_CIPHER, ct) + tlv.build(TAG_TAG, tag)
        return Response(out)

    async def _decipher(self, cmd) -> Response:
        k = self._env_key(_DEC)
        f = _fields(cmd.data, (TAG_PLAIN_OR_CIPHER, TAG_AAD, TAG_NONCE, TAG_TAG))
        for tag in (TAG_NONCE, TAG_PLAIN_OR_CIPHER, TAG_TAG):
            if tag not in f:
                _sw(apdu.SW_WRONG_DATA)
        nonce = f[TAG_NONCE]
        ct = f[TAG_PLAIN_OR_CIPHER]
        tag = f[TAG_TAG]
        aad = f.get(TAG_AAD, b"")
        if len(nonce) != NONCE_LEN or len(tag) != TAG_LEN:
            _sw(apdu.SW_WRONG_DATA)
        if len(ct) > MAX_MESSAGE or len(aad) > MAX_AAD:
            _sw(apdu.SW_WRONG_LENGTH)
        await self._confirm(k, True, len(ct))
        k = self._env_key(_DEC)
        try:
            pt = crypto.aes256_gcm_decrypt(k.key, nonce, ct, tag, aad)
        except crypto.AuthenticationError:
            _sw(SW_AUTH_TAG_FAILED)
        return Response(pt)
