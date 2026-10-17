# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""authenticatorClientPIN (CTAP 2.1 §6.5) and the pinUvAuthToken state.

* PIN/UV auth protocols **1** and **2** (§6.5.6, §6.5.7), each with its own
  P-256 key agreement key generated at power-up (lazily, on first use) and
  regenerated after a PIN mismatch.
* Subcommands: getPINRetries (0x01), getKeyAgreement (0x02), setPIN (0x03),
  changePIN (0x04), getPinToken (0x05), getPinUvAuthTokenUsingPinWithPermissions
  (0x09). The built-in UV subcommands (0x06, 0x07) are not supported
  (no built-in user verification method): CTAP2_ERR_INVALID_SUBCOMMAND.
* ``pinRetries`` (max 8) is persisted in the FIDO state blob and decremented
  **before** the PIN hash is compared, so cutting power during a guess never
  restores an attempt (§6.5.5.5). Three consecutive mismatches in one power
  cycle return CTAP2_ERR_PIN_AUTH_BLOCKED until the device is power cycled.
* PIN rules (§6.5.5.4 / §6.5.5.5): newPinEnc decrypts to exactly 64 bytes,
  the PIN is the prefix before the zero padding, at most 63 bytes, valid
  UTF-8 and at least :data:`~.state.DEFAULT_MIN_PIN_LENGTH` code points. The
  stored value is ``LEFT(SHA-256(PIN), 16)``.
* pinUvAuthToken state machine (§6.5.2.1): permissions (mc, ga, cm, lbw),
  permissions RP ID, userPresent / userVerified flags, initial usage time
  limit (30 s) and maximum usage period (10 min). Tokens obtained with a PIN
  have ``userPresent = false`` (§6.5.5.7, beginUsingPinUvAuthToken(false)).
"""

from micropython import const

from ...core.errors import InvalidInput, PinBlocked, PinInvalid, PolicyDenied
from ...platform import crypto
from ...platform import time as ptime
from . import params as prm
from .state import MAX_PIN_RETRIES
from .status import (
    CTAP1_ERR_INVALID_PARAMETER,
    CTAP2_ERR_MISSING_PARAMETER,
    CTAP2_ERR_NOT_ALLOWED,
    CTAP2_ERR_PIN_AUTH_BLOCKED,
    CTAP2_ERR_PIN_AUTH_INVALID,
    CTAP2_ERR_PIN_BLOCKED,
    CTAP2_ERR_PIN_INVALID,
    CTAP2_ERR_PIN_NOT_SET,
    CTAP2_ERR_PIN_POLICY_VIOLATION,
    CTAP2_ERR_UNAUTHORIZED_PERMISSION,
    CtapError,
)
from .status import CTAP2_ERR_INVALID_SUBCOMMAND as _INVALID_SUBCOMMAND

# subcommands
GET_PIN_RETRIES = const(0x01)
GET_KEY_AGREEMENT = const(0x02)
SET_PIN = const(0x03)
CHANGE_PIN = const(0x04)
GET_PIN_TOKEN = const(0x05)
GET_TOKEN_USING_UV = const(0x06)
GET_UV_RETRIES = const(0x07)
GET_TOKEN_USING_PIN = const(0x09)

# request keys
_P_PROTOCOL = const(0x01)
_P_SUBCMD = const(0x02)
_P_KEY_AGREEMENT = const(0x03)
_P_PIN_UV_AUTH_PARAM = const(0x04)
_P_NEW_PIN_ENC = const(0x05)
_P_PIN_HASH_ENC = const(0x06)
_P_PERMISSIONS = const(0x09)
_P_RP_ID = const(0x0A)

# response keys
R_KEY_AGREEMENT = const(0x01)
R_PIN_UV_AUTH_TOKEN = const(0x02)
R_PIN_RETRIES = const(0x03)
R_POWER_CYCLE_STATE = const(0x04)

# permissions (CTAP 2.1 §6.5.5.7)
PERM_MC = const(0x01)
PERM_GA = const(0x02)
PERM_CM = const(0x04)
PERM_BE = const(0x08)
PERM_LBW = const(0x10)
PERM_ACFG = const(0x20)
SUPPORTED_PERMISSIONS = const(0x17)  # mc | ga | cm | lbw

MAX_CONSECUTIVE_MISMATCHES = const(3)
INITIAL_USAGE_TIME_LIMIT_MS = const(30_000)
MAX_USAGE_TIME_PERIOD_MS = const(600_000)
USER_PRESENT_TIME_LIMIT_MS = const(30_000)
TOKEN_LEN = const(32)
PIN_PAD_LEN = const(64)
MAX_PIN_BYTES = const(63)

_HKDF_SALT = bytes(32)


class PinProtocol:
    """PIN/UV auth protocol (§6.5.6 interface): ``version``, key agreement
    key, ``encapsulate``-side primitives and token MAC."""

    version = 0
    mac_len = 0

    def __init__(self) -> None:
        self._sk = None
        self._pk = None

    def regenerate(self) -> None:
        self._sk = crypto.p256_generate()
        self._pk = crypto.p256_public(self._sk)

    def get_public_key(self) -> dict:
        """COSE_Key of the key agreement key (alg -25 per §6.5.6)."""
        if self._sk is None:
            self.regenerate()
        return {1: 2, 3: -25, -1: 1, -2: self._pk[1:33], -3: self._pk[33:65]}

    def decapsulate(self, peer) -> bytes:
        """Shared secret with the platform key ``peer`` (COSE_Key map).

        Raises CTAP1_ERR_INVALID_PARAMETER on a malformed key or a point not
        on the curve (§6.5.6 ``getSharedSecret``)."""
        if not isinstance(peer, dict):
            raise CtapError(CTAP1_ERR_INVALID_PARAMETER)
        x = peer.get(-2)
        y = peer.get(-3)
        if (
            peer.get(1) != 2
            or peer.get(-1) != 1
            or not isinstance(x, bytes)
            or not isinstance(y, bytes)
            or len(x) != 32
            or len(y) != 32
        ):
            raise CtapError(CTAP1_ERR_INVALID_PARAMETER)
        if self._sk is None:
            self.regenerate()
        try:
            z = crypto.p256_ecdh(self._sk, b"\x04" + x + y)
        except Exception:
            raise CtapError(CTAP1_ERR_INVALID_PARAMETER)
        return self.kdf(z)

    def kdf(self, z: bytes) -> bytes:  # pragma: no cover - abstract
        raise NotImplementedError

    def encrypt(self, key: bytes, pt: bytes) -> bytes:  # pragma: no cover - abstract
        raise NotImplementedError

    def decrypt(self, key: bytes, ct: bytes):  # pragma: no cover - abstract
        raise NotImplementedError

    def authenticate(self, key: bytes, msg: bytes) -> bytes:  # pragma: no cover - abstract
        raise NotImplementedError

    def verify(self, key: bytes, msg: bytes, signature) -> bool:
        if not isinstance(signature, bytes) or len(signature) != self.mac_len:
            return False
        return crypto.ct_equal(self.authenticate(key, msg), signature)


class PinProtocolV1(PinProtocol):
    """§6.5.6: SHA-256(Z), AES-256-CBC with zero IV, HMAC truncated to 16."""

    version = 1
    mac_len = 16

    def kdf(self, z: bytes) -> bytes:
        return crypto.sha256(z)

    def encrypt(self, key: bytes, pt: bytes) -> bytes:
        return crypto.aes256_cbc_encrypt(key, bytes(16), pt)

    def decrypt(self, key: bytes, ct: bytes):
        if len(ct) == 0 or len(ct) % 16:
            return None
        return crypto.aes256_cbc_decrypt(key, bytes(16), ct)

    def authenticate(self, key: bytes, msg: bytes) -> bytes:
        return crypto.hmac_sha256(key, msg)[:16]


class PinProtocolV2(PinProtocol):
    """§6.5.7: HKDF HMAC key || AES key, random IV, full 32-byte HMAC."""

    version = 2
    mac_len = 32

    def kdf(self, z: bytes) -> bytes:
        return crypto.hkdf_sha256(z, _HKDF_SALT, b"CTAP2 HMAC key", 32) + crypto.hkdf_sha256(
            z, _HKDF_SALT, b"CTAP2 AES key", 32
        )

    def encrypt(self, key: bytes, pt: bytes) -> bytes:
        aes_key = key[32:] if len(key) == 64 else key
        iv = crypto.random_bytes(16, False)
        return iv + crypto.aes256_cbc_encrypt(aes_key, iv, pt)

    def decrypt(self, key: bytes, ct: bytes):
        if len(ct) < 32 or len(ct) % 16:
            return None
        aes_key = key[32:] if len(key) == 64 else key
        return crypto.aes256_cbc_decrypt(aes_key, ct[:16], ct[16:])

    def authenticate(self, key: bytes, msg: bytes) -> bytes:
        return crypto.hmac_sha256(key[:32], msg)


def pin_hash(pin: bytes) -> bytes:
    return crypto.sha256(pin)[:16]


def check_pin_policy(pin: bytes, min_len: int) -> None:
    """Raise CTAP2_ERR_PIN_POLICY_VIOLATION if ``pin`` breaks the PIN rules."""
    if len(pin) > MAX_PIN_BYTES or not prm.utf8_valid(pin) or prm.utf8_code_points(pin) < min_len:
        raise CtapError(CTAP2_ERR_PIN_POLICY_VIOLATION)


class ClientPin:
    """Volatile clientPIN state of one power cycle + the persistent PIN."""

    def __init__(self, state) -> None:
        self.state = state
        self.protocols = {1: PinProtocolV1(), 2: PinProtocolV2()}
        self.consecutive_mismatches = 0
        self._token = crypto.random_bytes(TOKEN_LEN)
        self._stop_using()

    # -- pinUvAuthToken state (§6.5.2.1) -----------------------------------
    def _stop_using(self) -> None:
        self._in_use = False
        self._tok_protocol = 0
        self._perms = 0
        self._perm_rp_id = None
        self._user_present = False
        self._user_verified = False
        self._start = 0
        self._used = False

    def reset_token(self) -> None:
        """resetPinUvAuthToken(): new random token, previous one unusable."""
        self._token = crypto.random_bytes(TOKEN_LEN)
        self._stop_using()

    def _begin_using(self, protocol: int, user_present: bool) -> None:
        self._in_use = True
        self._tok_protocol = protocol
        self._user_present = user_present
        self._user_verified = True
        self._start = ptime.ticks_ms()
        self._used = False

    def _observe_timers(self) -> None:
        if not self._in_use:
            return
        elapsed = ptime.ticks_diff(ptime.ticks_ms(), self._start)
        if elapsed >= MAX_USAGE_TIME_PERIOD_MS or (not self._used and elapsed >= INITIAL_USAGE_TIME_LIMIT_MS):
            self._stop_using()
        elif elapsed >= USER_PRESENT_TIME_LIMIT_MS:
            self._user_present = False

    def token_in_use(self) -> bool:
        self._observe_timers()
        return self._in_use

    def verify_token(self, protocol: int, msg: bytes, signature) -> bool:
        """``verify(pinUvAuthToken, msg, pinUvAuthParam)`` for ``protocol``."""
        self._observe_timers()
        if not self._in_use or protocol != self._tok_protocol:
            return False
        proto = self.protocols.get(protocol)
        if proto is None or not proto.verify(self._token, msg, signature):
            return False
        self._used = True
        return True

    def has_permission(self, perm: int) -> bool:
        return self._in_use and bool(self._perms & perm)

    @property
    def permissions_rp_id(self):
        return self._perm_rp_id

    def set_permissions_rp_id(self, rp_id: str) -> None:
        if self._perm_rp_id is None:
            self._perm_rp_id = rp_id

    def user_present(self) -> bool:
        self._observe_timers()
        return self._in_use and self._user_present

    def user_verified(self) -> bool:
        self._observe_timers()
        return self._in_use and self._user_verified

    def clear_after_use(self) -> None:
        """clearUserPresentFlag + clearUserVerifiedFlag +
        clearPinUvAuthTokenPermissionsExceptLbw (§6.1.2 step 14, §6.2.2)."""
        self._user_present = False
        self._user_verified = False
        self._perms &= PERM_LBW

    def power_cycle_required(self) -> bool:
        return self.consecutive_mismatches >= MAX_CONSECUTIVE_MISMATCHES

    def reset(self) -> None:
        """Volatile part of authenticatorReset."""
        self.consecutive_mismatches = 0
        for p in self.protocols.values():
            p.regenerate()
        self.reset_token()

    # -- request handling ------------------------------------------------------
    def protocol(self, version):
        """The protocol object for ``version`` or CTAP1_ERR_INVALID_PARAMETER."""
        proto = self.protocols.get(version) if isinstance(version, int) else None
        if proto is None:
            raise CtapError(CTAP1_ERR_INVALID_PARAMETER)
        return proto

    def handle(self, req: dict) -> dict:
        sub = prm.get(req, _P_SUBCMD, "uint", required=True)
        version = prm.get(req, _P_PROTOCOL, "uint")
        if sub == GET_PIN_RETRIES:
            if version is not None:
                self.protocol(version)
            return {R_PIN_RETRIES: self.state.pin_retries, R_POWER_CYCLE_STATE: self.power_cycle_required()}
        if sub in (GET_TOKEN_USING_UV, GET_UV_RETRIES) or sub not in (
            GET_KEY_AGREEMENT,
            SET_PIN,
            CHANGE_PIN,
            GET_PIN_TOKEN,
            GET_TOKEN_USING_PIN,
        ):
            raise CtapError(_INVALID_SUBCOMMAND)
        if version is None:
            raise CtapError(CTAP2_ERR_MISSING_PARAMETER)
        proto = self.protocol(version)
        if sub == GET_KEY_AGREEMENT:
            return {R_KEY_AGREEMENT: proto.get_public_key()}
        if sub == SET_PIN:
            return self._set_pin(proto, req)
        if sub == CHANGE_PIN:
            return self._change_pin(proto, req)
        return self._get_token(proto, req, sub)

    def _set_pin(self, proto, req) -> dict:
        ka = prm.get(req, _P_KEY_AGREEMENT, "map", required=True)
        param = prm.get(req, _P_PIN_UV_AUTH_PARAM, "bytes", required=True)
        new_pin_enc = prm.get(req, _P_NEW_PIN_ENC, "bytes", required=True)
        if self.state.pin_is_set():
            raise CtapError(CTAP2_ERR_NOT_ALLOWED)
        shared = proto.decapsulate(ka)
        if not proto.verify(shared, new_pin_enc, param):
            raise CtapError(CTAP2_ERR_PIN_AUTH_INVALID)
        new_pin = self._decrypt_new_pin(proto, shared, new_pin_enc)
        self.state.set_pin_hash(pin_hash(new_pin))
        self.consecutive_mismatches = 0
        return {}

    def _change_pin(self, proto, req) -> dict:
        ka = prm.get(req, _P_KEY_AGREEMENT, "map", required=True)
        param = prm.get(req, _P_PIN_UV_AUTH_PARAM, "bytes", required=True)
        new_pin_enc = prm.get(req, _P_NEW_PIN_ENC, "bytes", required=True)
        pin_hash_enc = prm.get(req, _P_PIN_HASH_ENC, "bytes", required=True)
        if not self.state.pin_is_set():
            raise CtapError(CTAP2_ERR_PIN_NOT_SET)
        self._check_not_blocked()
        shared = proto.decapsulate(ka)
        if not proto.verify(shared, new_pin_enc + pin_hash_enc, param):
            raise CtapError(CTAP2_ERR_PIN_AUTH_INVALID)
        self._verify_pin_hash_enc(proto, shared, pin_hash_enc)
        new_pin = self._decrypt_new_pin(proto, shared, new_pin_enc)
        self.state.set_pin_hash(pin_hash(new_pin))
        self.reset_token()
        return {}

    def _get_token(self, proto, req, sub) -> dict:
        ka = prm.get(req, _P_KEY_AGREEMENT, "map", required=True)
        pin_hash_enc = prm.get(req, _P_PIN_HASH_ENC, "bytes", required=True)
        if sub == GET_TOKEN_USING_PIN:
            perms = prm.get(req, _P_PERMISSIONS, "uint", required=True)
            rp_id = prm.get(req, _P_RP_ID, "text")
            if perms == 0:
                raise CtapError(CTAP1_ERR_INVALID_PARAMETER)
            if perms & ~SUPPORTED_PERMISSIONS:
                raise CtapError(CTAP2_ERR_UNAUTHORIZED_PERMISSION)
        else:
            # getPinToken (legacy): permissions/rpId must be absent (§6.5.5.6)
            if _P_PERMISSIONS in req or _P_RP_ID in req:
                raise CtapError(CTAP1_ERR_INVALID_PARAMETER)
            perms = PERM_MC | PERM_GA
            rp_id = None
        if not self.state.pin_is_set():
            raise CtapError(CTAP2_ERR_PIN_NOT_SET)
        self._check_not_blocked()
        shared = proto.decapsulate(ka)
        self._verify_pin_hash_enc(proto, shared, pin_hash_enc)
        self.reset_token()
        self._begin_using(proto.version, False)
        self._perms = perms
        self._perm_rp_id = rp_id
        return {R_PIN_UV_AUTH_TOKEN: proto.encrypt(shared, self._token)}

    # -- helpers ---------------------------------------------------------------
    def _check_not_blocked(self) -> None:
        if self.state.pin_retries == 0:
            raise CtapError(CTAP2_ERR_PIN_BLOCKED)
        if self.power_cycle_required():
            raise CtapError(CTAP2_ERR_PIN_AUTH_BLOCKED)

    def _verify_pin_hash_enc(self, proto, shared: bytes, pin_hash_enc: bytes) -> None:
        """Decrement-then-compare (§6.5.5.5 steps 5-7)."""
        retries = self.state.pin_retries - 1
        self.state.set_pin_retries(retries)
        expected_ct_len = 16 if proto.version == 1 else 32
        candidate = proto.decrypt(shared, pin_hash_enc) if len(pin_hash_enc) == expected_ct_len else None
        stored = self.state.pin_hash
        if candidate is None or stored is None or not crypto.ct_equal(candidate, stored):
            proto.regenerate()
            self.consecutive_mismatches += 1
            if retries == 0:
                raise CtapError(CTAP2_ERR_PIN_BLOCKED)
            if self.power_cycle_required():
                raise CtapError(CTAP2_ERR_PIN_AUTH_BLOCKED)
            raise CtapError(CTAP2_ERR_PIN_INVALID)
        self.consecutive_mismatches = 0
        self.state.set_pin_retries(MAX_PIN_RETRIES)

    def _decrypt_new_pin(self, proto, shared: bytes, new_pin_enc: bytes) -> bytes:
        expected_ct_len = PIN_PAD_LEN if proto.version == 1 else PIN_PAD_LEN + 16
        if len(new_pin_enc) != expected_ct_len:
            raise CtapError(CTAP1_ERR_INVALID_PARAMETER)
        padded = proto.decrypt(shared, new_pin_enc)
        if padded is None or len(padded) != PIN_PAD_LEN:
            raise CtapError(CTAP1_ERR_INVALID_PARAMETER)
        end = 0
        while end < PIN_PAD_LEN and padded[end] != 0:
            end += 1
        pin = bytes(padded[:end])
        check_pin_policy(pin, self.state.min_pin_length)
        return pin

    # -- local (device menu) PIN management ----------------------------------
    def local_set_pin(self, pin: str) -> None:
        """Set the FIDO PIN from the device menu (only when none is set; CTAP
        has no PIN removal other than authenticatorReset, mirrored here)."""
        raw = self._local_pin_bytes(pin)
        if self.state.pin_is_set():
            raise PolicyDenied("PIN already set")
        self.state.set_pin_hash(pin_hash(raw))
        self.consecutive_mismatches = 0
        self.reset_token()

    def local_change_pin(self, old_pin: str, new_pin: str) -> None:
        """Change the FIDO PIN from the device menu. The current PIN is
        verified with the same retry accounting as changePIN."""
        if not self.state.pin_is_set():
            raise PolicyDenied("no PIN set")
        raw_new = self._local_pin_bytes(new_pin)
        if self.state.pin_retries == 0:
            raise PinBlocked("FIDO PIN blocked")
        retries = self.state.pin_retries - 1
        self.state.set_pin_retries(retries)
        if not crypto.ct_equal(pin_hash(old_pin.encode()), self.state.pin_hash):
            if retries == 0:
                raise PinBlocked("FIDO PIN blocked")
            raise PinInvalid(retries)
        self.state.set_pin_hash(pin_hash(raw_new))
        self.consecutive_mismatches = 0
        self.reset_token()

    def _local_pin_bytes(self, pin: str) -> bytes:
        if not isinstance(pin, str):
            raise InvalidInput("PIN")
        raw = pin.encode()
        try:
            check_pin_policy(raw, self.state.min_pin_length)
        except CtapError:
            raise InvalidInput("PIN policy")
        return raw
