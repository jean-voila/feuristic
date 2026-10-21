# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""authenticatorCredentialManagement (CTAP 2.1 §6.8), command 0x0A (and the
FIDO_2_1_PRE prototype alias 0x41, same semantics).

Subcommands: getCredsMetadata (0x01), enumerateRPsBegin (0x02),
enumerateRPsGetNextRP (0x03), enumerateCredentialsBegin (0x04),
enumerateCredentialsGetNextCredential (0x05), deleteCredential (0x06),
updateUserInformation (0x07).

Authentication (§6.8.1 .. §6.8.6): every non-"GetNext" subcommand requires a
pinUvAuthToken with the ``cm`` permission; the MAC covers
``subCommand || subCommandParams`` using the platform's exact CBOR bytes.
getCredsMetadata and enumerateRPsBegin reject tokens bound to an RP ID; the
other subcommands reject tokens whose permissions RP ID does not match the
credential's RP. Enumeration state is invalidated by any other command
(the dispatcher calls :meth:`CredentialManagement.reset_state`).
"""

from micropython import const

from ...core.errors import StorageFull
from ...platform import crypto
from . import params as prm
from .clientpin import PERM_CM
from .status import (
    CTAP1_ERR_INVALID_PARAMETER,
    CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
    CTAP2_ERR_INVALID_SUBCOMMAND,
    CTAP2_ERR_KEY_STORE_FULL,
    CTAP2_ERR_MISSING_PARAMETER,
    CTAP2_ERR_NO_CREDENTIALS,
    CTAP2_ERR_NOT_ALLOWED,
    CTAP2_ERR_PIN_AUTH_INVALID,
    CTAP2_ERR_PUAT_REQUIRED,
    CtapError,
)

GET_CREDS_METADATA = const(0x01)
ENUMERATE_RPS_BEGIN = const(0x02)
ENUMERATE_RPS_NEXT = const(0x03)
ENUMERATE_CREDS_BEGIN = const(0x04)
ENUMERATE_CREDS_NEXT = const(0x05)
DELETE_CREDENTIAL = const(0x06)
UPDATE_USER_INFO = const(0x07)

_P_SUBCMD = const(0x01)
_P_SUBCMD_PARAMS = const(0x02)
_P_PROTOCOL = const(0x03)
_P_PIN_UV_AUTH_PARAM = const(0x04)

_SP_RP_ID_HASH = const(0x01)
_SP_CREDENTIAL_ID = const(0x02)
_SP_USER = const(0x03)

R_EXISTING_COUNT = const(0x01)
R_REMAINING_COUNT = const(0x02)
R_RP = const(0x03)
R_RP_ID_HASH = const(0x04)
R_TOTAL_RPS = const(0x05)
R_USER = const(0x06)
R_CREDENTIAL_ID = const(0x07)
R_PUBLIC_KEY = const(0x08)
R_TOTAL_CREDENTIALS = const(0x09)
R_CRED_PROTECT = const(0x0A)
R_LARGE_BLOB_KEY = const(0x0B)


def user_entity(cred, full: bool = True) -> dict:
    user = {"id": cred.user_id}
    if full:
        if cred.user_name:
            user["name"] = cred.user_name
        if cred.display_name:
            user["displayName"] = cred.display_name
    return user


def descriptor_id(desc) -> bytes:
    """Credential ID of a PublicKeyCredentialDescriptor map (strict types)."""
    if not isinstance(desc, dict):
        raise CtapError(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
    cid = prm.get(desc, "id", "bytes", required=True)
    prm.get(desc, "type", "text", required=True)
    return cid


class CredentialManagement:
    def __init__(self, store, pin) -> None:
        self.store = store
        self.pin = pin
        self.reset_state()

    def reset_state(self) -> None:
        self._rps = None  # remaining [(rpId, rpIdHash, count)]
        self._rp_index = 0
        self._creds = None  # remaining [uid]

    # -- entry point -----------------------------------------------------------
    def handle(self, req: dict, raw: dict) -> dict:
        sub = prm.get(req, _P_SUBCMD, "uint", required=True)
        if sub == ENUMERATE_RPS_NEXT:
            self._creds = None
            return self._next_rp()
        if sub == ENUMERATE_CREDS_NEXT:
            self._rps = None
            return self._next_cred()
        self.reset_state()
        if sub not in (
            GET_CREDS_METADATA,
            ENUMERATE_RPS_BEGIN,
            ENUMERATE_CREDS_BEGIN,
            DELETE_CREDENTIAL,
            UPDATE_USER_INFO,
        ):
            raise CtapError(CTAP2_ERR_INVALID_SUBCOMMAND)
        sp = prm.get(req, _P_SUBCMD_PARAMS, "map")
        self._authenticate(req, sub, raw.get(_P_SUBCMD_PARAMS, b"") if sp is not None else b"")
        if sp is None:
            sp = {}
        if sub == GET_CREDS_METADATA:
            self._no_rp_binding()
            return {R_EXISTING_COUNT: self.store.count(), R_REMAINING_COUNT: self.store.remaining()}
        if sub == ENUMERATE_RPS_BEGIN:
            self._no_rp_binding()
            return self._rps_begin()
        if sub == ENUMERATE_CREDS_BEGIN:
            return self._creds_begin(sp)
        if sub == DELETE_CREDENTIAL:
            return self._delete(sp)
        return self._update(sp)

    def _authenticate(self, req: dict, sub: int, raw_params: bytes) -> None:
        param = prm.get(req, _P_PIN_UV_AUTH_PARAM, "bytes")
        proto = prm.get(req, _P_PROTOCOL, "uint")
        if param is None:
            raise CtapError(CTAP2_ERR_PUAT_REQUIRED)
        if proto is None:
            raise CtapError(CTAP2_ERR_MISSING_PARAMETER)
        self.pin.protocol(proto)
        msg = bytes((sub,)) + bytes(raw_params)
        if not self.pin.verify_token(proto, msg, param) or not self.pin.has_permission(PERM_CM):
            raise CtapError(CTAP2_ERR_PIN_AUTH_INVALID)

    def _no_rp_binding(self) -> None:
        if self.pin.permissions_rp_id is not None:
            raise CtapError(CTAP2_ERR_PIN_AUTH_INVALID)

    def _check_rp_binding(self, rp_id_hash: bytes) -> None:
        rp_id = self.pin.permissions_rp_id
        if rp_id is not None and not crypto.ct_equal(crypto.sha256(rp_id.encode()), rp_id_hash):
            raise CtapError(CTAP2_ERR_PIN_AUTH_INVALID)

    # -- RP enumeration --------------------------------------------------------
    def _rp_response(self, rp) -> dict:
        return {R_RP: {"id": rp[0]}, R_RP_ID_HASH: rp[1]}

    def _rps_begin(self) -> dict:
        rps = self.store.rps()
        if not rps:
            raise CtapError(CTAP2_ERR_NO_CREDENTIALS)
        resp = self._rp_response(rps[0])
        resp[R_TOTAL_RPS] = len(rps)
        self._rps = rps
        self._rp_index = 1
        return resp

    def _next_rp(self) -> dict:
        if self._rps is None or self._rp_index >= len(self._rps):
            self._rps = None
            raise CtapError(CTAP2_ERR_NOT_ALLOWED)
        rp = self._rps[self._rp_index]
        self._rp_index += 1
        return self._rp_response(rp)

    # -- credential enumeration ------------------------------------------------
    def _cred_response(self, cred) -> dict:
        resp = {
            R_USER: user_entity(cred),
            R_CREDENTIAL_ID: {"id": cred.cred_id, "type": "public-key"},
            R_PUBLIC_KEY: cred.cose_public_key(),
            R_CRED_PROTECT: cred.cred_protect,
        }
        lbk = cred.large_blob_key()
        if lbk is not None:
            resp[R_LARGE_BLOB_KEY] = lbk
        return resp

    def _creds_begin(self, sp: dict) -> dict:
        rp_id_hash = prm.get(sp, _SP_RP_ID_HASH, "bytes", required=True)
        if len(rp_id_hash) != 32:
            raise CtapError(CTAP1_ERR_INVALID_PARAMETER)
        self._check_rp_binding(rp_id_hash)
        creds = self.store.for_rp(rp_id_hash)
        if not creds:
            raise CtapError(CTAP2_ERR_NO_CREDENTIALS)
        resp = self._cred_response(creds[0])
        resp[R_TOTAL_CREDENTIALS] = len(creds)
        self._creds = [c.uid for c in creds[1:]]
        return resp

    def _next_cred(self) -> dict:
        while self._creds:
            cred = self.store.get(self._creds.pop(0))
            if cred is not None:
                return self._cred_response(cred)
        self._creds = None
        raise CtapError(CTAP2_ERR_NOT_ALLOWED)

    # -- modification ----------------------------------------------------------
    def _find(self, sp: dict):
        if _SP_CREDENTIAL_ID not in sp:
            raise CtapError(CTAP2_ERR_MISSING_PARAMETER)
        cid = descriptor_id(sp[_SP_CREDENTIAL_ID])
        cred = self.store.lookup_resident(cid)
        if cred is None:
            raise CtapError(CTAP2_ERR_NO_CREDENTIALS)
        self._check_rp_binding(cred.rp_id_hash)
        return cred

    def _delete(self, sp: dict) -> dict:
        cred = self._find(sp)
        self.store.delete(cred.uid)
        return {}

    def _update(self, sp: dict) -> dict:
        user = prm.get(sp, _SP_USER, "map")
        cred = self._find(sp)
        if user is None:
            raise CtapError(CTAP2_ERR_MISSING_PARAMETER)
        uid = prm.get(user, "id", "bytes", required=True)
        name = prm.get(user, "name", "text")
        display = prm.get(user, "displayName", "text")
        if not crypto.ct_equal(uid, cred.user_id):
            raise CtapError(CTAP1_ERR_INVALID_PARAMETER)
        try:
            self.store.update_user(
                cred,
                prm.truncate_utf8(name, 64) if name else None,
                prm.truncate_utf8(display, 64) if display else None,
            )
        except StorageFull:
            raise CtapError(CTAP2_ERR_KEY_STORE_FULL)
        return {}
