# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""CTAP 2.1 authenticator API (CTAP 2.1 PS 2021-06-15, §6).

Commands: authenticatorMakeCredential (0x01), GetAssertion (0x02), GetInfo
(0x04), ClientPIN (0x06), Reset (0x07), GetNextAssertion (0x08),
CredentialManagement (0x0A, alias 0x41), Selection (0x0B), LargeBlobs (0x0C).
authenticatorConfig (0x0D) and bio enrollment are not implemented and not
advertised (CTAP1_ERR_INVALID_COMMAND).

Design decisions (details in docs/protocols/fido2.md):

* No built-in user verification: UV is obtained through clientPIN
  pinUvAuthTokens only ("uv" is not advertised, a request with ``uv=true``
  gets CTAP2_ERR_INVALID_OPTION, §6.1.2 step 5).
* ``makeCredUvNotRqd`` = true (§6.4 / §6.1.2 step 7): when a PIN is set,
  discoverable credentials require a pinUvAuthToken (CTAP2_ERR_PUAT_REQUIRED)
  but non-discoverable ones may be created with user presence only, which
  keeps second-factor flows (U2F-style logins, ``ecdsa-sk`` SSH keys)
  working with a PIN-protected authenticator.
* Attestation: ``packed`` self attestation (signed by the credential key,
  ``alg`` = credential algorithm, no x5c) or ``none`` when the platform asks
  for it through ``attestationFormatsPreference`` (0x0B). No enterprise
  attestation (``enterpriseAttestation`` → CTAP1_ERR_INVALID_PARAMETER).
* Global signature counter (see :mod:`.state`).
* WebAuthn L3 backup flags: discoverable credentials BE=1 (exportable by the
  QR backup, product spec §5/§8.2), BS=1 once exported or restored;
  non-discoverable credentials BE=0, BS=0.
* Multiple discoverable credentials with user presence: the user picks the
  account on the device (``userSelected`` = true, §6.2.2 step 11); silent
  requests (up=false) return ``numberOfCredentials`` and serve
  authenticatorGetNextAssertion.
"""

from micropython import const

from ...core import cbor, i18n
from ...core.errors import StorageFull, UserCancelled, UserTimeout
from ...core.interaction import DANGER, NORMAL, SENSITIVE, Prompt
from ...platform import crypto, log
from ...platform import time as ptime
from . import credentials as cr
from . import params as prm
from . import strings
from .clientpin import PERM_GA, PERM_MC, ClientPin
from .context import NULL_CHANNEL, STATUS_PROCESSING, STATUS_UPNEEDED
from .credmgmt import CredentialManagement, user_entity
from .largeblobs import MAX_SERIALIZED, LargeBlobs
from .state import FidoState
from .status import (
    CTAP1_ERR_INVALID_COMMAND,
    CTAP1_ERR_INVALID_LENGTH,
    CTAP1_ERR_INVALID_PARAMETER,
    CTAP1_ERR_OTHER,
    CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
    CTAP2_ERR_CREDENTIAL_EXCLUDED,
    CTAP2_ERR_INVALID_OPTION,
    CTAP2_ERR_KEEPALIVE_CANCEL,
    CTAP2_ERR_KEY_STORE_FULL,
    CTAP2_ERR_LIMIT_EXCEEDED,
    CTAP2_ERR_MISSING_PARAMETER,
    CTAP2_ERR_NO_CREDENTIALS,
    CTAP2_ERR_NOT_ALLOWED,
    CTAP2_ERR_OPERATION_DENIED,
    CTAP2_ERR_PIN_AUTH_INVALID,
    CTAP2_ERR_PIN_INVALID,
    CTAP2_ERR_PIN_NOT_SET,
    CTAP2_ERR_PUAT_REQUIRED,
    CTAP2_ERR_UNSUPPORTED_ALGORITHM,
    CTAP2_ERR_UNSUPPORTED_OPTION,
    CTAP2_ERR_USER_ACTION_TIMEOUT,
    CtapError,
)

# commands
CMD_MAKE_CREDENTIAL = const(0x01)
CMD_GET_ASSERTION = const(0x02)
CMD_GET_INFO = const(0x04)
CMD_CLIENT_PIN = const(0x06)
CMD_RESET = const(0x07)
CMD_GET_NEXT_ASSERTION = const(0x08)
CMD_CREDENTIAL_MGMT = const(0x0A)
CMD_SELECTION = const(0x0B)
CMD_LARGE_BLOBS = const(0x0C)
CMD_CREDENTIAL_MGMT_PRE = const(0x41)

# feuristic AAGUID e90e59a4-2c04-4252-ae49-d69eff27585f (random UUIDv4,
# generated once for this project; identifies the *model*, never the device)
AAGUID = b"\xe9\x0e\x59\xa4\x2c\x04\x42\x52\xae\x49\xd6\x9e\xff\x27\x58\x5f"

MAX_MSG_SIZE = const(7609)  # CTAPHID maximum message (57 + 128 * 59)
MAX_CRED_COUNT_IN_LIST = const(16)  # advertised
MAX_LIST_LEN = const(64)  # hard limit for allowList / excludeList
UP_TIMEOUT_MS = const(30_000)
RESET_WINDOW_MS = const(10_000)
GET_NEXT_TIMEOUT_MS = const(30_000)
MAX_NAME_BYTES = const(64)

# authenticator data flags (WebAuthn L3 §6.1)
FLAG_UP = const(0x01)
FLAG_UV = const(0x04)
FLAG_BE = const(0x08)
FLAG_BS = const(0x10)
FLAG_AT = const(0x40)
FLAG_ED = const(0x80)

BOGUS_RP_ID = ".dummy"  # Chrome's "touch the authenticator" makeCredential


def _descriptor_ids(lst) -> list:
    """Credential IDs of the ``public-key`` descriptors of an allow/exclude list."""
    if len(lst) > MAX_LIST_LEN:
        raise CtapError(CTAP2_ERR_LIMIT_EXCEEDED)
    out = []
    for d in lst:
        if not isinstance(d, dict):
            raise CtapError(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        t = prm.get(d, "type", "text", required=True)
        cid = prm.get(d, "id", "bytes", required=True)
        prm.get(d, "transports", "list")
        if t == "public-key":
            out.append(cid)
    return out


def _bool_option(opts, name: str):
    if opts is None or name not in opts:
        return None
    return prm.get(opts, name, "bool")


class Authenticator:
    """One CTAP2 authenticator instance per power cycle."""

    def __init__(self, ctx) -> None:
        strings.register()
        self.ctx = ctx
        self.state = FidoState()
        self.store = cr.CredentialStore(self.state, ctx.ms)
        self.pin = ClientPin(self.state)
        self.large_blobs = LargeBlobs(self.pin, MAX_MSG_SIZE - 64)
        self.credmgmt = CredentialManagement(self.store, self.pin)
        self._ga = None
        self.last_auth_valid = False

    # -- dispatcher --------------------------------------------------------------
    async def dispatch(self, data, chan=None) -> bytes:
        """Process one CTAPHID_CBOR message; return status || CBOR response."""
        if chan is None:
            chan = NULL_CHANNEL
        if len(data) == 0:
            return bytes((CTAP1_ERR_INVALID_LENGTH,))
        cmd = data[0]
        if cmd != CMD_GET_NEXT_ASSERTION:
            self._ga = None
        if cmd not in (CMD_CREDENTIAL_MGMT, CMD_CREDENTIAL_MGMT_PRE):
            self.credmgmt.reset_state()
        body = memoryview(bytes(data))[1:]
        try:
            if cmd == CMD_GET_INFO:
                resp = self.get_info()
            elif cmd == CMD_MAKE_CREDENTIAL:
                resp = await self.make_credential(prm.decode_request(body), chan)
            elif cmd == CMD_GET_ASSERTION:
                resp = await self.get_assertion(prm.decode_request(body), chan)
            elif cmd == CMD_GET_NEXT_ASSERTION:
                resp = self.get_next_assertion()
            elif cmd == CMD_CLIENT_PIN:
                resp = self.pin.handle(prm.decode_request(body))
            elif cmd == CMD_RESET:
                resp = await self.reset(chan)
            elif cmd in (CMD_CREDENTIAL_MGMT, CMD_CREDENTIAL_MGMT_PRE):
                req = prm.decode_request(body)
                raw = prm.raw_map_values(body) if 2 in req else {}
                resp = self.credmgmt.handle(req, raw)
            elif cmd == CMD_SELECTION:
                await self._confirm(
                    chan, Prompt("fido2.selection", "fido2.title.select", (), NORMAL, UP_TIMEOUT_MS)
                )
                resp = None
            elif cmd == CMD_LARGE_BLOBS:
                resp = self.large_blobs.handle(prm.decode_request(body))
            else:
                raise CtapError(CTAP1_ERR_INVALID_COMMAND)
        except CtapError as e:
            return bytes((e.code,))
        except StorageFull:
            return bytes((CTAP2_ERR_KEY_STORE_FULL,))
        except Exception as e:  # never leak details, never crash the transport
            log.warning(__name__, "CTAP2 command 0x%02x failed: %s", cmd, repr(e))
            return bytes((CTAP1_ERR_OTHER,))
        if not resp:
            return b"\x00"
        return b"\x00" + cbor.encode(resp)

    # -- user presence ---------------------------------------------------------------
    async def _confirm(self, chan, prompt: Prompt) -> None:
        """Wait for user presence. Maps refusal → OPERATION_DENIED, timeout →
        USER_ACTION_TIMEOUT, CTAPHID_CANCEL → KEEPALIVE_CANCEL."""
        chan.set_status(STATUS_UPNEEDED)
        start = ptime.ticks_ms()
        timed_out = False
        ok = False
        try:
            ok = await self.ctx.ui.confirm(prompt)
        except UserTimeout:
            timed_out = True
        except UserCancelled:
            ok = False
        finally:
            chan.set_status(STATUS_PROCESSING)
        self._check_outcome(chan, ok, timed_out, start, prompt.timeout_ms)

    async def _select(self, chan, title: str, options: list) -> int:
        chan.set_status(STATUS_UPNEEDED)
        start = ptime.ticks_ms()
        timed_out = False
        idx = None
        try:
            idx = await self.ctx.ui.select(title, options, UP_TIMEOUT_MS)
        except UserTimeout:
            timed_out = True
        except UserCancelled:
            idx = None
        finally:
            chan.set_status(STATUS_PROCESSING)
        ok = isinstance(idx, int) and not isinstance(idx, bool) and 0 <= idx < len(options)
        self._check_outcome(chan, ok, timed_out, start, UP_TIMEOUT_MS)
        return idx

    @staticmethod
    def _check_outcome(chan, ok, timed_out, start, timeout_ms) -> None:
        if chan.cancelled:
            raise CtapError(CTAP2_ERR_KEEPALIVE_CANCEL)
        if ok:
            return
        if timed_out or ptime.ticks_diff(ptime.ticks_ms(), start) >= timeout_ms:
            raise CtapError(CTAP2_ERR_USER_ACTION_TIMEOUT)
        raise CtapError(CTAP2_ERR_OPERATION_DENIED)

    async def _zero_length_pin_auth(self, chan) -> None:
        """§6.1.2 / §6.2.2 step 1: a zero-length pinUvAuthParam asks the
        authenticator to blink and report whether a PIN is set."""
        await self._confirm(chan, Prompt("fido2.selection", "fido2.title.select", (), NORMAL, UP_TIMEOUT_MS))
        if self.state.pin_is_set():
            raise CtapError(CTAP2_ERR_PIN_INVALID)
        raise CtapError(CTAP2_ERR_PIN_NOT_SET)

    def _check_pin_protocol(self, pin_param, proto) -> None:
        if pin_param is not None:
            if proto is None:
                raise CtapError(CTAP2_ERR_MISSING_PARAMETER)
            self.pin.protocol(proto)

    def _verify_pin_auth(self, proto, cdh: bytes, pin_param: bytes, perm: int, rp_id: str) -> None:
        """§6.1.2 step 11 / §6.2.2 step 6."""
        pin = self.pin
        if not pin.verify_token(proto, cdh, pin_param):
            raise CtapError(CTAP2_ERR_PIN_AUTH_INVALID)
        if not pin.has_permission(perm):
            raise CtapError(CTAP2_ERR_PIN_AUTH_INVALID)
        if pin.permissions_rp_id is not None and pin.permissions_rp_id != rp_id:
            raise CtapError(CTAP2_ERR_PIN_AUTH_INVALID)
        if not pin.user_verified():
            raise CtapError(CTAP2_ERR_PIN_AUTH_INVALID)
        pin.set_permissions_rp_id(rp_id)

    # -- authenticatorGetInfo (§6.4) ------------------------------------------------
    def get_info(self) -> dict:
        return {
            0x01: ["U2F_V2", "FIDO_2_0", "FIDO_2_1"],
            0x02: ["credProtect", "hmac-secret", "largeBlobKey"],
            0x03: AAGUID,
            0x04: {
                "rk": True,
                "up": True,
                "plat": False,
                "clientPin": self.state.pin_is_set(),
                "credMgmt": True,
                "largeBlobs": True,
                "pinUvAuthToken": True,
                "makeCredUvNotRqd": True,
            },
            0x05: MAX_MSG_SIZE,
            0x06: [2, 1],
            0x07: MAX_CRED_COUNT_IN_LIST,
            0x08: cr.MAX_CRED_ID_LEN,
            0x09: ["usb"],
            0x0A: [{"alg": cr.ALG_ES256, "type": "public-key"}, {"alg": cr.ALG_EDDSA, "type": "public-key"}],
            0x0B: MAX_SERIALIZED,
            0x0D: self.state.min_pin_length,
            0x0E: self.ctx.firmware_version,
            0x14: self.store.remaining(),
            0x16: ["packed", "none"],
        }

    # -- extensions ------------------------------------------------------------------
    def _hmac_secret_input(self, value):
        """Validate and decrypt the hmac-secret getAssertion input (§12.5).
        Returns ``(protocol, sharedSecret, salts)``."""
        if not isinstance(value, dict):
            raise CtapError(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        ka = prm.get(value, 1, "map", required=True)
        salt_enc = prm.get(value, 2, "bytes", required=True)
        salt_auth = prm.get(value, 3, "bytes", required=True)
        version = prm.get(value, 4, "uint")
        proto = self.pin.protocol(1 if version is None else version)
        shared = proto.decapsulate(ka)
        if not proto.verify(shared, salt_enc, salt_auth):
            raise CtapError(CTAP2_ERR_PIN_AUTH_INVALID)
        overhead = 0 if proto.version == 1 else 16
        if len(salt_enc) not in (32 + overhead, 64 + overhead):
            raise CtapError(CTAP1_ERR_INVALID_LENGTH)
        salts = proto.decrypt(shared, salt_enc)
        return proto, shared, salts

    @staticmethod
    def _hmac_secret_output(cred, uv: bool, hs):
        if hs is None or not cred.hmac_secret:
            return None
        proto, shared, salts = hs
        cred_random = cred.cred_random(uv)
        out = crypto.hmac_sha256(cred_random, salts[:32])
        if len(salts) == 64:
            out += crypto.hmac_sha256(cred_random, salts[32:])
        return proto.encrypt(shared, out)

    # -- authenticatorMakeCredential (§6.1) ---------------------------------------
    async def make_credential(self, req: dict, chan) -> dict:
        cdh = prm.get(req, 0x01, "bytes", required=True)
        rp = prm.get(req, 0x02, "map", required=True)
        user = prm.get(req, 0x03, "map", required=True)
        pkcp = prm.get(req, 0x04, "list", required=True)
        exclude = prm.get(req, 0x05, "list")
        ext = prm.get(req, 0x06, "map")
        opts = prm.get(req, 0x07, "map")
        pin_param = prm.get(req, 0x08, "bytes")
        proto = prm.get(req, 0x09, "uint")
        enterprise = prm.get(req, 0x0A, "uint")
        att_pref = prm.get(req, 0x0B, "list")

        rp_id = prm.get(rp, "id", "text", required=True)
        rp_name = prm.get(rp, "name", "text")
        user_id = prm.get(user, "id", "bytes", required=True)
        user_name = prm.get(user, "name", "text")
        display_name = prm.get(user, "displayName", "text")
        if len(cdh) != 32 or len(user_id) > cr.MAX_USER_ID_LEN:
            raise CtapError(CTAP1_ERR_INVALID_LENGTH)
        exclude_ids = _descriptor_ids(exclude) if exclude is not None else []

        if pin_param is not None and len(pin_param) == 0:
            await self._zero_length_pin_auth(chan)
        self._check_pin_protocol(pin_param, proto)

        alg = None
        for p in pkcp:
            if not isinstance(p, dict):
                raise CtapError(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
            t = prm.get(p, "type", "text", required=True)
            a = prm.get(p, "alg", "int", required=True)
            if alg is None and t == "public-key" and a in cr.SUPPORTED_ALGS:
                alg = a
        if alg is None:
            raise CtapError(CTAP2_ERR_UNSUPPORTED_ALGORITHM)

        rk = _bool_option(opts, "rk") is True
        up = _bool_option(opts, "up")
        uv_opt = _bool_option(opts, "uv")
        if up is False:
            raise CtapError(CTAP2_ERR_INVALID_OPTION)
        if uv_opt and pin_param is None:
            raise CtapError(CTAP2_ERR_INVALID_OPTION)

        uv = False
        if pin_param is not None:
            self._verify_pin_auth(proto, cdh, pin_param, PERM_MC, rp_id)
            uv = True
        elif rk and self.state.pin_is_set():
            raise CtapError(CTAP2_ERR_PUAT_REQUIRED)
        if enterprise is not None:
            raise CtapError(CTAP1_ERR_INVALID_PARAMETER)

        # extensions (CTAP 2.1 §12)
        cred_protect = None
        hmac_secret = False
        large_blob = False
        if ext is not None:
            if "credProtect" in ext:
                cred_protect = prm.get(ext, "credProtect", "uint")
                if not 1 <= cred_protect <= 3:
                    raise CtapError(CTAP2_ERR_INVALID_OPTION)
            if "hmac-secret" in ext:
                hmac_secret = prm.get(ext, "hmac-secret", "bool")
            if "largeBlobKey" in ext:
                large_blob = prm.get(ext, "largeBlobKey", "bool")
                if not large_blob or not rk:
                    raise CtapError(CTAP2_ERR_INVALID_OPTION)

        fmt = "packed"
        if att_pref is not None:
            for f in att_pref:
                if not isinstance(f, str):
                    raise CtapError(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
            for f in att_pref:
                if f in ("packed", "none"):
                    fmt = f
                    break

        rp_id_hash = crypto.sha256(rp_id.encode())
        user_name = prm.truncate_utf8(user_name, MAX_NAME_BYTES) if user_name else None
        display_name = prm.truncate_utf8(display_name, MAX_NAME_BYTES) if display_name else None
        rp_label = prm.truncate_utf8(rp_name, MAX_NAME_BYTES) if rp_name else rp_id
        account = user_name or display_name or (user_id[:8].hex() if user_id else "-")

        # excludeList (§6.1.2 step 12)
        for cid in exclude_ids:
            cred = self.store.lookup(cid, rp_id_hash)
            if cred is None:
                continue
            if cred.cred_protect == cr.PROTECT_UV_REQUIRED and not uv:
                continue
            await self._confirm(
                chan,
                Prompt(
                    "fido2.excluded",
                    "fido2.title.already_registered",
                    (("fido2.rp", rp_id), ("fido2.user", cred.label() if cred.discoverable else account)),
                    NORMAL,
                    UP_TIMEOUT_MS,
                ),
            )
            raise CtapError(CTAP2_ERR_CREDENTIAL_EXCLUDED)

        if rk:
            if len(rp_id.encode()) > cr.MAX_RP_ID_LEN:
                raise CtapError(CTAP1_ERR_INVALID_LENGTH)
            if self.store.find_user(rp_id_hash, user_id) is None and self.store.is_full():
                raise CtapError(CTAP2_ERR_KEY_STORE_FULL)

        if rp_id == BOGUS_RP_ID:
            prompt = Prompt("fido2.selection", "fido2.title.select", (), NORMAL, UP_TIMEOUT_MS)
        else:
            fields = [("fido2.rp", rp_label), ("fido2.user", account)]
            if rk:
                fields.append(("fido2.type", i18n.t("fido2.type.passkey")))
            prompt = Prompt("fido2.make_credential", "fido2.title.register", fields, SENSITIVE, UP_TIMEOUT_MS)
        await self._confirm(chan, prompt)
        if pin_param is not None:
            self.pin.clear_after_use()

        prot = cred_protect if cred_protect is not None else cr.PROTECT_UV_OPTIONAL
        key = cr.generate_key(alg)
        if rk:
            try:
                cred = self.store.create_resident(
                    rp_id, user_id, user_name, display_name, alg, key, prot, hmac_secret, large_blob
                )
            except StorageFull:
                raise CtapError(CTAP2_ERR_KEY_STORE_FULL)
        else:
            cred = self.store.wrap(rp_id_hash, alg, key, prot, hmac_secret)

        flags = FLAG_UP | FLAG_AT
        if uv:
            flags |= FLAG_UV
        if cred.backup_eligible:
            flags |= FLAG_BE
        if cred.backup_state:
            flags |= FLAG_BS
        ext_out = {}
        if cred_protect is not None:
            ext_out["credProtect"] = cred_protect
        if hmac_secret:
            ext_out["hmac-secret"] = True
        ext_bytes = b""
        if ext_out:
            flags |= FLAG_ED
            ext_bytes = cbor.encode(ext_out)
        counter = self.state.next_signature_counter()
        auth_data = (
            rp_id_hash
            + bytes((flags,))
            + counter.to_bytes(4, "big")
            + AAGUID
            + len(cred.cred_id).to_bytes(2, "big")
            + cred.cred_id
            + cbor.encode(cred.cose_public_key())
            + ext_bytes
        )
        if fmt == "packed":
            att_stmt = {"alg": cred.alg, "sig": cred.sign(auth_data + cdh)}
        else:
            att_stmt = {}
        resp = {0x01: fmt, 0x02: auth_data, 0x03: att_stmt}
        if large_blob:
            resp[0x05] = cred.large_blob_key()
        return resp

    # -- authenticatorGetAssertion (§6.2) -----------------------------------------
    def _applicable(self, rp_id_hash: bytes, allow_ids, uv: bool) -> list:
        """Applicable credentials (§6.2.2 step 7) with credProtect applied."""
        out = []
        if allow_ids:
            seen = []
            for cid in allow_ids:
                cred = self.store.lookup(cid, rp_id_hash)
                if cred is None or cred.cred_id in seen:
                    continue
                if cred.cred_protect == cr.PROTECT_UV_REQUIRED and not uv:
                    continue
                seen.append(cred.cred_id)
                out.append(cred)
            return out
        for cred in self.store.for_rp(rp_id_hash):
            if cred.cred_protect >= cr.PROTECT_UV_OPTIONAL_WITH_LIST and not uv:
                continue
            out.append(cred)
        return out

    def _assertion(self, cred, cdh, rp_id_hash, up, uv, hs, want_lbk, number=None, selected=False) -> dict:
        flags = 0
        if up:
            flags |= FLAG_UP
        if uv:
            flags |= FLAG_UV
        if cred.backup_eligible:
            flags |= FLAG_BE
        if cred.backup_state:
            flags |= FLAG_BS
        ext_out = {}
        hmac_out = self._hmac_secret_output(cred, uv, hs)
        if hmac_out is not None:
            ext_out["hmac-secret"] = hmac_out
        ext_bytes = b""
        if ext_out:
            flags |= FLAG_ED
            ext_bytes = cbor.encode(ext_out)
        counter = self.state.next_signature_counter()
        auth_data = rp_id_hash + bytes((flags,)) + counter.to_bytes(4, "big") + ext_bytes
        resp = {
            0x01: {"id": cred.cred_id, "type": "public-key"},
            0x02: auth_data,
            0x03: cred.sign(auth_data + cdh),
        }
        if cred.discoverable:
            resp[0x04] = user_entity(cred, full=uv)
        if number is not None:
            resp[0x05] = number
        if selected:
            resp[0x06] = True
        if want_lbk:
            lbk = cred.large_blob_key()
            if lbk is not None:
                resp[0x07] = lbk
        return resp

    async def get_assertion(self, req: dict, chan) -> dict:
        rp_id = prm.get(req, 0x01, "text", required=True)
        cdh = prm.get(req, 0x02, "bytes", required=True)
        allow = prm.get(req, 0x03, "list")
        ext = prm.get(req, 0x04, "map")
        opts = prm.get(req, 0x05, "map")
        pin_param = prm.get(req, 0x06, "bytes")
        proto = prm.get(req, 0x07, "uint")
        if len(cdh) != 32:
            raise CtapError(CTAP1_ERR_INVALID_LENGTH)
        allow_ids = _descriptor_ids(allow) if allow is not None else []

        if pin_param is not None and len(pin_param) == 0:
            await self._zero_length_pin_auth(chan)
        self._check_pin_protocol(pin_param, proto)

        if opts is not None and "rk" in opts:
            prm.get(opts, "rk", "bool")
            raise CtapError(CTAP2_ERR_UNSUPPORTED_OPTION)
        up = _bool_option(opts, "up")
        up = True if up is None else up
        if _bool_option(opts, "uv") and pin_param is None:
            raise CtapError(CTAP2_ERR_INVALID_OPTION)

        uv = False
        if pin_param is not None:
            self._verify_pin_auth(proto, cdh, pin_param, PERM_GA, rp_id)
            uv = True

        hs = None
        want_lbk = False
        if ext is not None:
            if "hmac-secret" in ext:
                hs = self._hmac_secret_input(ext["hmac-secret"])
            if "largeBlobKey" in ext:
                want_lbk = prm.get(ext, "largeBlobKey", "bool")
                if not want_lbk:
                    raise CtapError(CTAP2_ERR_INVALID_OPTION)

        rp_id_hash = crypto.sha256(rp_id.encode())
        creds = self._applicable(rp_id_hash, allow_ids, uv)
        self.last_auth_valid = bool(creds)
        if not creds:
            raise CtapError(CTAP2_ERR_NO_CREDENTIALS)

        selected = creds[0]
        user_selected = False
        number = None
        if up:
            if allow_ids or len(creds) == 1:
                await self._confirm(
                    chan,
                    Prompt(
                        "fido2.get_assertion",
                        "fido2.title.sign_in",
                        (
                            ("fido2.rp", rp_id),
                            ("fido2.user", selected.label() if selected.discoverable else "-"),
                        ),
                        SENSITIVE,
                        UP_TIMEOUT_MS,
                    ),
                )
            else:
                await self._confirm(
                    chan,
                    Prompt(
                        "fido2.get_assertion",
                        "fido2.title.sign_in",
                        (("fido2.rp", rp_id), ("fido2.accounts", str(len(creds)))),
                        SENSITIVE,
                        UP_TIMEOUT_MS,
                    ),
                )
                idx = await self._select(chan, "fido2.title.choose_account", [c.label() for c in creds])
                selected = creds[idx]
                user_selected = True
            if pin_param is not None:
                self.pin.clear_after_use()
        elif not allow_ids and len(creds) > 1:
            number = len(creds)
            self._ga = {
                "uids": [c.uid for c in creds[1:]],
                "cdh": cdh,
                "rp": rp_id_hash,
                "uv": uv,
                "hs": hs,
                "lbk": want_lbk,
                "t": ptime.ticks_ms(),
            }
        return self._assertion(selected, cdh, rp_id_hash, up, uv, hs, want_lbk, number, user_selected)

    def get_next_assertion(self) -> dict:
        """§6.3: only after a getAssertion that returned numberOfCredentials,
        within 30 s of the previous response, with no other command between."""
        st = self._ga
        if st is None or ptime.ticks_diff(ptime.ticks_ms(), st["t"]) >= GET_NEXT_TIMEOUT_MS:
            self._ga = None
            raise CtapError(CTAP2_ERR_NOT_ALLOWED)
        while st["uids"]:
            cred = self.store.get(st["uids"].pop(0))
            if cred is None:
                continue
            st["t"] = ptime.ticks_ms()
            if not st["uids"]:
                self._ga = None
            return self._assertion(cred, st["cdh"], st["rp"], False, st["uv"], st["hs"], st["lbk"])
        self._ga = None
        raise CtapError(CTAP2_ERR_NOT_ALLOWED)

    # -- authenticatorReset (§6.6) ---------------------------------------------------
    async def reset(self, chan) -> None:
        if self.ctx.ms_since_power_up() > RESET_WINDOW_MS:
            raise CtapError(CTAP2_ERR_NOT_ALLOWED)
        await self._confirm(chan, Prompt("fido2.reset", "fido2.title.reset", (), DANGER, UP_TIMEOUT_MS))
        self.wipe()

    def wipe(self) -> None:
        """Erase every FIDO2 credential, the PIN and the largeBlob array, and
        invalidate all non-discoverable credentials and U2F key handles."""
        self.store.wipe()
        self.state.regenerate()
        self.store.forget_keys()
        self.large_blobs.reset()
        self.pin.reset()
        self.credmgmt.reset_state()
        self._ga = None
