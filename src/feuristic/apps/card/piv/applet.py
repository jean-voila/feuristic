# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""PIV card application (NIST SP 800-73-4 Parts 1 & 2, SP 800-78-4).

Interoperability targets: OpenSC's ``piv`` driver (``pkcs15-tool``,
``pkcs11-tool``, ``piv-tool``) and the common ``yubico-piv-tool`` / ``ykman
piv`` operations. The normative description of what is implemented —
commands, data objects, algorithms, PIN policies and limitations — is
``docs/protocols/piv.md``; status words follow SP 800-73-4 Part 2 §3 and
ISO/IEC 7816-4 §5.6.

Product rules (spec §6.2, §6.3, §10):

* private keys are generated on the device (GENERATE ASYMMETRIC KEY PAIR or
  the local menu) or restored from a feuristic backup; host import (YubiKey
  ``IMPORT ASYMMETRIC KEY``, INS ``FE``) answers ``6D00``;
* every private-key operation is confirmed on the device with a
  :class:`~feuristic.core.interaction.Prompt` showing the operation, the slot
  role, the algorithm, the public-key fingerprint and — because PIV only
  receives raw digests / padded blocks — the label
  ``piv.sign.uninterpreted`` ("Signature d'empreinte non interprétée");
  refusal or timeout answers ``6982``;
* PIN policy per slot: 9A once per session, 9C before every use, 9D once,
  9E never (GENERATE may only make it stricter).

The applet receives de-chained commands from the dispatcher (command
chaining and GET RESPONSE are handled there) and returns complete
responses; the dispatcher splits long ones (``61xx``).
"""

from micropython import const

from ....core import kdf, tlv
from ....core.errors import InvalidInput, PinBlocked, PinInvalid, StorageCorrupted, StorageFull
from ....core.i18n import t
from ....core.interaction import DANGER, SENSITIVE, Prompt
from ....platform import crypto
from .. import apdu
from ..apdu import ApduError, Response
from ..applet import Applet
from . import consts as pc
from . import des, storage, strings

strings.register()

# --- instructions (SP 800-73-4 Part 2 Table 5 + YubiKey PIV extensions) -----
INS_VERIFY = const(0x20)
INS_CHANGE_REFERENCE = const(0x24)
INS_RESET_RETRY = const(0x2C)
INS_GENERATE = const(0x47)
INS_GENERAL_AUTHENTICATE = const(0x87)
INS_GET_DATA = const(0xCB)
INS_PUT_DATA = const(0xDB)
INS_YK_GET_METADATA = const(0xF7)
INS_YK_GET_SERIAL = const(0xF8)
INS_YK_RESET = const(0xFB)
INS_YK_GET_VERSION = const(0xFD)
INS_YK_IMPORT_KEY = const(0xFE)
INS_YK_SET_MGMKEY = const(0xFF)

#: GET VERSION answer: PIV extension level of YubiKey firmware 5.7 (AES-192
#: default administration key, GET METADATA). Not a claim to be a YubiKey.
YK_VERSION = b"\x05\x07\x00"

# SP 800-73-4 Part 1 §3.1.2: FASC-N for non-federal issuers (agency 9999,
# system 9999, credential 999999), as used by yubico-piv-tool's CHUID.
FASCN_NONFEDERAL = bytes.fromhex("D4E739DA739CED39CE739D836858210842108421C84210C3EB")
CHUID_EXPIRY = b"20301231"
CCC_CARD_ID_PREFIX = bytes.fromhex("A000000116FF02")  # GSC-IS RID, manufacturer FF, type 02

_P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

MAX_ECDSA_INPUT = const(64)

# operations (prompt kinds)
OP_SIGN = "piv.sign"
OP_RSA = "piv.rsa"
OP_ECDH = "piv.ecdh"
OP_CARD_AUTH = "piv.card_auth"


def _sw(sw: int):
    raise ApduError(sw)


def p256_on_curve(point: bytes) -> bool:
    """True if ``point`` is an uncompressed affine point of P-256 (SEC 1 §3.2.2.1)."""
    if len(point) != 65 or point[0] != 0x04:
        return False
    x = int.from_bytes(point[1:33], "big")
    y = int.from_bytes(point[33:65], "big")
    if x >= _P256_P or y >= _P256_P:
        return False
    return (y * y - (x * x * x - 3 * x + _P256_B)) % _P256_P == 0


def ecdsa_input(data: bytes) -> bytes:
    """Map the host-provided hash to the 32-byte ECDSA input (FIPS 186-4 §6.4):
    longer values keep their leftmost 256 bits, shorter ones are left-padded
    with zeros (same integer value)."""
    if not 1 <= len(data) <= MAX_ECDSA_INPUT:
        _sw(apdu.SW_WRONG_DATA)
    if len(data) >= 32:
        return bytes(data[:32])
    return bytes(32 - len(data)) + bytes(data)


def parse_dynamic_auth(data: bytes) -> dict:
    """Parse the Dynamic Authentication Template ``7C`` (SP 800-73-4 Part 2 Table 7)."""
    items = tlv.parse(data)
    if len(items) != 1 or items[0][0] != 0x7C:
        _sw(apdu.SW_WRONG_DATA)
    out = {}
    for tag, value in tlv.iterate(items[0][1]):
        if tag not in (0x80, 0x81, 0x82, 0x85) or tag in out:
            _sw(apdu.SW_WRONG_DATA)
        out[tag] = value
    return out


def _dyn(tag: int, value: bytes) -> bytes:
    return tlv.build(0x7C, tlv.build(tag, value))


class PivApplet(Applet):
    AID = pc.AID
    NAME = "piv"

    def __init__(self, ui, store=None, master_secret=None, keepalive=None, progress=None) -> None:
        """
        * ``store``: :class:`~feuristic.apps.card.piv.storage.PivStore`
          (default: the firmware-wide instance);
        * ``master_secret``: the 32-byte device master secret, or a callable
          returning it (used for the CHUID GUID, CCC card id and serial via
          ``kdf`` label ``card/serial``);
        * ``keepalive``: async callable awaited regularly during RSA key
          generation (the CCID glue sends time extensions from it);
        * ``progress``: optional callable ``progress(permille)`` for the
          RSA key generation progress screen.
        """
        super().__init__(ui)
        self._store = store
        self._ms = master_secret
        self.keepalive = keepalive
        self.progress = progress
        self._clear_state()

    # -- state -----------------------------------------------------------------
    @property
    def store(self):
        if self._store is None:
            return storage.default()
        return self._store

    def _clear_state(self) -> None:
        #: PIN verified in this session (cleared by deselect/reset/VERIFY FF)
        self.pin_verified = False
        #: PIN verified and not yet consumed by a "PIN always" slot operation
        self._pin_fresh = False
        #: administration key (9B) authenticated in this session
        self.mgmt_authenticated = False
        self._auth = None  # pending 9B challenge: (kind, value, alg)
        self._epoch = None

    def deselect(self) -> None:
        self._clear_state()

    def _derive(self, context: bytes, length: int) -> bytes:
        ms = self._ms() if callable(self._ms) else self._ms
        if ms is None:
            _sw(apdu.SW_UNKNOWN)
        return kdf.derive(ms, b"card/serial", length, context)

    # -- SELECT ------------------------------------------------------------------
    def application_property_template(self) -> bytes:
        """SP 800-73-4 Part 1 Table 3 / Part 2 §3.1.1."""
        algs = b"".join(tlv.build(0x80, bytes((a,))) for a in pc.APT_ALGS)
        algs += tlv.build(0x06, b"\x00")
        body = (
            tlv.build(0x4F, pc.PIX)
            + tlv.build(0x79, tlv.build(0x4F, pc.RID_NIST))
            + tlv.build(0x50, pc.LABEL)
            + tlv.build(0xAC, algs)
        )
        return tlv.build(0x61, body)

    async def select(self, cmd) -> Response:
        if cmd.p2 == 0x0C:  # no response data requested
            return Response()
        return Response(self.application_property_template())

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
        cla = cmd.cla & 0xEF  # chaining bit already resolved by the dispatcher
        if cla & 0x0C:
            _sw(apdu.SW_SECURE_MESSAGING_NOT_SUPPORTED)
        if cla & 0x03:
            _sw(apdu.SW_LOGICAL_CHANNEL_NOT_SUPPORTED)
        if cla != 0x00:
            _sw(apdu.SW_CLA_NOT_SUPPORTED)
        store = self.store
        if self._epoch != store.epoch:
            # credentials changed or PIV wiped (locally or by a previous
            # command): previous authentications are void
            if self._epoch is not None:
                self._clear_state()
            self._epoch = store.epoch
        ins = cmd.ins
        if not (ins == INS_GENERAL_AUTHENTICATE and cmd.p2 == pc.SLOT_MGMT):
            self._auth = None  # a 9B challenge must be answered by the next command
        if ins == INS_VERIFY:
            return self._verify(cmd)
        if ins == INS_CHANGE_REFERENCE:
            return self._change_reference(cmd)
        if ins == INS_RESET_RETRY:
            return self._reset_retry(cmd)
        if ins == INS_GENERAL_AUTHENTICATE:
            return await self._general_authenticate(cmd)
        if ins == INS_GENERATE:
            return await self._generate(cmd)
        if ins == INS_GET_DATA:
            return self._get_data(cmd)
        if ins == INS_PUT_DATA:
            return self._put_data(cmd)
        if ins == INS_YK_GET_VERSION:
            return Response(YK_VERSION)
        if ins == INS_YK_GET_SERIAL:
            return Response(self._derive(b"piv-serial", 4))
        if ins == INS_YK_GET_METADATA:
            return self._get_metadata(cmd)
        if ins == INS_YK_SET_MGMKEY:
            return await self._set_mgmt_key(cmd)
        if ins == INS_YK_RESET:
            return await self._reset(cmd)
        # INS_YK_IMPORT_KEY (spec §6.2: no private-key import), attestation,
        # SET PIN RETRIES, MOVE KEY and everything else.
        _sw(apdu.SW_INS_NOT_SUPPORTED)
        return Response()  # pragma: no cover

    # -- PIN / PUK (SP 800-73-4 Part 2 §3.2.1-3.2.3) -------------------------------
    def _check_secret(self, ref: int, padded: bytes) -> None:
        try:
            self.store.check_secret(ref, padded)
        except PinBlocked:
            _sw(apdu.SW_AUTH_METHOD_BLOCKED)
        except PinInvalid as e:
            _sw(apdu.SW_VERIFY_FAILED | min(e.retries, 15))

    def _verify(self, cmd) -> Response:
        if cmd.p2 != pc.REF_PIN:
            _sw(apdu.SW_REFERENCE_NOT_FOUND)
        if cmd.p1 == 0xFF:  # reset the security status of the PIN
            if cmd.data:
                _sw(apdu.SW_WRONG_DATA)
            self.pin_verified = False
            self._pin_fresh = False
            return Response()
        if cmd.p1 != 0x00:
            _sw(apdu.SW_INCORRECT_P1P2)
        if not cmd.data:  # query
            if self.pin_verified:
                return Response()
            left = self.store.retries_remaining(pc.REF_PIN)
            _sw(apdu.SW_AUTH_METHOD_BLOCKED if left == 0 else apdu.SW_VERIFY_FAILED | min(left, 15))
        if not storage.pin_format_ok(cmd.data):
            _sw(apdu.SW_WRONG_DATA)
        self.pin_verified = False
        self._pin_fresh = False
        self._check_secret(pc.REF_PIN, cmd.data)
        self.pin_verified = True
        self._pin_fresh = True
        return Response()

    def _change_reference(self, cmd) -> Response:
        if cmd.p1 != 0x00:
            _sw(apdu.SW_INCORRECT_P1P2)
        if cmd.p2 not in (pc.REF_PIN, pc.REF_PUK):
            _sw(apdu.SW_REFERENCE_NOT_FOUND)
        data = cmd.data
        if len(data) != 16 or not storage.pin_format_ok(data[:8]) or not storage.pin_format_ok(data[8:]):
            _sw(apdu.SW_WRONG_DATA)
        if cmd.p2 == pc.REF_PIN:
            self.pin_verified = False
            self._pin_fresh = False
        self._check_secret(cmd.p2, data[:8])
        self.store.set_secret(cmd.p2, data[8:])
        return Response()

    def _reset_retry(self, cmd) -> Response:
        if cmd.p1 != 0x00:
            _sw(apdu.SW_INCORRECT_P1P2)
        if cmd.p2 != pc.REF_PIN:
            _sw(apdu.SW_REFERENCE_NOT_FOUND)
        data = cmd.data
        if len(data) != 16 or not storage.pin_format_ok(data[:8]) or not storage.pin_format_ok(data[8:]):
            _sw(apdu.SW_WRONG_DATA)
        self._check_secret(pc.REF_PUK, data[:8])
        self.store.set_secret(pc.REF_PIN, data[8:])
        return Response()

    # -- GENERAL AUTHENTICATE (SP 800-73-4 Part 2 §3.2.4, Appendix A) -----------
    async def _general_authenticate(self, cmd) -> Response:
        d = parse_dynamic_auth(cmd.data)
        if cmd.p2 == pc.SLOT_MGMT:
            return self._mgmt_auth(cmd.p1, d)
        if cmd.p2 not in pc.KEY_SLOTS:
            _sw(apdu.SW_INCORRECT_P1P2)
        return await self._key_operation(cmd.p1, cmd.p2, d)

    @staticmethod
    def _mgmt_cipher(creds):
        if creds.mgmt_alg == pc.ALG_3DES:
            c = des.TripleDes(creds.mgmt_key)
            return c.encrypt_block, des.BLOCK_SIZE
        key = creds.mgmt_key

        def enc(block):
            return crypto.aes_ecb_encrypt_block(key, block)

        return enc, 16

    def _mgmt_auth(self, alg: int, d: dict) -> Response:
        """Administration key authentication.

        * mutual: ``7C{80 ∅}`` → ``7C{80 E(W)}``; ``7C{80 W, 81 C}`` → ``7C{82 E(C)}``
        * external: ``7C{81 ∅}`` → ``7C{81 C}``; ``7C{82 E(C)}`` → ``9000``

        Internal authentication (``7C{81 C, 82 ∅}``) is refused: it would be
        an encryption oracle answering the external-authentication challenge.
        """
        creds = self.store.creds()
        pending = self._auth
        self._auth = None
        if alg != creds.mgmt_alg:
            _sw(apdu.SW_INCORRECT_P1P2)
        encrypt, block = self._mgmt_cipher(creds)
        keys = sorted(d)
        if keys == [0x80] and not d[0x80]:
            witness = crypto.random_bytes(block)
            self._auth = ("W", witness, alg)
            return Response(_dyn(0x80, encrypt(witness)))
        if keys == [0x81] and not d[0x81]:
            challenge = crypto.random_bytes(block)
            self._auth = ("C", challenge, alg)
            return Response(_dyn(0x81, challenge))
        if keys == [0x80, 0x81]:
            if pending is None or pending[0] != "W" or pending[2] != alg:
                _sw(apdu.SW_CONDITIONS_NOT_SATISFIED)
            if len(d[0x80]) != block or len(d[0x81]) != block:
                self.mgmt_authenticated = False
                _sw(apdu.SW_WRONG_DATA)
            if not crypto.ct_equal(d[0x80], pending[1]):
                self.mgmt_authenticated = False
                _sw(apdu.SW_SECURITY_STATUS_NOT_SATISFIED)
            self.mgmt_authenticated = True
            return Response(_dyn(0x82, encrypt(d[0x81])))
        if keys == [0x82] and d[0x82]:
            if pending is None or pending[0] != "C" or pending[2] != alg:
                _sw(apdu.SW_CONDITIONS_NOT_SATISFIED)
            if len(d[0x82]) != block:
                self.mgmt_authenticated = False
                _sw(apdu.SW_WRONG_DATA)
            if not crypto.ct_equal(d[0x82], encrypt(pending[1])):
                self.mgmt_authenticated = False
                _sw(apdu.SW_SECURITY_STATUS_NOT_SATISFIED)
            self.mgmt_authenticated = True
            return Response()
        _sw(apdu.SW_WRONG_DATA)
        return Response()  # pragma: no cover

    def _require_pin(self, slotd) -> None:
        pol = slotd.pin_policy
        if pol == pc.PIN_POLICY_NEVER:
            return
        if not self.pin_verified:
            _sw(apdu.SW_SECURITY_STATUS_NOT_SATISFIED)
        if pol == pc.PIN_POLICY_ALWAYS:
            if not self._pin_fresh:
                _sw(apdu.SW_SECURITY_STATUS_NOT_SATISFIED)
            self._pin_fresh = False  # consumed by this operation

    def key_prompt(self, slotd, op: str) -> Prompt:
        """Confirmation prompt of a private-key operation (spec §6.3)."""
        fp = slotd.fingerprint()
        if op == OP_ECDH:
            title, op_key = "piv.prompt.ecdh", "piv.op.ecdh"
        elif op == OP_CARD_AUTH:
            title, op_key = "piv.prompt.cardauth", "piv.op.challenge"
        elif op == OP_RSA:
            title, op_key = "piv.prompt.decrypt", "piv.op.rsa"
        else:
            title, op_key = "piv.prompt.sign", "piv.op.sign"
        fields = [
            ("piv.field.operation", t(op_key)),
            ("piv.field.slot", f"{t(pc.SLOT_ROLE_KEYS[slotd.slot])} ({slotd.slot:02X})"),
            ("piv.field.algorithm", pc.ALG_NAME[slotd.alg]),
            ("piv.field.fingerprint", fp),
        ]
        if op != OP_ECDH:
            fields.append(("piv.field.data", t("piv.sign.uninterpreted")))
        p = Prompt(op, title, fields, SENSITIVE, fingerprint=fp)
        p.slot = slotd.slot
        return p

    async def _key_operation(self, alg: int, slot: int, d: dict) -> Response:
        slotd = self.store.get_slot(slot)
        if slotd is None or not slotd.has_key:
            _sw(apdu.SW_REFERENCE_NOT_FOUND)
        if alg != slotd.alg:
            _sw(apdu.SW_INCORRECT_P1P2)
        keys = sorted(d)
        if keys == [0x81, 0x82] and not d[0x82]:
            ecdh = False
            data = d[0x81]
        elif keys == [0x82, 0x85] and not d[0x82]:
            ecdh = True
            data = d[0x85]
        else:
            _sw(apdu.SW_WRONG_DATA)
        # key-usage separation (spec §6.2): ECDH only with the key management
        # key, ECDSA never with it; RSA cannot tell signing from decryption.
        if ecdh:
            if slot != pc.SLOT_KEYMGMT or slotd.alg != pc.ALG_P256:
                _sw(apdu.SW_WRONG_DATA)
            op = OP_ECDH
        elif slotd.alg == pc.ALG_P256:
            if slot == pc.SLOT_KEYMGMT:
                _sw(apdu.SW_WRONG_DATA)
            op = OP_CARD_AUTH if slot == pc.SLOT_CARDAUTH else OP_SIGN
        else:
            op = OP_CARD_AUTH if slot == pc.SLOT_CARDAUTH else OP_RSA
        self._require_pin(slotd)
        # validate the input before bothering the user
        if op == OP_ECDH:
            if not p256_on_curve(data):
                _sw(apdu.SW_WRONG_DATA)
        elif slotd.alg == pc.ALG_P256:
            digest = ecdsa_input(data)
        else:
            key = slotd.rsa_key()
            if len(data) != pc.RSA_BYTES or int.from_bytes(data, "big") >= int.from_bytes(key.n, "big"):
                _sw(apdu.SW_WRONG_DATA)
        if not await self.ui.confirm(self.key_prompt(slotd, op)):
            _sw(apdu.SW_SECURITY_STATUS_NOT_SATISFIED)
        try:
            if op == OP_ECDH:
                out = crypto.p256_ecdh(slotd.sk, data)
            elif slotd.alg == pc.ALG_P256:
                out = crypto.ecdsa_sig_to_der(crypto.p256_sign_digest(slotd.sk, digest))
            else:
                out = crypto.rsa_private(key, data)
        except crypto.CryptoError:
            _sw(apdu.SW_WRONG_DATA)
        return Response(_dyn(0x82, out))

    # -- GENERATE ASYMMETRIC KEY PAIR (SP 800-73-4 Part 2 §3.3.2) -----------------
    async def _generate(self, cmd) -> Response:
        if not self.mgmt_authenticated:
            _sw(apdu.SW_SECURITY_STATUS_NOT_SATISFIED)
        slot = cmd.p2
        if cmd.p1 != 0x00 or slot not in pc.KEY_SLOTS:
            _sw(apdu.SW_INCORRECT_P1P2)
        items = tlv.parse(cmd.data)
        if len(items) != 1 or items[0][0] != 0xAC:
            _sw(apdu.SW_WRONG_DATA)
        params = {}
        for tag, value in tlv.iterate(items[0][1]):
            if tag not in (0x80, 0xAA, 0xAB) or tag in params or len(value) != 1:
                _sw(apdu.SW_WRONG_DATA)
            params[tag] = value[0]
        alg = params.get(0x80)
        if alg not in pc.ASYM_ALGS:
            _sw(apdu.SW_WRONG_DATA)
        policy = pc.DEFAULT_PIN_POLICY[slot]
        req = params.get(0xAA, pc.PIN_POLICY_DEFAULT)
        if req != pc.PIN_POLICY_DEFAULT:
            # only a stricter PIN policy than the product default is honoured
            if req not in (pc.PIN_POLICY_NEVER, pc.PIN_POLICY_ONCE, pc.PIN_POLICY_ALWAYS) or req < policy:
                _sw(apdu.SW_WRONG_DATA)
            policy = req
        # every operation is confirmed on the device: touch "never" cannot be honoured
        if params.get(0xAB, pc.TOUCH_POLICY_DEFAULT) not in (
            pc.TOUCH_POLICY_DEFAULT,
            pc.TOUCH_POLICY_ALWAYS,
            pc.TOUCH_POLICY_CACHED,
        ):
            _sw(apdu.SW_WRONG_DATA)
        existing = self.store.get_slot(slot)
        if not await self.ui.confirm(generate_prompt(slot, alg, existing)):
            _sw(apdu.SW_SECURITY_STATUS_NOT_SATISFIED)
        new = await generate_slot_key(slot, alg, policy, self.keepalive, self.progress)
        self.store.put_slot(new)
        return Response(tlv.build(0x7F49, new.public_tlv()))

    # -- GET DATA / PUT DATA (SP 800-73-4 Part 2 §3.1.2, §3.3.1) ------------------
    @staticmethod
    def _object_tag(value: bytes) -> int:
        if not 1 <= len(value) <= 3:
            _sw(apdu.SW_WRONG_DATA)
        return int.from_bytes(value, "big")

    def _get_data(self, cmd) -> Response:
        if cmd.p1p2 != 0x3FFF:
            _sw(apdu.SW_INCORRECT_P1P2)
        items = tlv.parse(cmd.data)
        if len(items) != 1 or items[0][0] != 0x5C:
            _sw(apdu.SW_WRONG_DATA)
        return Response(self.read_object(self._object_tag(items[0][1])))

    def read_object(self, tag: int) -> bytes:
        """Complete BER-TLV encoding of data object ``tag`` (``53``/``7E`` template)."""
        s = self.store
        if tag == pc.OBJ_DISCOVERY:
            # PIN usage policy 0x40 0x00: PIV Card Application PIN only
            return tlv.build(0x7E, tlv.build(0x4F, pc.AID) + tlv.build(0x5F2F, b"\x40\x00"))
        if tag in pc.CERT_OBJECTS:
            slotd = s.get_slot(pc.CERT_OBJECTS[tag])
            if slotd is None or slotd.cert is None:
                _sw(apdu.SW_FILE_NOT_FOUND)
            body = (
                tlv.build(0x70, slotd.cert) + tlv.build(0x71, bytes((slotd.certinfo,))) + tlv.build(0xFE, b"")
            )
            return tlv.build(0x53, body)
        if tag not in pc.DATA_OBJECT_CAPS:
            _sw(apdu.SW_FILE_NOT_FOUND)
        if tag == pc.OBJ_PRINTED and not self.pin_verified:
            _sw(apdu.SW_SECURITY_STATUS_NOT_SATISFIED)  # access rule: PIN
        stored = s.get_object(tag)
        if stored is not None:
            return tlv.build(0x53, stored)
        if tag == pc.OBJ_CHUID:
            body = (
                tlv.build(0x30, FASCN_NONFEDERAL)
                + tlv.build(0x34, self._derive(b"piv-guid", 16))
                + tlv.build(0x35, CHUID_EXPIRY)
                + tlv.build(0x3E, b"")
                + tlv.build(0xFE, b"")
            )
            return tlv.build(0x53, body)
        if tag == pc.OBJ_CCC:
            body = tlv.build(0xF0, CCC_CARD_ID_PREFIX + self._derive(b"piv-ccc", 14))
            body += bytes.fromhex("F10121F20121F300F40100F50110F600F700FA00FB00FC00FD00FE00")
            return tlv.build(0x53, body)
        if tag == pc.OBJ_KEY_HISTORY:
            # retired key slots are not supported: no on-card / off-card history
            body = tlv.build(0xC1, b"\x00") + tlv.build(0xC2, b"\x00") + tlv.build(0xFE, b"")
            return tlv.build(0x53, body)
        _sw(apdu.SW_FILE_NOT_FOUND)
        return b""  # pragma: no cover

    def _put_data(self, cmd) -> Response:
        if not self.mgmt_authenticated:
            _sw(apdu.SW_SECURITY_STATUS_NOT_SATISFIED)
        if cmd.p1p2 != 0x3FFF:
            _sw(apdu.SW_INCORRECT_P1P2)
        items = tlv.parse(cmd.data)
        if len(items) != 2 or items[0][0] != 0x5C or items[1][0] != 0x53:
            _sw(apdu.SW_WRONG_DATA)
        tag = self._object_tag(items[0][1])
        value = items[1][1]
        if tag in pc.CERT_OBJECTS:
            self._put_certificate(pc.CERT_OBJECTS[tag], value)
            return Response()
        cap = pc.DATA_OBJECT_CAPS.get(tag)
        if cap is None:  # unknown or read-only (Discovery) object
            _sw(apdu.SW_WRONG_DATA)
        if len(value) > cap:
            _sw(apdu.SW_NOT_ENOUGH_MEMORY)
        if value:
            tlv.parse(value)  # strict BER-TLV content (raises -> 6A80)
        self.store.put_object(tag, value or None)
        return Response()

    def _put_certificate(self, slot: int, value: bytes) -> None:
        s = self.store
        slotd = s.get_slot(slot) or storage.SlotData(slot)
        if not value:  # empty 53: delete the certificate
            slotd.cert = None
            slotd.certinfo = 0
            s.put_slot(slotd)
            return
        seen = {}
        for tag, v in tlv.iterate(value):
            if tag not in (0x70, 0x71, 0xFE) or tag in seen:
                _sw(apdu.SW_WRONG_DATA)
            seen[tag] = v
        cert = seen.get(0x70)
        info = seen.get(0x71, b"\x00")
        if not cert or len(info) != 1 or info[0] not in (0x00, 0x01) or seen.get(0xFE, b"") != b"":
            _sw(apdu.SW_WRONG_DATA)
        if len(cert) > pc.MAX_CERT_LEN:
            _sw(apdu.SW_NOT_ENOUGH_MEMORY)
        slotd.cert = bytes(cert)
        slotd.certinfo = info[0]
        s.put_slot(slotd)

    # -- YubiKey-compatible extensions ---------------------------------------------
    def _get_metadata(self, cmd) -> Response:
        if cmd.p1 != 0x00:
            _sw(apdu.SW_INCORRECT_P1P2)
        ref = cmd.p2
        s = self.store
        creds = s.creds()
        if ref in (pc.REF_PIN, pc.REF_PUK):
            bit = storage.FLAG_PIN_DEFAULT if ref == pc.REF_PIN else storage.FLAG_PUK_DEFAULT
            body = (
                tlv.build(0x01, b"\xff")
                + tlv.build(0x05, b"\x01" if creds.flags & bit else b"\x00")
                + tlv.build(0x06, bytes((s.max_retries(ref), s.retries_remaining(ref))))
            )
        elif ref == pc.SLOT_MGMT:
            body = (
                tlv.build(0x01, bytes((creds.mgmt_alg,)))
                + tlv.build(0x02, bytes((pc.PIN_POLICY_NEVER, pc.TOUCH_POLICY_NEVER)))
                + tlv.build(0x05, b"\x01" if creds.flags & storage.FLAG_MGMT_DEFAULT else b"\x00")
            )
        elif ref in pc.KEY_SLOTS:
            slotd = s.get_slot(ref)
            if slotd is None or not slotd.has_key:
                _sw(apdu.SW_REFERENCE_NOT_FOUND)
            body = (
                tlv.build(0x01, bytes((slotd.alg,)))
                + tlv.build(0x02, bytes((slotd.pin_policy, pc.TOUCH_POLICY_ALWAYS)))
                + tlv.build(0x03, bytes((slotd.origin,)))
                + tlv.build(0x04, slotd.public_tlv())
            )
        else:
            _sw(apdu.SW_REFERENCE_NOT_FOUND)
        return Response(body)

    async def _set_mgmt_key(self, cmd) -> Response:
        if not self.mgmt_authenticated:
            _sw(apdu.SW_SECURITY_STATUS_NOT_SATISFIED)
        if cmd.p1 != 0xFF or cmd.p2 not in (0xFF, 0xFE):
            _sw(apdu.SW_INCORRECT_P1P2)
        data = cmd.data
        if len(data) < 3 or data[1] != pc.SLOT_MGMT or data[2] != len(data) - 3:
            _sw(apdu.SW_WRONG_DATA)
        alg = data[0]
        key = bytes(data[3:])
        if pc.MGMT_ALGS.get(alg) != len(key):
            _sw(apdu.SW_WRONG_DATA)
        fields = [
            ("piv.field.algorithm", pc.MGMT_ALG_NAME[alg]),
            ("piv.field.warning", t("piv.warn.mgmt_host")),
        ]
        if not await self.ui.confirm(Prompt("piv.set_mgmt_key", "piv.prompt.set_mgmt", fields, SENSITIVE)):
            _sw(apdu.SW_SECURITY_STATUS_NOT_SATISFIED)
        self.store.set_mgmt_key(alg, key)
        return Response()

    async def _reset(self, cmd) -> Response:
        """YubiKey-style PIV reset, allowed only when both PIN and PUK are blocked."""
        if cmd.p1p2 != 0x0000:
            _sw(apdu.SW_INCORRECT_P1P2)
        s = self.store
        if not (s.is_blocked(pc.REF_PIN) and s.is_blocked(pc.REF_PUK)):
            _sw(apdu.SW_CONDITIONS_NOT_SATISFIED)
        if not await self.ui.confirm(reset_prompt()):
            _sw(apdu.SW_SECURITY_STATUS_NOT_SATISFIED)
        s.wipe()
        self._clear_state()
        return Response()


# ---------------------------------------------------------------------------
# helpers shared with localmgmt
# ---------------------------------------------------------------------------


def generate_prompt(slot: int, alg: int, existing) -> Prompt:
    replacing = existing is not None and (existing.has_key or existing.cert is not None)
    fields = [
        ("piv.field.slot", f"{t(pc.SLOT_ROLE_KEYS[slot])} ({slot:02X})"),
        ("piv.field.algorithm", pc.ALG_NAME[alg]),
    ]
    if replacing:
        fields.append(("piv.field.warning", t("piv.warn.replace")))
    title = "piv.prompt.replace" if replacing else "piv.prompt.generate"
    p = Prompt("piv.generate", title, fields, DANGER if replacing else SENSITIVE)
    p.slot = slot
    return p


def reset_prompt() -> Prompt:
    return Prompt("piv.reset", "piv.prompt.reset", [("piv.field.warning", t("piv.warn.reset"))], DANGER)


async def generate_slot_key(slot: int, alg: int, pin_policy: int, keepalive=None, progress=None):
    """Generate a fresh key for ``slot`` (certificate dropped). Returns :class:`SlotData`."""
    if alg == pc.ALG_P256:
        sk = crypto.p256_generate()
        return storage.SlotData(slot, alg, sk=sk, pub=crypto.p256_public(sk), pin_policy=pin_policy)
    if alg != pc.ALG_RSA2048:
        raise InvalidInput("PIV algorithm")
    try:
        from ....core import rsa as _rsa
    except ImportError:
        raise ApduError(apdu.SW_FUNC_NOT_SUPPORTED)
    key = await _rsa.generate(bits=pc.RSA_BITS, e=pc.RSA_E, progress=progress, yield_fn=keepalive)
    half = pc.RSA_BYTES // 2
    p = bytes(key.p)
    q = bytes(key.q)
    if len(p) != half or len(q) != half or key.e != pc.RSA_E:
        raise ApduError(apdu.SW_UNKNOWN)
    return storage.SlotData(slot, alg, p=p, q=q, e=key.e, pin_policy=pin_policy)
