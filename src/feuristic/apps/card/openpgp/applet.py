# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""OpenPGP Card application v3.4 (product spec F03, §6.1, §6.3; R09).

Implemented commands (OpenPGP Card 3.4 §7.2): SELECT (via the dispatcher),
SELECT DATA (occurrence 0 of 7F21 only), GET DATA, PUT DATA, VERIFY
(including ``Lc`` absent status query and ``P1=FF`` reset), CHANGE REFERENCE
DATA, RESET RETRY COUNTER (resetting code ``P1=00`` / PW3 ``P1=02``),
GENERATE ASYMMETRIC KEY PAIR (``P1=80/81``), PSO:COMPUTE DIGITAL SIGNATURE,
PSO:DECIPHER, INTERNAL AUTHENTICATE, GET CHALLENGE (≤ 32 bytes, spec §7),
TERMINATE DF and ACTIVATE FILE.

Not implemented, by design:

* **key import** (PUT DATA odd INS ``DB`` with the ``4D`` extended header
  list) answers ``6A81``: keys are generated and managed on the device
  (spec §6.1, §6.2); identities move between devices only through the
  encrypted QR backup (:mod:`.provider`, spec §8.2);
* secure messaging, KDF-DO (``F9``), AES (``D5``), MSE, GET NEXT DATA,
  attestation.

Physical confirmation (spec §6.3, §10.10): every signature, decryption and
internal authentication, every key generation from the host, an algorithm
change that destroys a key, and TERMINATE DF show a :class:`Prompt`. A
refusal or a timeout answers ``6985`` (*conditions of use not satisfied*):
GnuPG maps it to ``GPG_ERR_USE_CONDITIONS`` and keeps its cached PIN,
whereas ``6982`` would be reported as a bad PIN.

PIN rules: PW1 ≥ 6, PW3 ≥ 8, resetting code ≥ 8, all ≤ 127 bytes (UTF-8
format, PW status bytes ``7F``). The PIN try counter (3) is consumed
**before** the comparison and persisted power-loss safely
(:class:`.storage.TryCounter`); PINs are stored as salted PBKDF2-HMAC-SHA256
references and compared in constant time. A PIN whose length is outside the
public bounds is rejected with ``6A80`` without consuming a try.
"""

from micropython import const

from ....core import i18n, tlv
from ....core.errors import InvalidInput
from ....core.interaction import DANGER, SENSITIVE, Prompt
from ....platform import crypto
from .. import apdu as iso
from ..applet import Applet
from ..ccid import HISTORICAL_BYTES
from . import const as pgp
from . import keys as alg
from . import strings as _strings  # noqa: F401 - registers the i18n table
from .storage import ZERO20, PinRef, check_pin_length
from .storage import default as _storage_default

# volatile access status indices
V_SIG = const(0)  # PW1 verified with P2=81 (PSO:CDS)
V_OTHER = const(1)  # PW1 verified with P2=82 (decipher, internal auth, private DO 0103)
V_ADMIN = const(2)  # PW3 verified

_ROLE_KEYS = ("openpgp.role.sig", "openpgp.role.dec", "openpgp.role.aut")
#: maximum DigestInfo for RSA-2048 signatures / authentication (40 % of k)
MAX_RSA_DIGEST_INFO = const(102)


def card_serial(ms: bytes) -> bytes:
    """4-byte card serial derived from the master secret (``card/serial``)."""
    return pgp.card_serial(ms)


def _err(sw: int):
    return iso.ApduError(sw)


class OpenPgpApplet(Applet):
    AID = pgp.AID_PREFIX + b"\x00\x00\x00\x00" + pgp.AID_RFU  # replaced per device
    NAME = "openpgp"

    def __init__(self, ui, ms: bytes, store=None, rsa_yield=None, rsa_progress=None) -> None:
        super().__init__(ui)
        self.serial = card_serial(ms)
        self.AID = pgp.AID_PREFIX + self.serial + pgp.AID_RFU
        self.store = store if store is not None else _storage_default()
        self.rsa_yield = rsa_yield
        self.rsa_progress = rsa_progress
        self._verified = [False, False, False]
        self._epoch = self.store.epoch

    # -- applet lifecycle --------------------------------------------------------
    def deselect(self) -> None:
        self._verified = [False, False, False]

    def _sync(self):
        if self.store.epoch != self._epoch:
            self._epoch = self.store.epoch
            self.deselect()
        return self.store.ident

    async def select(self, cmd):
        ident = self._sync()
        if ident.terminated:
            return iso.Response(b"", iso.SW_FILE_TERMINATED)
        return iso.Response(b"", iso.SW_OK)

    async def process(self, cmd):
        ident = self._sync()
        if cmd.cla != 0x00:
            raise _err(iso.SW_CLA_NOT_SUPPORTED)
        ins = cmd.ins
        if ident.terminated:
            if ins == pgp.INS_ACTIVATE_FILE:
                return self._activate(cmd)
            raise _err(iso.SW_CONDITIONS_NOT_SATISFIED)
        if ins == pgp.INS_GET_DATA:
            return self._get_data(cmd)
        if ins == pgp.INS_VERIFY:
            return self._verify(cmd)
        if ins == pgp.INS_PSO:
            return await self._pso(cmd)
        if ins == pgp.INS_INTERNAL_AUTHENTICATE:
            return await self._internal_authenticate(cmd)
        if ins == pgp.INS_PUT_DATA:
            return await self._put_data(cmd)
        if ins == pgp.INS_PUT_DATA_ODD:
            # key import (4D extended header list) is refused by design
            raise _err(iso.SW_FUNC_NOT_SUPPORTED)
        if ins == pgp.INS_GENERATE:
            return await self._generate(cmd)
        if ins == pgp.INS_CHANGE_REFERENCE_DATA:
            return self._change_reference_data(cmd)
        if ins == pgp.INS_RESET_RETRY_COUNTER:
            return self._reset_retry_counter(cmd)
        if ins == pgp.INS_GET_CHALLENGE:
            return self._get_challenge(cmd)
        if ins == pgp.INS_SELECT_DATA:
            return self._select_data(cmd)
        if ins == pgp.INS_TERMINATE_DF:
            return await self._terminate(cmd)
        if ins == pgp.INS_ACTIVATE_FILE:
            return self._activate(cmd)
        raise _err(iso.SW_INS_NOT_SUPPORTED)

    # -- data objects ---------------------------------------------------------------
    def aid(self) -> bytes:
        return self.AID

    def pw_status(self) -> bytes:
        s = self.store
        return bytes(
            (
                s.ident.pw1_status,
                pgp.PW_MAX,
                pgp.PW_MAX,
                pgp.PW_MAX,
                s.remaining(pgp.PW1),
                s.remaining(pgp.RC),
                s.remaining(pgp.PW3),
            )
        )

    def _fingerprints(self) -> bytes:
        return b"".join(k.fpr for k in self.store.ident.keys)

    def _ca_fingerprints(self) -> bytes:
        return b"".join(k.ca_fpr for k in self.store.ident.keys)

    def _dates(self) -> bytes:
        return b"".join((k.date & 0xFFFFFFFF).to_bytes(4, "big") for k in self.store.ident.keys)

    def _key_info(self) -> bytes:
        out = b""
        for i, k in enumerate(self.store.ident.keys):
            out += bytes((i + 1, k.origin))
        return out

    def _algorithm_info(self) -> bytes:
        items = []
        rsa = alg.rsa_available()
        for role, tag in ((pgp.SIG, 0xC1), (pgp.DEC, 0xC2), (pgp.AUT, 0xC3)):
            items.append((tag, pgp.ATTR_X25519 if role == pgp.DEC else pgp.ATTR_ED25519))
            if rsa:
                items.append((tag, pgp.ATTR_RSA2048))
        return tlv.build_many(items)

    def _extended_length_info(self) -> bytes:
        return tlv.build(0x02, pgp.MAX_CMD_DATA.to_bytes(2, "big")) + tlv.build(
            0x02, pgp.MAX_RSP_DATA.to_bytes(2, "big")
        )

    def _cardholder(self) -> bytes:
        ident = self.store.ident
        return tlv.build_many(((0x5B, ident.name), (0x5F2D, ident.lang), (0x5F35, ident.sex)))

    def _security_support(self) -> bytes:
        return tlv.build(0x93, self.store.signature_count().to_bytes(3, "big"))

    def application_related_data(self) -> bytes:
        ident = self.store.ident
        disc = tlv.build_many(
            (
                (0xC0, pgp.EXTENDED_CAPABILITIES),
                (0xC1, ident.keys[pgp.SIG].attr),
                (0xC2, ident.keys[pgp.DEC].attr),
                (0xC3, ident.keys[pgp.AUT].attr),
                (0xC4, self.pw_status()),
                (0xC5, self._fingerprints()),
                (0xC6, self._ca_fingerprints()),
                (0xCD, self._dates()),
                (0xDE, self._key_info()),
                (0xD6, pgp.UIF_VALUE),
                (0xD7, pgp.UIF_VALUE),
                (0xD8, pgp.UIF_VALUE),
            )
        )
        return tlv.build_many(
            (
                (0x4F, self.AID),
                (0x5F52, HISTORICAL_BYTES),
                (0x7F74, pgp.GENERAL_FEATURES),
                (0x7F66, self._extended_length_info()),
                (0x73, disc),
            )
        )

    def _get_data(self, cmd):
        """GET DATA (3.4 §7.2.6).

        The constructed DOs ``6E``, ``65``, ``7A`` and ``FA`` are returned
        with their own tag (as YubiKey/Gnuk do; ykman and GnuPG parse them
        that way). ``7F66`` and ``7F74`` return their content only (GnuPG
        reads ``7F66`` bytes 2–3 directly) and ``7F21`` the raw certificate.
        """
        if cmd.data:
            raise _err(iso.SW_WRONG_LENGTH)
        tag = cmd.p1p2
        ident = self.store.ident
        if tag == 0x4F:
            data = self.AID
        elif tag == 0x5E:
            data = ident.login
        elif tag == 0x5B:
            data = ident.name
        elif tag == 0x5F2D:
            data = ident.lang
        elif tag == 0x5F35:
            data = ident.sex
        elif tag == 0x5F50:
            data = ident.url
        elif tag == 0x5F52:
            data = HISTORICAL_BYTES
        elif tag == 0x65:
            data = tlv.build(0x65, self._cardholder())
        elif tag == 0x6E:
            data = tlv.build(0x6E, self.application_related_data())
        elif tag == 0x7A:
            data = tlv.build(0x7A, self._security_support())
        elif tag == 0x93:
            data = self.store.signature_count().to_bytes(3, "big")
        elif tag == 0x7F21:
            data = ident.cert
        elif tag == 0x7F66:
            data = self._extended_length_info()
        elif tag == 0x7F74:
            data = pgp.GENERAL_FEATURES
        elif tag == 0xC0:
            data = pgp.EXTENDED_CAPABILITIES
        elif tag in pgp.ATTR_TAGS:
            data = ident.keys[pgp.ATTR_TAGS.index(tag)].attr
        elif tag == 0xC4:
            data = self.pw_status()
        elif tag == 0xC5:
            data = self._fingerprints()
        elif tag == 0xC6:
            data = self._ca_fingerprints()
        elif tag == 0xCD:
            data = self._dates()
        elif tag == 0xDE:
            data = self._key_info()
        elif tag in pgp.UIF_TAGS:
            data = pgp.UIF_VALUE
        elif tag == 0xFA:
            data = tlv.build(0xFA, self._algorithm_info())
        elif 0x0101 <= tag <= 0x0104:
            if tag == 0x0103 and not self._verified[V_OTHER]:
                raise _err(iso.SW_SECURITY_STATUS_NOT_SATISFIED)
            if tag == 0x0104 and not self._verified[V_ADMIN]:
                raise _err(iso.SW_SECURITY_STATUS_NOT_SATISFIED)
            data = ident.private[tag - 0x0101]
        else:
            # includes F9 (KDF-DO): not supported, reported absent
            raise _err(iso.SW_REFERENCE_NOT_FOUND)
        return iso.Response(bytes(data))

    # -- PUT DATA -------------------------------------------------------------------------
    _AUX_TAGS = (0x5E, 0x5F50, 0x7F21, 0x0101, 0x0102, 0x0103, 0x0104)
    _MAIN_TAGS = (
        0x5B,
        0x5F2D,
        0x5F35,
        0xC1,
        0xC2,
        0xC3,
        0xC4,
        0xC7,
        0xC8,
        0xC9,
        0xCA,
        0xCB,
        0xCC,
        0xCE,
        0xCF,
        0xD0,
        0xD3,
        0xD6,
        0xD7,
        0xD8,
    )

    async def _put_data(self, cmd):
        tag = cmd.p1p2
        data = bytes(cmd.data)
        if tag in (0xF9, 0xD5):
            raise _err(iso.SW_FUNC_NOT_SUPPORTED)  # KDF-DO, AES key
        if tag not in self._AUX_TAGS and tag not in self._MAIN_TAGS:
            raise _err(iso.SW_REFERENCE_NOT_FOUND)
        need = V_OTHER if tag in (0x0101, 0x0103) else V_ADMIN
        if not self._verified[need]:
            raise _err(iso.SW_SECURITY_STATUS_NOT_SATISFIED)
        ident = self.store.ident
        n = len(data)
        if tag in self._AUX_TAGS:
            limit = pgp.MAX_CERT if tag == 0x7F21 else pgp.MAX_SPECIAL_DO
            if n > limit:
                raise _err(iso.SW_WRONG_LENGTH)
            if tag == 0x5E:
                ident.login = data
            elif tag == 0x5F50:
                ident.url = data
            elif tag == 0x7F21:
                ident.cert = data
            else:
                ident.private[tag - 0x0101] = data
            self.store.save(aux_changed=True)
            return iso.Response()
        if tag == 0x5B:
            if n > pgp.MAX_NAME:
                raise _err(iso.SW_WRONG_LENGTH)
            ident.name = data
        elif tag == 0x5F2D:
            if n > pgp.MAX_LANG:
                raise _err(iso.SW_WRONG_LENGTH)
            ident.lang = data
        elif tag == 0x5F35:
            if n > 1:
                raise _err(iso.SW_WRONG_LENGTH)
            if n and data not in (b"0", b"1", b"2", b"9"):
                raise _err(iso.SW_WRONG_DATA)
            ident.sex = data
        elif tag in pgp.ATTR_TAGS:
            return await self._put_attributes(pgp.ATTR_TAGS.index(tag), data)
        elif tag == 0xC4:
            if n != 1:
                raise _err(iso.SW_WRONG_LENGTH)
            if data[0] not in (0, 1):
                raise _err(iso.SW_WRONG_DATA)
            ident.pw1_status = data[0]
        elif tag in pgp.FPR_TAGS or tag in pgp.CA_FPR_TAGS:
            if n != 20:
                raise _err(iso.SW_WRONG_LENGTH)
            if tag in pgp.FPR_TAGS:
                ident.keys[pgp.FPR_TAGS.index(tag)].fpr = data
            else:
                ident.keys[pgp.CA_FPR_TAGS.index(tag)].ca_fpr = data
        elif tag in pgp.DATE_TAGS:
            if n != 4:
                raise _err(iso.SW_WRONG_LENGTH)
            ident.keys[pgp.DATE_TAGS.index(tag)].date = int.from_bytes(data, "big")
        elif tag == 0xD3:
            if n == 0:
                ident.pins[pgp.RC] = None
            else:
                self._check_new_pin(pgp.RC, data)
                ident.pins[pgp.RC] = PinRef.create(data)
            self.store.save()
            if n:
                self.store.tries[pgp.RC].clear()
            return iso.Response()
        elif tag in pgp.UIF_TAGS:
            if n != 2:
                raise _err(iso.SW_WRONG_LENGTH)
            if data[0] == 0x00:
                raise _err(iso.SW_CONDITIONS_NOT_SATISFIED)  # cannot be disabled
            if data[0] not in (0x01, 0x02):
                raise _err(iso.SW_WRONG_DATA)
            return iso.Response()  # stays "permanently enabled"
        self.store.save()
        return iso.Response()

    async def _put_attributes(self, role: int, data: bytes):
        try:
            kind = alg.parse_attr(role, data)
        except InvalidInput:
            raise _err(iso.SW_WRONG_DATA)
        attr = alg.canonical_attr(kind)
        slot = self.store.ident.keys[role]
        if attr == slot.attr:
            return iso.Response()
        if slot.present:
            fields = (
                ("openpgp.field.role", i18n.t(_ROLE_KEYS[role])),
                ("openpgp.field.algorithm", alg.display_name(slot.kind) + " > " + alg.display_name(kind)),
                ("openpgp.field.warning", i18n.t("openpgp.warn.key_lost")),
            )
            fp = slot.fpr.hex().upper() if slot.fpr != ZERO20 else None
            prompt = Prompt(
                "openpgp.attr_change", "openpgp.confirm.attr_change", fields, DANGER, fingerprint=fp
            )
            if not await self.ui.confirm(prompt):
                raise _err(iso.SW_CONDITIONS_NOT_SATISFIED)
            slot.clear()
            if role == pgp.SIG:
                self.store.reset_signature_count()
        slot.attr = attr
        self.store.save()
        return iso.Response()

    # -- PIN handling -------------------------------------------------------------------
    def _check_new_pin(self, which: int, pin) -> None:
        try:
            check_pin_length(which, pin)
        except InvalidInput:
            raise _err(iso.SW_WRONG_DATA)

    def _check_pin(self, which: int, pin) -> None:
        """Verify ``pin``; the try is consumed before the comparison."""
        store = self.store
        ref = store.ident.pins[which]
        tries = store.tries[which]
        if ref is None or tries.remaining() == 0:
            raise _err(iso.SW_AUTH_METHOD_BLOCKED)
        if not pgp.PW_MIN[which] <= len(pin) <= pgp.PW_MAX:
            raise _err(iso.SW_WRONG_DATA)
        tries.consume()  # persisted BEFORE the comparison (power-loss safe)
        if not ref.matches(pin):
            if which == pgp.PW1:
                self._verified[V_SIG] = False
                self._verified[V_OTHER] = False
            elif which == pgp.PW3:
                self._verified[V_ADMIN] = False
            raise _err(iso.SW_VERIFY_FAILED | tries.remaining())
        tries.clear()

    def _verify(self, cmd):
        p2 = cmd.p2
        if p2 == 0x81:
            which, idx = pgp.PW1, V_SIG
        elif p2 == 0x82:
            which, idx = pgp.PW1, V_OTHER
        elif p2 == 0x83:
            which, idx = pgp.PW3, V_ADMIN
        else:
            raise _err(iso.SW_INCORRECT_P1P2)
        if cmd.p1 == 0xFF:  # 3.4: reset the access status
            if cmd.data:
                raise _err(iso.SW_WRONG_LENGTH)
            self._verified[idx] = False
            return iso.Response()
        if cmd.p1 != 0x00:
            raise _err(iso.SW_INCORRECT_P1P2)
        if not cmd.data:
            if self._verified[idx]:
                return iso.Response()
            raise _err(iso.SW_VERIFY_FAILED | self.store.remaining(which))
        self._check_pin(which, bytes(cmd.data))
        self._verified[idx] = True
        return iso.Response()

    def _change_reference_data(self, cmd):
        if cmd.p1 != 0x00:
            raise _err(iso.SW_INCORRECT_P1P2)
        if cmd.p2 == 0x81:
            which = pgp.PW1
        elif cmd.p2 == 0x83:
            which = pgp.PW3
        else:
            raise _err(iso.SW_INCORRECT_P1P2)
        ref = self.store.ident.pins[which]
        if ref is None:
            raise _err(iso.SW_AUTH_METHOD_BLOCKED)
        data = bytes(cmd.data)
        old, new = data[: ref.length], data[ref.length :]
        self._check_pin(which, old)
        self._check_new_pin(which, new)
        self.store.ident.pins[which] = PinRef.create(new)
        self.store.save()
        if which == pgp.PW1:
            self._verified[V_SIG] = False
            self._verified[V_OTHER] = False
        else:
            self._verified[V_ADMIN] = False
        return iso.Response()

    def _reset_retry_counter(self, cmd):
        if cmd.p2 != 0x81:
            raise _err(iso.SW_INCORRECT_P1P2)
        data = bytes(cmd.data)
        store = self.store
        if cmd.p1 == 0x00:
            rc = store.ident.pins[pgp.RC]
            if rc is None or store.remaining(pgp.RC) == 0:
                raise _err(iso.SW_AUTH_METHOD_BLOCKED)
            self._check_pin(pgp.RC, data[: rc.length])
            new = data[rc.length :]
        elif cmd.p1 == 0x02:
            if not self._verified[V_ADMIN]:
                raise _err(iso.SW_SECURITY_STATUS_NOT_SATISFIED)
            new = data
        else:
            raise _err(iso.SW_INCORRECT_P1P2)
        self._check_new_pin(pgp.PW1, new)
        store.ident.pins[pgp.PW1] = PinRef.create(new)
        store.save()
        store.tries[pgp.PW1].clear()
        self._verified[V_SIG] = False
        self._verified[V_OTHER] = False
        return iso.Response()

    # -- key generation --------------------------------------------------------------------
    @staticmethod
    def _crt_role(data) -> int:
        try:
            items = tlv.parse(data)
        except InvalidInput:
            raise _err(iso.SW_WRONG_DATA)
        if len(items) != 1 or items[0][0] not in pgp.CRT_TAGS:
            raise _err(iso.SW_WRONG_DATA)
        role = pgp.CRT_TAGS.index(items[0][0])
        value = items[0][1]
        # optional key reference (84 01 xx) as allowed by 3.4 §7.2.14
        if value and value != bytes((0x84, 0x01, role + 1)):
            raise _err(iso.SW_WRONG_DATA)
        return role

    async def _generate(self, cmd):
        if cmd.p1 not in (0x80, 0x81) or cmd.p2 != 0x00:
            raise _err(iso.SW_INCORRECT_P1P2)
        role = self._crt_role(cmd.data)
        slot = self.store.ident.keys[role]
        if cmd.p1 == 0x81:
            if not slot.present:
                raise _err(iso.SW_REFERENCE_NOT_FOUND)
            return iso.Response(alg.public_key_do(slot.kind, slot.public()))
        if not self._verified[V_ADMIN]:
            raise _err(iso.SW_SECURITY_STATUS_NOT_SATISFIED)
        kind = slot.kind
        if kind == pgp.KIND_RSA2048 and not alg.rsa_available():
            raise _err(iso.SW_FUNC_NOT_SUPPORTED)
        replacing = slot.present
        fields = [
            ("openpgp.field.role", i18n.t(_ROLE_KEYS[role])),
            ("openpgp.field.algorithm", alg.display_name(kind)),
        ]
        if replacing:
            fields.append(("openpgp.field.warning", i18n.t("openpgp.warn.key_lost")))
        fp = slot.fpr.hex().upper() if replacing and slot.fpr != ZERO20 else None
        prompt = Prompt(
            "openpgp.generate",
            "openpgp.confirm.replace_key" if replacing else "openpgp.confirm.generate",
            fields,
            DANGER if replacing else SENSITIVE,
            fingerprint=fp,
        )
        if not await self.ui.confirm(prompt):
            raise _err(iso.SW_CONDITIONS_NOT_SATISFIED)
        secret = await alg.generate(kind, self.rsa_yield, self.rsa_progress)
        slot.set_secret(secret, pgp.ORIGIN_GENERATED)
        # the host computes the fingerprint/date and writes C7..D0 afterwards
        slot.fpr = ZERO20
        slot.date = 0
        if role == pgp.SIG:
            self.store.reset_signature_count()
        self.store.save()
        return iso.Response(alg.public_key_do(kind, slot.public()))

    # -- private key operations ----------------------------------------------------------------
    async def _confirm(self, role: int, kind_id: str, title: str, type_key: str, data, uninterpreted: bool):
        slot = self.store.ident.keys[role]
        fields = [
            ("openpgp.field.type", i18n.t(type_key)),
            ("openpgp.field.role", i18n.t(_ROLE_KEYS[role])),
            ("openpgp.field.algorithm", alg.display_name(slot.kind)),
        ]
        if slot.fpr != ZERO20:
            fp = slot.fpr.hex().upper()
        else:
            fp = None
            fields.append(("openpgp.field.pubkey_hash", crypto.sha256(slot.public())[:20].hex().upper()))
        data = bytes(data)
        if uninterpreted:
            shown = data.hex().upper() if len(data) <= 64 else crypto.sha256(data).hex().upper()
            fields.append(("openpgp.field.uninterpreted", shown))
        else:
            fields.append(("openpgp.field.input_hash", crypto.sha256(data).hex().upper()))
        prompt = Prompt(kind_id, title, fields, SENSITIVE, fingerprint=fp)
        if not await self.ui.confirm(prompt):
            raise _err(iso.SW_CONDITIONS_NOT_SATISFIED)

    def _key(self, role: int):
        slot = self.store.ident.keys[role]
        if not slot.present:
            raise _err(iso.SW_REFERENCE_NOT_FOUND)
        return slot

    async def _pso(self, cmd):
        if cmd.p1p2 == 0x9E9A:
            return await self._compute_signature(cmd)
        if cmd.p1p2 == 0x8086:
            return await self._decipher(cmd)
        if cmd.p1p2 == 0x8680:
            raise _err(iso.SW_FUNC_NOT_SUPPORTED)  # AES encipher
        raise _err(iso.SW_INCORRECT_P1P2)

    async def _compute_signature(self, cmd):
        if not self._verified[V_SIG]:
            raise _err(iso.SW_SECURITY_STATUS_NOT_SATISFIED)
        slot = self._key(pgp.SIG)
        if self.store.ident.pw1_status == 0x00:
            self._verified[V_SIG] = False  # valid for one PSO:CDS only
        data = bytes(cmd.data)
        kind = slot.kind
        if not data:
            raise _err(iso.SW_WRONG_LENGTH)
        if kind == pgp.KIND_RSA2048:
            if len(data) > MAX_RSA_DIGEST_INFO:
                raise _err(iso.SW_WRONG_LENGTH)
            type_key = "openpgp.type.rsa_pkcs1"
        else:
            type_key = "openpgp.type.eddsa"
        await self._confirm(pgp.SIG, "openpgp.sign", "openpgp.confirm.sign", type_key, data, True)
        self.store.dsc.increment()  # counted before the signature is released
        if kind == pgp.KIND_RSA2048:
            sig = alg.rsa_sign(slot.secret, data)
        else:
            sig = alg.ed25519_sign(slot.secret, data)
        return iso.Response(sig)

    async def _decipher(self, cmd):
        if not self._verified[V_OTHER]:
            raise _err(iso.SW_SECURITY_STATUS_NOT_SATISFIED)
        slot = self._key(pgp.DEC)
        data = bytes(cmd.data)
        if slot.kind == pgp.KIND_X25519:
            point = self._ecdh_point(data)
            await self._confirm(
                pgp.DEC, "openpgp.decrypt", "openpgp.confirm.decrypt", "openpgp.type.ecdh", data, False
            )
            try:
                return iso.Response(alg.x25519_shared(slot.secret, point))
            except crypto.CryptoError:
                raise _err(iso.SW_WRONG_DATA)
        # RSA: padding indicator 00 || cryptogram
        if len(data) != 1 + pgp.RSA_BYTES:
            raise _err(iso.SW_WRONG_LENGTH)
        if data[0] != 0x00:
            raise _err(iso.SW_WRONG_DATA)
        await self._confirm(
            pgp.DEC, "openpgp.decrypt", "openpgp.confirm.decrypt", "openpgp.type.rsa_decrypt", data, False
        )
        try:
            return iso.Response(alg.rsa_decrypt(slot.secret, data[1:]))
        except (InvalidInput, crypto.CryptoError):
            raise _err(iso.SW_WRONG_DATA)

    @staticmethod
    def _ecdh_point(data: bytes) -> bytes:
        """``A6 { 7F49 { 86 point } }`` (3.4 §7.2.11) → 32-byte u-coordinate."""
        try:
            outer = tlv.parse(data)
            if len(outer) != 1 or outer[0][0] != 0xA6:
                raise InvalidInput("A6")
            mid = tlv.parse(outer[0][1])
            if len(mid) != 1 or mid[0][0] != 0x7F49:
                raise InvalidInput("7F49")
            inner = tlv.parse(mid[0][1])
            if len(inner) != 1 or inner[0][0] != 0x86:
                raise InvalidInput("86")
        except InvalidInput:
            raise _err(iso.SW_WRONG_DATA)
        point = inner[0][1]
        if len(point) == 33 and point[0] == 0x40:
            point = point[1:]  # OpenPGP native-point prefix tolerated
        if len(point) != 32:
            raise _err(iso.SW_WRONG_DATA)
        return point

    async def _internal_authenticate(self, cmd):
        if cmd.p1p2 != 0x0000:
            raise _err(iso.SW_INCORRECT_P1P2)
        if not self._verified[V_OTHER]:
            raise _err(iso.SW_SECURITY_STATUS_NOT_SATISFIED)
        slot = self._key(pgp.AUT)
        data = bytes(cmd.data)
        if not data:
            raise _err(iso.SW_WRONG_LENGTH)
        kind = slot.kind
        if kind == pgp.KIND_RSA2048:
            if len(data) > MAX_RSA_DIGEST_INFO:
                raise _err(iso.SW_WRONG_LENGTH)
            type_key = "openpgp.type.rsa_pkcs1"
        else:
            type_key = "openpgp.type.eddsa"
        await self._confirm(pgp.AUT, "openpgp.auth", "openpgp.confirm.auth", type_key, data, True)
        if kind == pgp.KIND_RSA2048:
            return iso.Response(alg.rsa_sign(slot.secret, data))
        return iso.Response(alg.ed25519_sign(slot.secret, data))

    # -- misc ---------------------------------------------------------------------------------
    def _get_challenge(self, cmd):
        if cmd.p1p2 != 0x0000:
            raise _err(iso.SW_INCORRECT_P1P2)
        if cmd.data or not 1 <= cmd.ne <= pgp.MAX_CHALLENGE:
            raise _err(iso.SW_WRONG_LENGTH)
        return iso.Response(crypto.random_bytes(cmd.ne))

    def _select_data(self, cmd):
        """SELECT DATA (3.4 §7.2.5): only occurrence 0 of 7F21 exists."""
        if cmd.p2 != 0x04:
            raise _err(iso.SW_INCORRECT_P1P2)
        try:
            outer = tlv.parse(cmd.data)
            if len(outer) != 1 or outer[0][0] != 0x60:
                raise InvalidInput("60")
            inner = tlv.parse(outer[0][1])
            if len(inner) != 1 or inner[0][0] != 0x5C:
                raise InvalidInput("5C")
        except InvalidInput:
            raise _err(iso.SW_WRONG_DATA)
        if inner[0][1] != b"\x7f\x21":
            raise _err(iso.SW_REFERENCE_NOT_FOUND)
        if cmd.p1 != 0x00:
            raise _err(iso.SW_REFERENCE_NOT_FOUND)
        return iso.Response()

    async def _terminate(self, cmd):
        if cmd.p1p2 != 0x0000:
            raise _err(iso.SW_INCORRECT_P1P2)
        if cmd.data:
            raise _err(iso.SW_WRONG_LENGTH)
        if not self._verified[V_ADMIN] and self.store.remaining(pgp.PW3) != 0:
            raise _err(iso.SW_SECURITY_STATUS_NOT_SATISFIED)
        fields = (("openpgp.field.warning", i18n.t("openpgp.warn.terminate")),)
        prompt = Prompt("openpgp.terminate", "openpgp.confirm.terminate", fields, DANGER)
        if not await self.ui.confirm(prompt):
            raise _err(iso.SW_CONDITIONS_NOT_SATISFIED)
        self.store.terminate()
        self._epoch = self.store.epoch
        self.deselect()
        return iso.Response()

    def _activate(self, cmd):
        if cmd.p1p2 != 0x0000:
            raise _err(iso.SW_INCORRECT_P1P2)
        if cmd.data:
            raise _err(iso.SW_WRONG_LENGTH)
        if self.store.ident.terminated:
            self.store.activate()
            self._epoch = self.store.epoch
            self.deselect()
        return iso.Response()
