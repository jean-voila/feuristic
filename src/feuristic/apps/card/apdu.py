# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""ISO/IEC 7816-4 command/response APDUs.

Supports cases 1–4 in short and extended form. Command chaining (CLA bit
0x10) and response chaining (``61xx`` + GET RESPONSE) are handled by
:mod:`feuristic.apps.card.dispatcher`, not here.
"""

from micropython import const

from ...core.errors import InvalidInput

# --- status words -----------------------------------------------------------
SW_OK = const(0x9000)
SW_BYTES_REMAINING = const(0x6100)  # | remaining (0x00 = 256 or more)
SW_WARNING_NV_UNCHANGED = const(0x6200)
SW_FILE_DEACTIVATED = const(0x6283)  # selected file deactivated (ISO 7816-4)
SW_FILE_TERMINATED = const(0x6285)  # selected file in termination state (ISO 7816-4, OpenPGP 3.4 §7.2.17)
SW_VERIFY_FAILED = const(0x63C0)  # | retries left
SW_EXEC_ERROR = const(0x6400)
SW_MEMORY_FAILURE = const(0x6581)
SW_SECURITY_ISSUE = const(0x6600)  # GnuPG "SW_ACK_TIMEOUT" (Gnuk/YubiKey touch timeout)
SW_WRONG_LENGTH = const(0x6700)
SW_LOGICAL_CHANNEL_NOT_SUPPORTED = const(0x6881)
SW_SECURE_MESSAGING_NOT_SUPPORTED = const(0x6882)
SW_LAST_COMMAND_OF_CHAIN_EXPECTED = const(0x6883)
SW_CHAINING_NOT_SUPPORTED = const(0x6884)
SW_SECURITY_STATUS_NOT_SATISFIED = const(0x6982)
SW_AUTH_METHOD_BLOCKED = const(0x6983)
SW_DATA_INVALID = const(0x6984)
SW_CONDITIONS_NOT_SATISFIED = const(0x6985)
SW_COMMAND_NOT_ALLOWED = const(0x6986)
SW_WRONG_DATA = const(0x6A80)
SW_FUNC_NOT_SUPPORTED = const(0x6A81)
SW_FILE_NOT_FOUND = const(0x6A82)
SW_RECORD_NOT_FOUND = const(0x6A83)
SW_NOT_ENOUGH_MEMORY = const(0x6A84)
SW_INCORRECT_P1P2 = const(0x6A86)
SW_REFERENCE_NOT_FOUND = const(0x6A88)
SW_WRONG_P1P2 = const(0x6B00)
SW_WRONG_LE = const(0x6C00)  # | exact length
SW_INS_NOT_SUPPORTED = const(0x6D00)
SW_CLA_NOT_SUPPORTED = const(0x6E00)
SW_UNKNOWN = const(0x6F00)

MAX_SHORT_LC = const(255)
MAX_EXTENDED_LC = const(65535)
MAX_SHORT_NE = const(256)
MAX_EXTENDED_NE = const(65536)

# feuristic accepts command data up to this size after chaining/extension
MAX_COMMAND_DATA = const(4096)


class ApduError(Exception):
    """Raised by applets to answer with a specific status word."""

    def __init__(self, sw: int) -> None:
        super().__init__(hex(sw))
        self.sw = sw


class Command:
    """A parsed command APDU.

    ``ne`` is the expected response length: ``0`` when absent (case 1/3),
    otherwise ``1..65536`` (``Le=00`` → 256, extended ``Le=0000`` → 65536).
    """

    def __init__(
        self, cla: int, ins: int, p1: int, p2: int, data: bytes = b"", ne: int = 0, extended: bool = False
    ) -> None:
        self.cla = cla
        self.ins = ins
        self.p1 = p1
        self.p2 = p2
        self.data = data
        self.ne = ne
        self.extended = extended

    @property
    def chained(self) -> bool:
        """True if this is a non-final part of a command chain (CLA b5)."""
        return bool(self.cla & 0x10)

    @property
    def p1p2(self) -> int:
        return (self.p1 << 8) | self.p2

    def __repr__(self) -> str:
        head = f"{self.cla:02x} {self.ins:02x} {self.p1:02x} {self.p2:02x}"
        return f"Command({head} lc={len(self.data)} ne={self.ne})"


def parse(raw) -> Command:
    """Parse a command APDU (raises :class:`InvalidInput` on malformed input)."""
    raw = bytes(raw)
    n = len(raw)
    if n < 4:
        raise InvalidInput("APDU too short")
    cla, ins, p1, p2 = raw[0], raw[1], raw[2], raw[3]
    if cla == 0xFF:
        raise InvalidInput("invalid CLA")
    if n == 4:  # case 1
        return Command(cla, ins, p1, p2)
    if n == 5:  # case 2 short
        return Command(cla, ins, p1, p2, b"", raw[4] or 256)
    if raw[4] != 0:  # short case 3/4
        lc = raw[4]
        if n == 5 + lc:
            return Command(cla, ins, p1, p2, raw[5:], 0)
        if n == 6 + lc:
            return Command(cla, ins, p1, p2, raw[5 : 5 + lc], raw[5 + lc] or 256)
        raise InvalidInput("APDU length mismatch")
    # extended forms: raw[4] == 0
    if n == 7:  # case 2 extended
        le = (raw[5] << 8) | raw[6]
        return Command(cla, ins, p1, p2, b"", le or 65536, True)
    if n < 7:
        raise InvalidInput("APDU length mismatch")
    lc = (raw[5] << 8) | raw[6]
    if lc == 0:
        raise InvalidInput("extended Lc of zero")
    if n == 7 + lc:
        return Command(cla, ins, p1, p2, raw[7:], 0, True)
    if n == 9 + lc:
        le = (raw[7 + lc] << 8) | raw[8 + lc]
        return Command(cla, ins, p1, p2, raw[7 : 7 + lc], le or 65536, True)
    raise InvalidInput("APDU length mismatch")


def build(cla: int, ins: int, p1: int, p2: int, data: bytes = b"", ne: int = 0) -> bytes:
    """Build a command APDU (short form when possible). Used by tests/tools."""
    head = bytes((cla, ins, p1, p2))
    ext = len(data) > MAX_SHORT_LC or ne > 256
    if not ext:
        out = head
        if data:
            out += bytes((len(data),)) + bytes(data)
        if ne:
            out += bytes((ne & 0xFF,))
        return out
    out = head + b"\x00"
    if data:
        out += len(data).to_bytes(2, "big") + bytes(data)
    if ne:
        out += (ne & 0xFFFF).to_bytes(2, "big")
    return out


class Response:
    def __init__(self, data: bytes = b"", sw: int = SW_OK) -> None:
        self.data = data
        self.sw = sw

    def encode(self) -> bytes:
        return bytes(self.data) + self.sw.to_bytes(2, "big")

    def __repr__(self) -> str:
        return f"Response(len={len(self.data)}, sw={self.sw:04x})"
