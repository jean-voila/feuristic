# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""USB CCID (Rev 1.1) message layer of the feuristic virtual card reader.

The kernel CCID class (docs/architecture.md §5.3) only shuttles raw bulk
packets of at most 64 bytes. Everything else lives here, as a **pure,
synchronous state machine** that is fed bulk-OUT packets and produces
complete ``RDR_to_PC`` messages:

* message assembly by ``dwLength`` with a hard bound
  (:data:`MAX_MESSAGE_LENGTH`), resynchronisation on short packets,
  rejection of oversized/truncated transfers;
* slot 0 only, ``bSeq`` echo, ``bStatus``/``bError`` per CCID Rev 1.1 §6.2.6;
* ``PC_to_RDR_IccPowerOn`` (ATR, :func:`atr`), ``IccPowerOff``,
  ``GetSlotStatus``, ``XfrBlock`` (short and extended APDU level, including
  the ``wLevelParameter`` / ``bChainParameter`` chaining of §6.1.4 and
  §6.2.1 for APDUs that do not fit into one message), ``GetParameters`` /
  ``SetParameters`` / ``ResetParameters`` (T=1 protocol data structure,
  §6.1.7), ``SetDataRateAndClockFrequency``, ``Abort``, ``Escape`` (refused
  with ``CMD_NOT_SUPPORTED``) and every other optional command (refused);
* busy handling (``bMaxCCIDBusySlots`` = 1): while an APDU is being processed
  every new command except ``Abort`` is answered ``CMD_SLOT_BUSY``;
* time extension (``bmCommandStatus`` = 2, ``bError`` = multiplier, §6.2.6)
  messages for the APDU in progress (:meth:`CcidSlot.time_extension`), sent
  by the glue every :data:`WTX_INTERVAL_MS` while an applet waits for the
  user;
* ``RDR_to_PC_NotifySlotChange`` interrupt message builder.

APDU processing itself is asynchronous and done by
:class:`feuristic.apps.card.card.Card`, which owns a :class:`CcidSlot` and the
:class:`~feuristic.apps.card.dispatcher.Dispatcher`.

Bulk-IN packetisation (:func:`packetize`) appends an explicit zero-length
packet marker (``b""``) when a message length is a multiple of the packet
size, because the host (libccid) posts reads larger than the message and
would otherwise wait for more data (USB 2.0 §5.8.3).

The class descriptor exposed by the kernel must mirror
:func:`class_descriptor` byte for byte (see docs/protocols/ccid.md).
"""

from micropython import const

from . import apdu as _apdu

# ---------------------------------------------------------------------------
# message types (CCID Rev 1.1 §6.1, §6.2, §6.3)
# ---------------------------------------------------------------------------
PC_TO_RDR_SET_PARAMETERS = const(0x61)
PC_TO_RDR_ICC_POWER_ON = const(0x62)
PC_TO_RDR_ICC_POWER_OFF = const(0x63)
PC_TO_RDR_GET_SLOT_STATUS = const(0x65)
PC_TO_RDR_SECURE = const(0x69)
PC_TO_RDR_T0_APDU = const(0x6A)
PC_TO_RDR_ESCAPE = const(0x6B)
PC_TO_RDR_GET_PARAMETERS = const(0x6C)
PC_TO_RDR_RESET_PARAMETERS = const(0x6D)
PC_TO_RDR_ICC_CLOCK = const(0x6E)
PC_TO_RDR_XFR_BLOCK = const(0x6F)
PC_TO_RDR_MECHANICAL = const(0x71)
PC_TO_RDR_ABORT = const(0x72)
PC_TO_RDR_SET_DATA_RATE_AND_CLOCK = const(0x73)

RDR_TO_PC_DATA_BLOCK = const(0x80)
RDR_TO_PC_SLOT_STATUS = const(0x81)
RDR_TO_PC_PARAMETERS = const(0x82)
RDR_TO_PC_ESCAPE = const(0x83)
RDR_TO_PC_DATA_RATE_AND_CLOCK = const(0x84)

RDR_TO_PC_NOTIFY_SLOT_CHANGE = const(0x50)
RDR_TO_PC_HARDWARE_ERROR = const(0x51)

# class-specific control requests (§5.3); handled by the kernel
REQUEST_ABORT = const(0x01)
REQUEST_GET_CLOCK_FREQUENCIES = const(0x02)
REQUEST_GET_DATA_RATES = const(0x03)

# ---------------------------------------------------------------------------
# bStatus / bError (§6.2.6)
# ---------------------------------------------------------------------------
ICC_ACTIVE = const(0x00)  # ICC present and active
ICC_INACTIVE = const(0x01)  # ICC present, inactive (powered off)
ICC_ABSENT = const(0x02)  # no ICC present

CMD_OK = const(0x00)
CMD_FAILED = const(0x40)
CMD_TIME_EXTENSION = const(0x80)

ERR_CMD_NOT_SUPPORTED = const(0x00)
ERR_CMD_ABORTED = const(0xFF)
ERR_ICC_MUTE = const(0xFE)
ERR_XFR_PARITY_ERROR = const(0xFD)
ERR_XFR_OVERRUN = const(0xFC)
ERR_HW_ERROR = const(0xFB)
ERR_BAD_ATR_TS = const(0xF8)
ERR_BAD_ATR_TCK = const(0xF7)
ERR_ICC_PROTOCOL_NOT_SUPPORTED = const(0xF6)
ERR_ICC_CLASS_NOT_SUPPORTED = const(0xF5)
ERR_PROCEDURE_BYTE_CONFLICT = const(0xF4)
ERR_DEACTIVATED_PROTOCOL = const(0xF3)
ERR_BUSY_WITH_AUTO_SEQUENCE = const(0xF2)
ERR_PIN_TIMEOUT = const(0xF0)
ERR_PIN_CANCELLED = const(0xEF)
ERR_CMD_SLOT_BUSY = const(0xE0)
# "1..127: index of the not supported / incorrect message parameter"
ERR_OFFSET_DW_LENGTH = const(1)
ERR_OFFSET_SLOT = const(5)
ERR_OFFSET_BYTE7 = const(7)  # bPowerSelect / bProtocolNum / bBWI
ERR_OFFSET_LEVEL = const(8)  # wLevelParameter

# ---------------------------------------------------------------------------
# reader capabilities (class descriptor, §5.1)
# ---------------------------------------------------------------------------
HEADER_LEN = const(10)
PACKET_SIZE = const(64)  # bulk wMaxPacketSize (full speed)
INTERRUPT_PACKET_SIZE = const(8)

#: dwMaxCCIDMessageLength: header + 4096 bytes of abData. Matches the kernel
#: descriptor. A short APDU always fits; an extended APDU carrying more than
#: 4096 - 9 data bytes (max 4096 + 9 with feuristic's MAX_COMMAND_DATA) is
#: split by the host with wLevelParameter chaining, which this module
#: reassembles (bounded by MAX_APDU_LENGTH).
MAX_MESSAGE_LENGTH = const(4096 + 10)
MAX_DATA_LENGTH = const(4096)
#: largest command APDU accepted after XfrBlock-level chaining
MAX_APDU_LENGTH = 4 + 3 + _apdu.MAX_COMMAND_DATA + 2
#: largest response APDU this layer will chain to the host
MAX_RESPONSE_LENGTH = const(65536 + 2)

BCD_CCID = const(0x0110)
MAX_SLOT_INDEX = const(0)
VOLTAGE_SUPPORT = const(0x07)  # 5.0 V, 3.0 V, 1.8 V (virtual card: any)
PROTOCOLS = const(0x00000002)  # T=1 only
DEFAULT_CLOCK_KHZ = const(4000)
MAXIMUM_CLOCK_KHZ = const(4000)
DATA_RATE_BPS = const(10752)  # 4 MHz / 372
MAX_DATA_RATE_BPS = const(10752)
MAX_IFSD = const(254)
SYNCH_PROTOCOLS = const(0)
MECHANICAL = const(0)
#: 0x02 automatic parameter configuration based on ATR
#: 0x04 automatic activation of ICC on inserting
#: 0x08 automatic ICC voltage selection
#: 0x10 automatic ICC clock frequency change
#: 0x20 automatic baud rate change
#: 0x40 automatic parameters negotiation (libccid then never sends PPS or
#:      SetParameters on its own)
#: 0x80 automatic PPS
#: 0x00040000 short and extended APDU level exchange
FEATURES = const(0x000400FE)
CLASS_GET_RESPONSE = const(0xFF)  # echo the APDU class byte
CLASS_ENVELOPE = const(0xFF)
LCD_LAYOUT = const(0x0000)
PIN_SUPPORT = const(0x00)
MAX_BUSY_SLOTS = const(1)

#: interval at which the glue sends time-extension messages while an APDU is
#: pending. libccid reads bulk-IN with a timeout of at least 3 s
#: (DEFAULT_COM_READ_TIMEOUT) and restarts the read on every time-extension
#: message; 1 s leaves a 3x margin for USB scheduling and slow event loops.
WTX_INTERVAL_MS = const(1000)
#: bError of a time-extension message (BWT multiplier). libccid only logs it
#: (or multiplies its *current* read timeout by it); 1 keeps the host
#: timeout bounded.
WTX_MULTIPLIER = const(1)

# ---------------------------------------------------------------------------
# ATR (ISO/IEC 7816-3 §8)
# ---------------------------------------------------------------------------
#: Historical bytes (ISO/IEC 7816-4 §8.1.1), shared by every application and
#: returned by OpenPGP GET DATA 5F52:
#:
#: * ``00``        category indicator: status indicator in the last 3 bytes
#: * ``31 C1``     card service data: selection by full and by partial DF
#:   name, card without MF
#: * ``73 C0 01 C0`` card capabilities: (1) selection by full/partial DF name;
#:   (2) data coding byte, data unit = 1 byte; (3) **command chaining and
#:   extended Lc/Le supported**, no logical channels
#: * ``05 90 00``  status indicator: LCS = operational (activated), SW 9000
HISTORICAL_BYTES = b"\x00\x31\xc1\x73\xc0\x01\xc0\x05\x90\x00"

#: Interface bytes:
#: ``TS=3B`` direct convention; ``T0=DA`` (TA1, TC1, TD1 present, K=10);
#: ``TA1=11`` Fi=372/Di=1; ``TC1=FF`` minimal guard time; ``TD1=81`` TD2
#: present, T=1; ``TD2=B1`` TA3, TB3, TD3 present, T=1; ``TA3=FE`` IFSC=254;
#: ``TB3=75`` BWI=7 (≈11 s at 4 MHz), CWI=5; ``TD3=1F`` TA4 present, T=15;
#: ``TA4=03`` class A and B (5 V, 3 V), no clock stop. TCK follows the
#: historical bytes (mandatory because T=1 is indicated).
_ATR_INTERFACE = b"\x3b\xda\x11\xff\x81\xb1\xfe\x75\x1f\x03"

# T=1 protocol data structure (§6.1.7, Table 6.1-8) derived from the ATR:
# bmFindexDindex, bmTCCKST1 (LRC, direct), bGuardTimeT1, bmWaitingIntegersT1,
# bClockStop, bIFSC, bNadValue
DEFAULT_T1_PARAMETERS = b"\x11\x10\xff\x75\x00\xfe\x00"


def atr() -> bytes:
    """Return the ATR of the virtual card (TCK computed)."""
    body = _ATR_INTERFACE + HISTORICAL_BYTES
    tck = 0
    for b in body[1:]:
        tck ^= b
    return body + bytes((tck,))


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _le32(v: int) -> bytes:
    return bytes((v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF, (v >> 24) & 0xFF))


def _le16(v: int) -> bytes:
    return bytes((v & 0xFF, (v >> 8) & 0xFF))


def _rd32(b, off: int) -> int:
    return b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)


def class_descriptor() -> list:
    """All fields of the CCID class descriptor (Table 5.1-1), in order.

    Returns ``[(name, size_in_bytes, value), ...]``; multi-byte values are
    little-endian on the wire. The kernel C descriptor must mirror this.
    """
    return [
        ("bLength", 1, 0x36),
        ("bDescriptorType", 1, 0x21),
        ("bcdCCID", 2, BCD_CCID),
        ("bMaxSlotIndex", 1, MAX_SLOT_INDEX),
        ("bVoltageSupport", 1, VOLTAGE_SUPPORT),
        ("dwProtocols", 4, PROTOCOLS),
        ("dwDefaultClock", 4, DEFAULT_CLOCK_KHZ),
        ("dwMaximumClock", 4, MAXIMUM_CLOCK_KHZ),
        ("bNumClockSupported", 1, 0),
        ("dwDataRate", 4, DATA_RATE_BPS),
        ("dwMaxDataRate", 4, MAX_DATA_RATE_BPS),
        ("bNumDataRatesSupported", 1, 0),
        ("dwMaxIFSD", 4, MAX_IFSD),
        ("dwSynchProtocols", 4, SYNCH_PROTOCOLS),
        ("dwMechanical", 4, MECHANICAL),
        ("dwFeatures", 4, FEATURES),
        ("dwMaxCCIDMessageLength", 4, MAX_MESSAGE_LENGTH),
        ("bClassGetResponse", 1, CLASS_GET_RESPONSE),
        ("bClassEnvelope", 1, CLASS_ENVELOPE),
        ("wLcdLayout", 2, LCD_LAYOUT),
        ("bPINSupport", 1, PIN_SUPPORT),
        ("bMaxCCIDBusySlots", 1, MAX_BUSY_SLOTS),
    ]


def class_descriptor_bytes() -> bytes:
    """The 54-byte CCID class descriptor as sent on the wire."""
    out = b""
    for _name, size, value in class_descriptor():
        out += bytes((value >> (8 * i)) & 0xFF for i in range(size))
    return out


def notify_slot_change(present: bool = True, changed: bool = True) -> bytes:
    """``RDR_to_PC_NotifySlotChange`` (§6.3.1) for slot 0 (interrupt IN).

    Bit 0: current state (1 = ICC present), bit 1: state changed since the
    last message. The kernel sends ``50 03`` after SET_CONFIGURATION.
    """
    return bytes((RDR_TO_PC_NOTIFY_SLOT_CHANGE, (0x01 if present else 0) | (0x02 if changed else 0)))


def build_message(
    msg_type: int, slot: int, seq: int, status: int, error: int, specific: int, data=b""
) -> bytes:
    """Encode a ``RDR_to_PC`` message (10-byte header + abData)."""
    data = bytes(data)
    return (
        bytes((msg_type,))
        + _le32(len(data))
        + bytes((slot & 0xFF, seq & 0xFF, status & 0xFF, error & 0xFF, specific & 0xFF))
        + data
    )


def build_command(
    msg_type: int, seq: int, data=b"", b7: int = 0, b8: int = 0, b9: int = 0, slot: int = 0
) -> bytes:
    """Encode a ``PC_to_RDR`` message (tests and host tools)."""
    data = bytes(data)
    return bytes((msg_type,)) + _le32(len(data)) + bytes((slot, seq, b7, b8, b9)) + data


def packetize(message, size: int = PACKET_SIZE) -> list:
    """Split a message into bulk-IN packets.

    A final ``b""`` element requests a zero-length packet: it is present iff
    ``len(message)`` is a non-zero multiple of ``size``.
    """
    message = bytes(message)
    out = [message[i : i + size] for i in range(0, len(message), size)]
    if message and len(message) % size == 0:
        out.append(b"")
    return out


# response message type for each command (§6.1, Table 6.1-1)
_RESPONSE_TYPE = {
    PC_TO_RDR_ICC_POWER_ON: RDR_TO_PC_DATA_BLOCK,
    PC_TO_RDR_XFR_BLOCK: RDR_TO_PC_DATA_BLOCK,
    PC_TO_RDR_SECURE: RDR_TO_PC_DATA_BLOCK,
    PC_TO_RDR_GET_PARAMETERS: RDR_TO_PC_PARAMETERS,
    PC_TO_RDR_RESET_PARAMETERS: RDR_TO_PC_PARAMETERS,
    PC_TO_RDR_SET_PARAMETERS: RDR_TO_PC_PARAMETERS,
    PC_TO_RDR_ESCAPE: RDR_TO_PC_ESCAPE,
    PC_TO_RDR_SET_DATA_RATE_AND_CLOCK: RDR_TO_PC_DATA_RATE_AND_CLOCK,
}


def response_type(msg_type: int) -> int:
    """``RDR_to_PC`` type answering ``msg_type`` (SlotStatus by default)."""
    return _RESPONSE_TYPE.get(msg_type, RDR_TO_PC_SLOT_STATUS)


class Message:
    """A complete ``PC_to_RDR`` message."""

    def __init__(self, header, data=b"") -> None:
        self.msg_type = header[0]
        self.length = _rd32(header, 1)
        self.slot = header[5]
        self.seq = header[6]
        self.b7 = header[7]
        self.b8 = header[8]
        self.b9 = header[9]
        self.data = bytes(data)

    @property
    def level(self) -> int:
        """``wLevelParameter`` of an XfrBlock (bytes 8–9, little-endian)."""
        return self.b8 | (self.b9 << 8)

    def __repr__(self) -> str:
        return f"Message(type={self.msg_type:02x} seq={self.seq} len={self.length})"


class FramingError:
    """A transfer that could not be assembled; must be answered with ``error``."""

    def __init__(self, header, error: int) -> None:
        self.msg_type = header[0]
        self.slot = header[5]
        self.seq = header[6]
        self.error = error


class Assembler:
    """Reassemble ``PC_to_RDR`` messages from bulk-OUT packets.

    A transfer ends with a packet shorter than ``packet_size`` *or* once
    ``10 + dwLength`` bytes were received (hosts do not send an OUT ZLP).
    Packets longer than ``packet_size`` are accepted as several packets'
    worth of data (the emulator may deliver whole messages in one datagram).

    :meth:`feed` returns ``None``, a :class:`Message` or a
    :class:`FramingError`.
    """

    def __init__(self, max_data: int = MAX_DATA_LENGTH, packet_size: int = PACKET_SIZE) -> None:
        self.max_data = max_data
        self.packet_size = packet_size
        self._buf = bytearray()
        self._header = None
        self._expected = 0
        self._discard = False

    def reset(self) -> None:
        self._buf = bytearray()
        self._header = None
        self._expected = 0
        self._discard = False

    @property
    def idle(self) -> bool:
        return self._header is None and not self._discard

    def feed(self, packet):
        packet = bytes(packet)
        short = len(packet) < self.packet_size
        if self._discard:
            # swallow the rest of a rejected transfer
            if short:
                self._discard = False
            return None
        if self._header is None:
            if not packet:
                return None  # stray ZLP between transfers
            if len(packet) < HEADER_LEN:
                # cannot even answer (bSeq unknown); drop the transfer
                return None
            header = packet[:HEADER_LEN]
            length = _rd32(header, 1)
            if length > self.max_data:
                if not short:
                    self._discard = True
                return FramingError(header, ERR_OFFSET_DW_LENGTH)
            self._header = header
            self._expected = length
            self._buf = bytearray(packet[HEADER_LEN:])
        else:
            self._buf.extend(packet)
        have = len(self._buf)
        header = self._header
        if have == self._expected:
            data = bytes(self._buf)
            self.reset()
            return Message(header, data)
        if have > self._expected:
            self.reset()
            if not short:
                self._discard = True
            return FramingError(header, ERR_OFFSET_DW_LENGTH)
        if short:
            # transfer ended before dwLength bytes arrived
            self.reset()
            return FramingError(header, ERR_OFFSET_DW_LENGTH)
        return None


class Pending:
    """An APDU handed to the dispatcher, awaiting its response."""

    def __init__(self, seq: int, apdu: bytes) -> None:
        self.seq = seq
        self.apdu = apdu
        self.aborted = False


class CcidSlot:
    """CCID state machine for slot 0.

    ``feed(packet)`` returns a list of complete ``RDR_to_PC`` messages to send
    now. When an APDU is ready, :attr:`pending` is set; the owner processes
    it and calls :meth:`complete` with the response APDU. While pending,
    :meth:`time_extension` yields the time-extension message.

    ``on_reset(powered)`` (optional) is called on power-on (``True``, cold or
    warm reset) and power-off (``False``) so that the owner resets the
    applets.
    """

    def __init__(self, on_reset=None, max_data: int = MAX_DATA_LENGTH) -> None:
        self.on_reset = on_reset
        self.max_data = max_data
        self.assembler = Assembler(max_data)
        self.powered = False
        self.parameters = bytearray(DEFAULT_T1_PARAMETERS)
        self.pending = None
        self._cmd_chain = None  # bytearray while an XfrBlock chain is open
        self._rsp_chain = None  # remaining response bytes for 0x10 requests
        self._control_abort = None  # (slot, seq) from the ABORT control request

    # -- status helpers -----------------------------------------------------
    def icc_status(self) -> int:
        return ICC_ACTIVE if self.powered else ICC_INACTIVE

    def _reply(self, msg, status: int, error: int = 0, specific: int = 0, data=b"", icc=None) -> bytes:
        if icc is None:
            icc = self.icc_status()
        return build_message(
            response_type(msg.msg_type), msg.slot, msg.seq, status | icc, error, specific, data
        )

    def _fail(self, msg, error: int, icc=None) -> bytes:
        return self._reply(msg, CMD_FAILED, error, icc=icc)

    # -- public API ----------------------------------------------------------
    def feed(self, packet) -> list:
        """Feed one bulk-OUT packet; return the messages to send."""
        item = self.assembler.feed(packet)
        if item is None:
            return []
        if isinstance(item, FramingError):
            if self.pending is not None:
                return [self._reply(item, CMD_FAILED, ERR_CMD_SLOT_BUSY)]
            icc = ICC_ABSENT if item.slot != 0 else None
            return [self._reply(item, CMD_FAILED, item.error, icc=icc)]
        return self.handle(item)

    def handle(self, msg: Message) -> list:
        """Process a complete message (also used by whole-message transports)."""
        if msg.slot > MAX_SLOT_INDEX:
            return [self._fail(msg, ERR_OFFSET_SLOT, icc=ICC_ABSENT)]
        if msg.msg_type == PC_TO_RDR_ABORT:
            return self._abort(msg)
        if self.pending is not None:
            return [self._fail(msg, ERR_CMD_SLOT_BUSY)]
        t = msg.msg_type
        if t == PC_TO_RDR_XFR_BLOCK:
            return self._xfr_block(msg)
        if t == PC_TO_RDR_ICC_POWER_ON:
            return self._power_on(msg)
        if t == PC_TO_RDR_ICC_POWER_OFF:
            return self._power_off(msg)
        if t == PC_TO_RDR_GET_SLOT_STATUS:
            return [self._reply(msg, CMD_OK)]
        if t == PC_TO_RDR_GET_PARAMETERS:
            return [self._parameters(msg)]
        if t == PC_TO_RDR_RESET_PARAMETERS:
            self.parameters = bytearray(DEFAULT_T1_PARAMETERS)
            return [self._parameters(msg)]
        if t == PC_TO_RDR_SET_PARAMETERS:
            return [self._set_parameters(msg)]
        if t == PC_TO_RDR_SET_DATA_RATE_AND_CLOCK:
            if len(msg.data) != 8:
                return [self._fail(msg, ERR_OFFSET_DW_LENGTH)]
            # fixed virtual clock/rate: report the values actually in use
            return [self._reply(msg, CMD_OK, data=_le32(DEFAULT_CLOCK_KHZ) + _le32(DATA_RATE_BPS))]
        # Escape, IccClock, T0APDU, Secure, Mechanical and unknown types
        return [self._fail(msg, ERR_CMD_NOT_SUPPORTED)]

    def complete(self, response) -> list:
        """Deliver the response APDU of :attr:`pending`; return the messages."""
        p = self.pending
        self.pending = None
        if p is None or p.aborted:
            return []
        response = bytes(response)
        if len(response) > MAX_RESPONSE_LENGTH:
            return [
                build_message(RDR_TO_PC_DATA_BLOCK, 0, p.seq, CMD_FAILED | self.icc_status(), ERR_HW_ERROR, 0)
            ]
        if len(response) <= self.max_data:
            return [build_message(RDR_TO_PC_DATA_BLOCK, 0, p.seq, self.icc_status(), 0, 0x00, response)]
        # §6.2.1 bChainParameter 0x01: begins, continues in the next block
        self._rsp_chain = response[self.max_data :]
        return [
            build_message(
                RDR_TO_PC_DATA_BLOCK, 0, p.seq, self.icc_status(), 0, 0x01, response[: self.max_data]
            )
        ]

    def time_extension(self) -> list:
        """Time-extension message for the pending APDU (empty if none)."""
        p = self.pending
        if p is None or p.aborted:
            return []
        status = CMD_TIME_EXTENSION | self.icc_status()
        return [build_message(RDR_TO_PC_DATA_BLOCK, 0, p.seq, status, WTX_MULTIPLIER, 0)]

    def control_abort(self, slot: int, seq: int) -> None:
        """Record the class-specific ABORT control request (§5.3.1)."""
        self._control_abort = (slot, seq)

    def power_cycle(self, powered: bool = False) -> None:
        """External reset (USB reset / reconfiguration / device lock)."""
        self.assembler.reset()
        self._cmd_chain = None
        self._rsp_chain = None
        if self.pending is not None:
            self.pending.aborted = True
            self.pending = None
        self.powered = powered
        self.parameters = bytearray(DEFAULT_T1_PARAMETERS)
        if self.on_reset is not None:
            self.on_reset(powered)

    # -- commands ------------------------------------------------------------
    def _abort(self, msg) -> list:
        out = []
        p = self.pending
        if p is not None:
            p.aborted = True
            self.pending = None
            out.append(
                build_message(
                    RDR_TO_PC_DATA_BLOCK, 0, p.seq, CMD_FAILED | self.icc_status(), ERR_CMD_ABORTED, 0
                )
            )
        self._cmd_chain = None
        self._rsp_chain = None
        self._control_abort = None
        out.append(self._reply(msg, CMD_OK))
        return out

    def _power_on(self, msg) -> list:
        if msg.b7 > 3:  # bPowerSelect: 0 auto, 1 = 5 V, 2 = 3 V, 3 = 1.8 V
            return [self._fail(msg, ERR_OFFSET_BYTE7)]
        if msg.data:
            return [self._fail(msg, ERR_OFFSET_DW_LENGTH)]
        self._cmd_chain = None
        self._rsp_chain = None
        self.parameters = bytearray(DEFAULT_T1_PARAMETERS)
        self.powered = True
        if self.on_reset is not None:
            self.on_reset(True)
        return [self._reply(msg, CMD_OK, data=atr())]

    def _power_off(self, msg) -> list:
        self._cmd_chain = None
        self._rsp_chain = None
        was = self.powered
        self.powered = False
        if was and self.on_reset is not None:
            self.on_reset(False)
        return [self._reply(msg, CMD_OK, specific=0x00)]  # bClockStatus: running

    def _parameters(self, msg) -> bytes:
        return self._reply(msg, CMD_OK, specific=0x01, data=self.parameters)  # bProtocolNum = T=1

    def _set_parameters(self, msg) -> bytes:
        if msg.b7 != 0x01:
            return self._reply(msg, CMD_FAILED, ERR_OFFSET_BYTE7, specific=0x01, data=self.parameters)
        d = msg.data
        if len(d) != 7:
            return self._reply(msg, CMD_FAILED, ERR_OFFSET_DW_LENGTH, specific=0x01, data=self.parameters)
        # offsets of abProtocolDataStructure bytes start at 10
        bad = -1
        if d[1] & 0xFE != 0x10:  # bmTCCKST1: LRC/CRC, direct convention
            bad = 1
        elif d[3] >> 4 > 9:  # BWI 0..9
            bad = 3
        elif d[4] != 0x00:  # bClockStop: not supported
            bad = 4
        elif not 1 <= d[5] <= 0xFE:  # bIFSC
            bad = 5
        elif d[6] != 0x00:  # bNadValue
            bad = 6
        if bad >= 0:
            return self._reply(msg, CMD_FAILED, HEADER_LEN + bad, specific=0x01, data=self.parameters)
        self.parameters = bytearray(d)
        return self._parameters(msg)

    def _xfr_block(self, msg) -> list:
        if not self.powered:
            return [self._fail(msg, ERR_ICC_MUTE)]
        level = msg.level
        data = msg.data
        if level == 0x0010:
            # continuation of a chained response requested (§6.1.4)
            if data or self._rsp_chain is None:
                self._rsp_chain = None
                return [self._fail(msg, ERR_OFFSET_LEVEL)]
            rest = self._rsp_chain
            chunk = rest[: self.max_data]
            rest = rest[self.max_data :]
            self._rsp_chain = rest if rest else None
            chain = 0x03 if rest else 0x02
            return [self._reply(msg, CMD_OK, specific=chain, data=chunk)]
        # any new command data drops a half-read chained response
        self._rsp_chain = None
        if level == 0x0000:
            if self._cmd_chain is not None:
                self._cmd_chain = None
                return [self._fail(msg, ERR_OFFSET_LEVEL)]
            if len(data) > MAX_APDU_LENGTH:
                return [self._fail(msg, ERR_OFFSET_DW_LENGTH)]
            self.pending = Pending(msg.seq, data)
            return []
        if level == 0x0001:  # begins, continues in the next block
            self._cmd_chain = bytearray(data)
            return [self._reply(msg, CMD_OK, specific=0x10)]
        if level in (0x0002, 0x0003):
            if self._cmd_chain is None:
                return [self._fail(msg, ERR_OFFSET_LEVEL)]
            if len(self._cmd_chain) + len(data) > MAX_APDU_LENGTH:
                self._cmd_chain = None
                return [self._fail(msg, ERR_OFFSET_DW_LENGTH)]
            self._cmd_chain.extend(data)
            if level == 0x0003:
                return [self._reply(msg, CMD_OK, specific=0x10)]
            apdu_bytes = bytes(self._cmd_chain)
            self._cmd_chain = None
            self.pending = Pending(msg.seq, apdu_bytes)
            return []
        self._cmd_chain = None
        return [self._fail(msg, ERR_OFFSET_LEVEL)]


def parse_message(raw) -> Message:
    """Parse one whole ``PC_to_RDR`` message (raises ``InvalidInput``)."""
    from ...core.errors import InvalidInput

    raw = bytes(raw)
    if len(raw) < HEADER_LEN:
        raise InvalidInput("CCID header too short")
    if _rd32(raw, 1) != len(raw) - HEADER_LEN:
        raise InvalidInput("CCID dwLength mismatch")
    return Message(raw[:HEADER_LEN], raw[HEADER_LEN:])
