# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""The virtual card reader as seen by the firmware glue: CCID + dispatcher.

Glue contract (``fw_ccid.py``, firmware only; see docs/protocols/ccid.md §6)::

    card = Card([openpgp_applet, piv_applet, aes_applet], fallback=aes_applet)

    # reader task: bulk-OUT packets from SYSHANDLE_USB_CCID
    for pkt in incoming_packets:
        for p in card.receive(pkt):        # immediate answers (status, errors, busy)
            write_bulk_in(p)               # b"" means "send a ZLP"
        if card.pending is not None and no worker is running:
            spawn worker()

    async def worker():
        job = card.process_pending()       # coroutine
        # while the job runs, every WTX_INTERVAL_MS:
        #     for p in card.time_extension(): write_bulk_in(p)
        for p in await job:
            write_bulk_in(p)

``receive`` may be called while a job runs (the reader answers new commands
with ``CMD_SLOT_BUSY`` and honours ``Abort``). Whole-message transports (the
emulator's UDP datagrams carrying complete CCID messages) use
:meth:`handle_message`.
"""

from . import ccid as _ccid
from .dispatcher import Dispatcher


class Card:
    def __init__(self, applets, fallback=None) -> None:
        self.dispatcher = Dispatcher(applets, fallback)
        self.ccid = _ccid.CcidSlot(on_reset=self._on_reset)

    # -- reset ------------------------------------------------------------------
    def _on_reset(self, powered: bool) -> None:
        self.dispatcher.reset()

    def usb_reset(self) -> None:
        """USB bus reset / re-enumeration / device lock: power the card off."""
        self.ccid.power_cycle(False)

    # -- packet API --------------------------------------------------------------
    @property
    def pending(self):
        """The :class:`~feuristic.apps.card.ccid.Pending` APDU, or None."""
        return self.ccid.pending

    def receive(self, packet) -> list:
        """Feed a bulk-OUT packet; return bulk-IN packets to send now."""
        out = []
        for msg in self.ccid.feed(packet):
            out.extend(_ccid.packetize(msg))
        return out

    async def process_pending(self) -> list:
        """Run the pending APDU through the dispatcher; return bulk-IN packets.

        Returns ``[]`` when nothing is pending or the APDU was aborted
        meanwhile (the abort answer was already produced by :meth:`receive`).
        """
        p = self.ccid.pending
        if p is None:
            return []
        rsp = await self.dispatcher.transmit(p.apdu)
        if p.aborted or self.ccid.pending is not p:
            return []
        out = []
        for msg in self.ccid.complete(rsp):
            out.extend(_ccid.packetize(msg))
        return out

    def time_extension(self) -> list:
        """Bulk-IN packets of a time-extension message (``[]`` if idle)."""
        out = []
        for msg in self.ccid.time_extension():
            out.extend(_ccid.packetize(msg))
        return out

    def control_abort(self, slot: int, seq: int) -> None:
        """Class-specific ABORT control request forwarded by the kernel."""
        self.ccid.control_abort(slot, seq)

    @staticmethod
    def notify_slot_change(present: bool = True, changed: bool = True) -> bytes:
        return _ccid.notify_slot_change(present, changed)

    # -- whole-message API ------------------------------------------------------
    async def handle_message(self, raw) -> list:
        """Process one complete ``PC_to_RDR`` message.

        Returns the list of complete ``RDR_to_PC`` messages produced (usually
        one; two for an Abort cancelling a pending APDU; none when the input
        is malformed beyond answering). Not packetised.
        """
        from ...core.errors import InvalidInput

        try:
            msg = _ccid.parse_message(raw)
        except InvalidInput:
            raw = bytes(raw)
            if len(raw) < _ccid.HEADER_LEN:
                return []
            err = _ccid.FramingError(raw[: _ccid.HEADER_LEN], _ccid.ERR_OFFSET_DW_LENGTH)
            icc = _ccid.ICC_ABSENT if err.slot else None
            return [self.ccid._reply(err, _ccid.CMD_FAILED, err.error, icc=icc)]
        if len(msg.data) > self.ccid.max_data:
            return [self.ccid._fail(msg, _ccid.ERR_OFFSET_DW_LENGTH)]
        out = self.ccid.handle(msg)
        if self.ccid.pending is not None:
            p = self.ccid.pending
            rsp = await self.dispatcher.transmit(p.apdu)
            if not p.aborted and self.ccid.pending is p:
                out.extend(self.ccid.complete(rsp))
        return out

    async def transmit(self, apdu_bytes) -> bytes:
        """Send one APDU directly to the dispatcher (tests, tools)."""
        return await self.dispatcher.transmit(apdu_bytes)
