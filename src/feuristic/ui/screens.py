# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
"""Device screens built on the upstream Rust layouts (layout_caesar).

Firmware-only module. Navigation rules (spec §9):

* left = previous, right = next, both buttons = validate;
* a long press on the left button (>= 1 s) = back/cancel;
* destructive confirmations use hold-to-confirm so that an ambiguous button
  combination can never silently validate an erase.

Every function is ``async`` and returns plain Python values; ``None`` means
"back / cancelled / timed out".
"""

import trezorui_api
import utime
from micropython import const
from trezor import io, loop, ui, workflow

from ..core.i18n import t

LONG_PRESS_MS = const(1000)
QR_TIMEOUT_MS = const(60_000)
QR_MAX_BYTES = const(180)  # QR version 9, ECC M, byte mode (upstream renderer limit)
# The upstream renderer (core/embed/rust/src/ui/component/qr_code.rs) encodes up
# to version 9 at ECC M and picks the alphanumeric mode by itself when every
# character is in the QR alphanumeric set: 262 characters then fit (this is
# the "dense" backup frame profile). A longer text makes the Rust code panic
# at render time, so callers must stay within these limits.
QR_MAX_ALNUM = const(262)
_QR_ALNUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"


class NavLayout(ui.Layout):
    """Layout adding "long press on the left button = back" (spec §9)."""

    def __init__(self, layout) -> None:
        super().__init__(layout)
        self._left_task = None
        self._right_down = False

    def _cancel_long_press(self) -> None:
        if self._left_task is not None:
            loop.close(self._left_task)
            self.tasks.discard(self._left_task)
            self._left_task = None

    def _arm_long_press(self) -> None:
        self._cancel_long_press()

        async def fire() -> None:
            await loop.sleep(LONG_PRESS_MS)
            self._left_task = None
            try:
                self._emit_message(trezorui_api.CANCELLED)
            except ui.Shutdown:
                pass

        self._left_task = fire()
        self._start_task(self._left_task)

    def _event(self, event_call, *args):
        # Button events reach the layout here both from the hardware task and
        # from the debuglink, so long-press detection lives at this level.
        if (
            len(args) == 2
            and isinstance(args[0], int)
            and isinstance(args[1], int)
            and args[0] in (io.BUTTON_PRESSED, io.BUTTON_RELEASED)
            and args[1] in (io.BUTTON_LEFT, io.BUTTON_RIGHT)
        ):
            ev_type, ev_btn = args
            if ev_btn == io.BUTTON_RIGHT:
                self._right_down = ev_type == io.BUTTON_PRESSED
                # both buttons together = validate, never "back"
                self._cancel_long_press()
            elif ev_type == io.BUTTON_PRESSED and not self._right_down:
                self._arm_long_press()
            else:
                self._cancel_long_press()
        return super()._event(event_call, *args)

    def stop(self, _close_all: bool = True) -> None:
        self._cancel_long_press()
        super().stop(_close_all)


_TIMEOUT = object()


async def _timeout(ms: int):
    await loop.sleep(ms)
    return _TIMEOUT


async def run(layout_ctx, timeout_ms: int = 0, close_others: bool = True, cls=None):
    """Run a layout to completion and return its raw result.

    With ``timeout_ms`` the layout is closed and ``None`` returned on expiry.
    ``cls`` overrides the Python layout wrapper (default :class:`NavLayout`).
    """
    if close_others:
        workflow.close_others()
    with layout_ctx as obj:
        layout = (cls or NavLayout)(obj)
        if timeout_ms:
            result = await loop.race(layout.get_result(), _timeout(timeout_ms))
            if result is _TIMEOUT:
                layout.stop()
                return None
            return result
        return await layout.get_result()


# --- menus -------------------------------------------------------------------

_PAGE = const(31)  # the Rust carousel holds up to 32 items (1 reserved for "More...")


async def menu(
    title: str,
    items: list,
    current: int = 0,
    back: bool = True,
    timeout_ms: int = 0,
    close_others: bool = True,
):
    """Carousel menu. Returns the selected index or ``None`` for back.

    Lists longer than the Rust limit are paginated with a "More..." entry.
    A "Back" entry is appended when ``back`` is True (long press also works).
    """
    offset = 0
    while True:
        page = items[offset : offset + _PAGE]
        labels = list(page)
        has_more = offset + _PAGE < len(items)
        if has_more:
            labels.append(t("ui.more"))
        if back:
            labels.append(t("ui.back"))
        cur = current - offset if 0 <= current - offset < len(page) else 0
        res = await run(
            trezorui_api.select_menu(items=labels, current=cur, title=title), timeout_ms, close_others
        )
        if res is None or res is trezorui_api.CANCELLED:
            return None
        if not isinstance(res, int):
            return None
        if res < len(page):
            return offset + res
        if has_more and res == len(page):
            offset += _PAGE
            if offset >= len(items):
                offset = 0
            continue
        return None  # "Back"


# --- confirmations -----------------------------------------------------------


async def confirm(
    title: str,
    text: str = "",
    verb: str | None = None,
    hold: bool = False,
    timeout_ms: int = 0,
    close_others: bool = True,
) -> bool:
    res = await run(
        trezorui_api.confirm_action(
            title=title,
            action=text or None,
            description=None,
            verb=verb or t("ui.confirm"),
            verb_cancel="",
            hold=hold,
        ),
        timeout_ms,
        close_others,
    )
    return res is trezorui_api.CONFIRMED


async def confirm_fields(
    title: str,
    fields,
    hold: bool = False,
    timeout_ms: int = 0,
    verb: str | None = None,
    close_others: bool = True,
) -> bool:
    """Confirm a list of ``(label, value, monospace)`` properties."""
    items = [(label, value, mono) for (label, value, mono) in fields]
    res = await run(
        trezorui_api.confirm_properties(title=title, items=items, hold=hold, verb=verb or t("ui.confirm")),
        timeout_ms,
        close_others,
    )
    return res is trezorui_api.CONFIRMED


async def show_info(title: str, text: str = "", timeout_ms: int = 0, close_others: bool = True) -> None:
    """Information screen. With ``timeout_ms`` it disappears by itself;
    otherwise it waits for the (both-buttons) OK button."""
    if timeout_ms:
        await run(trezorui_api.show_info(title=title, description=text, time_ms=timeout_ms), 0, close_others)
    else:
        # Caesar's warning layout ignores its title and is a single page.
        # The normal confirmation layout preserves the title and paginates.
        await confirm(title, text, verb=t("ui.ok"), close_others=close_others)


async def show_warning(
    title: str, text: str = "", button: str | None = None, close_others: bool = False
) -> None:
    await run(
        trezorui_api.show_warning(
            title=title, button=button or t("ui.ok"), description=text, allow_cancel=False
        ),
        close_others=close_others,
    )


async def show_error(text: str, close_others: bool = False) -> None:
    await show_warning(t("ui.error"), text, close_others=close_others)


def show_busy(text: str) -> None:
    """Draw a static screen without waiting for input (long computations)."""
    with trezorui_api.show_simple(text=text) as obj:
        layout = ui.Layout(obj)
        layout.start()
        layout.stop()


# --- input -------------------------------------------------------------------


async def show_lockscreen() -> None:
    """Visible locked greeting; releasing either button opens the PIN prompt."""

    # The wrapper is needed only while locked. Release its class and instances
    # on return rather than adding a permanent class to the small NORMAL heap.
    class WakeLayout(ui.Layout):
        def _event(self, event_call, *args):
            if (
                len(args) == 2
                and args[0] == io.BUTTON_RELEASED
                and args[1] in (io.BUTTON_LEFT, io.BUTTON_RIGHT)
            ):
                self._emit_message(trezorui_api.CONFIRMED)
                return None
            return super()._event(event_call, *args)

    await run(trezorui_api.show_simple(text="FEURISTIC\n\n" + t("lock.press_any")), cls=WakeLayout)


async def request_pin(
    prompt: str, attempts: str = "", wrong: bool = False, last: bool = False, close_others: bool = False
):
    res = await run(
        trezorui_api.request_pin(
            prompt=prompt, attempts=attempts, allow_cancel=True, wrong_pin=wrong, last_attempt=last
        ),
        close_others=close_others,
    )
    if isinstance(res, str):
        return res
    return None


async def request_text(prompt: str, max_len: int, close_others: bool = False):
    """Character entry (printable ASCII carousel). Returns str or None."""
    res = await run(
        trezorui_api.request_passphrase(prompt=prompt, prompt_empty=prompt, max_len=max_len),
        close_others=close_others,
    )
    if isinstance(res, str):
        return res
    return None


async def request_number(title: str, count: int, min_count: int, max_count: int):
    res = await run(
        trezorui_api.request_number(title=title, count=count, min_count=min_count, max_count=max_count)
    )
    if isinstance(res, tuple) and res[0] is trezorui_api.CONFIRMED:
        return res[1]
    return None


# --- QR display --------------------------------------------------------------


def qr_fits(data: str) -> bool:
    """True if the upstream renderer can draw ``data`` (version <= 9, ECC M)."""
    raw = data.encode()
    if len(raw) == len(data):
        alnum = True
        for c in data:
            if c not in _QR_ALNUM:
                alnum = False
                break
        if alnum:
            return len(data) <= QR_MAX_ALNUM
    return len(raw) <= QR_MAX_BYTES


QR_PREV = "prev"  # left button
QR_NEXT = "next"  # right button
QR_BOTH = "both"  # both buttons
QR_BACK = "back"  # long press on the left button


class _QrLayout(NavLayout):
    """QR screen whose buttons are handled in Python.

    The Rust ``AddressDetails`` component of layout_caesar draws the QR code
    full screen (no title) with a left and a right arrow; its right arrow
    would open an empty "details" page. Button events are therefore not
    forwarded to Rust: a short left press returns :data:`QR_PREV`, a right
    press :data:`QR_NEXT`, both buttons :data:`QR_BOTH` and a long left
    press :data:`QR_BACK` (results are emitted on release, like the Rust
    buttons)."""

    def __init__(self, layout) -> None:
        super().__init__(layout)
        self._down = 0
        self._seen = 0

    def _arm_long_press(self) -> None:
        self._cancel_long_press()

        async def fire() -> None:
            await loop.sleep(LONG_PRESS_MS)
            self._left_task = None
            self._seen = 0
            try:
                self._emit_message(QR_BACK)
            except ui.Shutdown:
                pass

        self._left_task = fire()
        self._start_task(self._left_task)

    def _event(self, event_call, *args):
        if (
            len(args) == 2
            and isinstance(args[0], int)
            and isinstance(args[1], int)
            and args[0] in (io.BUTTON_PRESSED, io.BUTTON_RELEASED)
            and args[1] in (io.BUTTON_LEFT, io.BUTTON_RIGHT)
        ):
            ev_type, ev_btn = args
            bit = 1 if ev_btn == io.BUTTON_LEFT else 2
            if ev_type == io.BUTTON_PRESSED:
                self._down |= bit
                self._seen |= bit
                if self._down == 1:
                    self._arm_long_press()
                else:
                    self._cancel_long_press()
                return None
            self._down &= ~bit
            if bit == 1:
                self._cancel_long_press()
            if self._down == 0 and self._seen:
                seen = self._seen
                self._seen = 0
                if seen == 3:
                    self._emit_message(QR_BOTH)
                elif seen == 1:
                    self._emit_message(QR_PREV)
                else:
                    self._emit_message(QR_NEXT)
            return None
        return ui.Layout._event(self, event_call, *args)


def _qr_layout(title: str, data: str):
    if not qr_fits(data):
        raise ValueError("QR payload too large")
    return trezorui_api.show_address_details(
        qr_title=title,
        address=data,
        case_sensitive=True,
        details_title=title,
        account=None,
        path=None,
        xpubs=[],
    )


async def show_qr_page(title: str, data: str, timeout_ms: int = QR_TIMEOUT_MS, close_others: bool = False):
    """Show one QR code full screen. Returns :data:`QR_PREV`, :data:`QR_NEXT`,
    :data:`QR_BOTH`, :data:`QR_BACK`, or ``None`` when it was hidden after
    ``timeout_ms`` (spec §8.1: 60 s). ``title`` is drawn only by layouts that
    have room for it (layout_caesar shows the QR code alone)."""
    res = await run(_qr_layout(title, data), timeout_ms, close_others, _QrLayout)
    if res in (QR_PREV, QR_NEXT, QR_BOTH, QR_BACK):
        return res
    return None


async def show_qr(title: str, data: str, timeout_ms: int = QR_TIMEOUT_MS) -> None:
    """Show ``data`` as a QR code; closes on any button or after ``timeout_ms``
    (spec §8.1: secret QR codes are hidden automatically after 60 s)."""
    await run(_qr_layout(title, data), timeout_ms, True, _QrLayout)


class _InlineProgressLayout(ui.ProgressLayout):
    def start(self) -> None:
        # Import and USB interactions can run inside loop.race children of the
        # default workflow. Closing other workflows here closes that parent,
        # including its storage session, while this child still uses it.
        if ui.CURRENT_LAYOUT is not self and ui.CURRENT_LAYOUT is not None:
            ui.CURRENT_LAYOUT.stop()
        assert ui.CURRENT_LAYOUT is None
        ui.set_current_layout(self)
        self.repaint()


class Progress:
    """Progress bar for long operations (PBKDF2, RSA key generation...)."""

    def __init__(self, text: str) -> None:
        self.layout = _InlineProgressLayout(trezorui_api.show_progress(description=text))
        self._last = -1

    def report(self, fraction: float) -> None:
        value = int(max(0.0, min(1.0, fraction)) * 1000)
        if value != self._last:
            self._last = value
            self.layout.report(value)

    def stop(self) -> None:
        self.layout.stop()


def ticks_ms() -> int:
    return utime.ticks_ms()
