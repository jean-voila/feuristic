# SPDX-License-Identifier: GPL-3.0-only
"""Exercise the actual Rust Caesar button controller with raw physical events.

No debuglink shortcut or Python confirmation substitute participates. Timers
use the emulator's monotonic clock, including holds broken by one release.
"""

import trezorui_api as api
import utime
from trezor import io
from upytest import run, test


class Buttons:
    def __init__(self, layout):
        self.layout = layout
        self.timers = {}
        self.done = False
        self.layout.attach_timer_fn(self.timer_set, api.AttachType.INITIAL)

    def timer_set(self, token, delay):
        self.timers[token] = utime.ticks_add(utime.ticks_ms(), delay)

    def event(self, pressed, button):
        result = self.layout.button_event(io.BUTTON_PRESSED if pressed else io.BUTTON_RELEASED, button)
        if result is api.LayoutState.DONE:
            self.done = True
        return result

    def press_both(self):
        self.event(True, io.BUTTON_LEFT)
        self.event(True, io.BUTTON_RIGHT)

    def release_both(self):
        self.event(False, io.BUTTON_LEFT)
        self.event(False, io.BUTTON_RIGHT)

    def tap(self, button):
        self.event(True, button)
        self.event(False, button)

    def pump(self, duration):
        end = utime.ticks_add(utime.ticks_ms(), duration)
        while utime.ticks_diff(end, utime.ticks_ms()) > 0 and not self.done:
            now = utime.ticks_ms()
            for token in list(self.timers):
                if utime.ticks_diff(now, self.timers[token]) >= 0:
                    del self.timers[token]
                    if self.layout.timer(token) is api.LayoutState.DONE:
                        self.done = True
                        return
            utime.sleep_ms(1)

    def trace(self):
        parts = []
        self.layout.trace(lambda *args: parts.extend(args))
        return "".join(parts)


def action(text="", hold=False):
    return api.confirm_action(
        title="Identity",
        action=text or None,
        description=None,
        verb="Confirm",
        verb_cancel="",
        hold=hold,
    )


@test
def action_only_both_buttons_confirm():
    with action() as layout:
        buttons = Buttons(layout)
        buttons.tap(io.BUTTON_RIGHT)
        assert not buttons.done
        buttons.press_both()
        buttons.release_both()
        assert buttons.done and layout.return_value() is api.CONFIRMED


@test
def properties_only_both_buttons_confirm():
    with api.confirm_properties(title="Identity", items=[], verb="Confirm", hold=False) as layout:
        buttons = Buttons(layout)
        buttons.tap(io.BUTTON_RIGHT)
        assert not buttons.done
        buttons.press_both()
        buttons.release_both()
        assert buttons.done and layout.return_value() is api.CONFIRMED


@test
def both_buttons_on_intermediate_page_neither_confirm_nor_navigate():
    with action("Review this identity and its protection before continuing. " * 5) as layout:
        buttons = Buttons(layout)
        assert layout.page_count() > 1
        initial = buttons.trace()
        buttons.press_both()
        buttons.release_both()
        assert not buttons.done and buttons.trace() == initial
        buttons.tap(io.BUTTON_RIGHT)
        assert buttons.trace() != initial  # right means next page
        buttons.tap(io.BUTTON_LEFT)
        assert buttons.trace() == initial  # left means previous page
        for _ in range(layout.page_count() - 1):
            buttons.tap(io.BUTTON_RIGHT)
        assert not buttons.done
        buttons.tap(io.BUTTON_RIGHT)
        assert not buttons.done  # last-page right must never confirm
        buttons.press_both()
        buttons.release_both()
        assert buttons.done


@test
def destructive_confirmation_requires_continuous_simultaneous_hold():
    with action(hold=True) as layout:
        buttons = Buttons(layout)
        buttons.event(True, io.BUTTON_RIGHT)
        buttons.pump(1150)
        assert not buttons.done  # holding one side is insufficient
        buttons.event(False, io.BUTTON_RIGHT)
        buttons.press_both()
        buttons.release_both()
        assert not buttons.done  # simultaneous short press is insufficient
        buttons.press_both()
        buttons.pump(650)
        buttons.event(False, io.BUTTON_RIGHT)
        buttons.pump(50)
        assert not buttons.done  # one button released: hold is cancelled
        buttons.event(True, io.BUTTON_RIGHT)
        buttons.pump(650)
        assert not buttons.done  # two interrupted holds cannot accumulate
        buttons.event(False, io.BUTTON_LEFT)
        buttons.event(False, io.BUTTON_RIGHT)
        buttons.press_both()
        buttons.pump(1150)
        assert buttons.done and layout.return_value() is api.CONFIRMED


@test
def single_left_never_confirms_and_native_cancel_is_on_release():
    # The firmware wrapper adds the duration threshold. Native first-page
    # cancellation is also checked so navigation never becomes an approval.
    with action(hold=True) as layout:
        buttons = Buttons(layout)
        buttons.event(True, io.BUTTON_LEFT)
        buttons.pump(1150)
        assert not buttons.done
        buttons.event(False, io.BUTTON_LEFT)
        assert buttons.done and layout.return_value() is api.CANCELLED


run()
