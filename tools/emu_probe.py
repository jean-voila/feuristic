#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Tiny interactive probe for the feuristic emulator (development aid).

Usage: tools/emu_probe.py [actions...] where each action is one of
left, right, middle, hold_left, read, sleep:<ms>, pin:<digits>
"""

import sys
import time

from trezorlib import models
from trezorlib.debuglink import DebugLink
from trezorlib.transport.udp import UdpTransport


def main() -> None:
    dl = DebugLink(UdpTransport("127.0.0.1:21325"), auto_interact=False)
    dl.model = models.T3B1

    def show() -> None:
        lay = dl.read_layout()
        print("title:", lay.title(), "| text:", lay.text_content()[:160].replace("\n", " / "))

    for act in sys.argv[1:] or ["read"]:
        if act == "read":
            show()
        elif act == "left":
            dl.press_left()
        elif act == "right":
            dl.press_right()
        elif act == "middle":
            dl.press_middle()
        elif act.startswith("sleep:"):
            time.sleep(int(act[6:]) / 1000)
        else:
            raise SystemExit(f"unknown action {act}")
        if act != "read":
            time.sleep(0.4)
    dl.close()


if __name__ == "__main__":
    main()
