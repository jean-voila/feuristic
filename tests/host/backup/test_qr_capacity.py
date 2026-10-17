# SPDX-License-Identifier: GPL-3.0-only
"""Every generated frame must fit the display profile (spec §8.1, §8.2, R13):
dense ≤ QR version 9, large modules ≤ version 3, both at ECC level M in
alphanumeric mode. Verified with an independent QR encoder (segno)."""

import random

import pytest
import segno

from feuristic.apps.backup import frames

BID = b"\xff" * 8  # worst case for Base45 length is irrelevant, but keep it extreme


def _qr(text):
    return segno.make(text, error="m", boost_error=False, micro=False)


@pytest.mark.parametrize(("profile", "max_version"), [("dense", 9), ("large", 3)])
def test_every_frame_fits(profile, max_version):
    rng = random.Random(42)
    sizes = list(range(1, 400)) + [rng.randrange(400, 20000) for _ in range(15)]
    if profile == "dense":
        sizes.append(65536)
    seen_versions = set()
    for n in sizes:
        env = rng.randbytes(n)
        texts = frames.split(env, BID, profile)
        max_chars = frames.PROFILES[profile][1]
        assert all(len(t) <= max_chars for t in texts)
        # chunks are balanced: the first and last frames cover both text lengths
        for text in {texts[0], texts[-1]}:
            qr = _qr(text)
            assert qr.mode == "alphanumeric", text
            assert qr.error == "M"
            assert qr.version <= max_version, (n, len(text), qr.version)
            seen_versions.add(qr.version)
    assert max(seen_versions) == max_version  # the capacity is actually used


@pytest.mark.parametrize(("profile", "max_version"), [("dense", 9), ("large", 3)])
def test_worst_case_frame_and_one_more_char(profile, max_version):
    cap = frames.chunk_capacity(profile)
    text = frames.encode_frame(b"\xff" * 8, 999, 999, b"\xff" * cap)
    assert len(text) == frames.PROFILES[profile][1]
    assert _qr(text).version == max_version
    # the profile is tight: one more character needs a bigger symbol
    assert _qr(text + "0").version == max_version + 1


def test_module_sizes_fit_display():
    """Side length (modules) of the largest symbol vs the 64-pixel height."""
    height = 64
    assert height >= 17 + 4 * 9  # dense: 53 modules, 1 px per module
    assert height >= (17 + 4 * 3) * 2  # large: 29 modules, 2 px per module
