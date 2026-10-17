# SPDX-License-Identifier: GPL-3.0-only
import random

from hypothesis import given, settings
from hypothesis import strategies as st

from feuristic.apps.backup import frames
from feuristic.apps.importer import session as sess
from feuristic.core import base45, i18n

OTP = b"otpauth://totp/ACME:alice?secret=JBSWY3DPEHPK3PXP"
OTP2 = b"otpauth://totp/ACME:bob?secret=JBSWY3DPEHPK3PXP"
BID1 = b"\x11" * 8
BID2 = b"\x22" * 8


def _texts(n=500, bid=BID1, seed=1, profile="dense"):
    env = random.Random(seed).randbytes(n)
    return env, [t.encode() for t in frames.split(env, bid, profile)]


def test_otp_flow():
    s = sess.ImportSession()
    assert not s.is_ready() and s.action() is None
    ev = s.add_payload(OTP)
    assert ev.status == sess.OTP_READY and ev.accepted
    assert ev.key == "importer.status.otp_ready"
    assert s.is_ready() and s.has_otp() and not s.has_backup()
    act = s.action()
    assert act.kind == sess.ACTION_OTP and bytes(act.otp_uri) == OTP
    assert s.add_payload(OTP).status == sess.DUPLICATE
    assert s.add_payload(OTP2).status == sess.REJECTED_OTP_PENDING
    uri = act.otp_uri
    s.finish()
    assert uri == bytearray(len(OTP))  # secret wiped
    assert s.finished and not s.is_ready() and s.action() is None
    assert s.add_payload(OTP).status == sess.REJECTED_FINISHED
    assert s.files_seen == 4 and s.files_rejected == 2


def test_backup_single_sequence_any_order_with_duplicates():
    env, texts = _texts(1000)
    s = sess.ImportSession()
    order = list(range(len(texts)))
    random.Random(3).shuffle(order)
    statuses = []
    for i in order[:-1]:
        ev = s.add_payload(texts[i])
        statuses.append(ev.status)
        assert ev.backup_id == BID1 and ev.total == len(texts)
        assert not s.is_ready()  # missing frame blocks
        assert s.action() is None
    assert set(statuses) == {sess.FRAME_ADDED}
    assert s.add_payload(texts[order[0]]).status == sess.DUPLICATE
    (p,) = s.progress()
    assert p.missing == [order[-1] + 1] and p.received == len(texts) - 1 and not p.complete
    ev = s.add_payload(texts[order[-1]])
    assert ev.status == sess.BACKUP_COMPLETE and ev.missing == [] and ev.received == len(texts)
    assert s.is_ready()
    act = s.action()
    assert act.kind == sess.ACTION_RESTORE and act.envelopes == [env]
    assert s.action().envelopes == [env]  # non-destructive
    assert s.counts() == (1, 0)


def test_frame_event_progress_fields():
    _, texts = _texts(1000)  # 7 frames
    s = sess.ImportSession()
    ev = s.add_payload(texts[2])
    assert (ev.index, ev.total, ev.received) == (3, 7, 1)
    assert ev.missing == [1, 2, 4, 5, 6, 7]
    assert "Frame" not in repr(ev)


def test_missing_report_limited():
    _, texts = _texts(5000, profile="large")
    s = sess.ImportSession()
    ev = s.add_payload(texts[0])
    assert len(ev.missing) == sess.MISSING_REPORT_LIMIT
    assert ev.missing[0] == 2


def test_multiple_sequences_full_export():
    env1, t1 = _texts(400, BID1, 1)
    env2, t2 = _texts(300, BID2, 2)
    s = sess.ImportSession()
    stream = t1 + t2
    random.Random(9).shuffle(stream)
    for t in stream[:-1]:
        s.add_payload(t)
    assert not s.is_ready()
    assert s.counts() in ((1, 1),)
    s.add_payload(stream[-1])
    assert s.is_ready()
    envs = s.action().envelopes
    assert sorted(envs) == sorted([env1, env2])
    assert [p.backup_id for p in s.progress()] in ([BID1, BID2], [BID2, BID1])


def test_incomplete_sequence_blocks_until_discarded():
    env1, t1 = _texts(400, BID1, 1)
    _, t2 = _texts(400, BID2, 2)
    s = sess.ImportSession()
    for t in t1:
        s.add_payload(t)
    s.add_payload(t2[0])
    assert s.counts() == (1, 1) and not s.is_ready()
    assert s.discard(BID2) is True
    assert s.discard(BID2) is False
    assert s.is_ready() and s.action().envelopes == [env1]


def test_mixing_rules():
    _, texts = _texts(400)
    s = sess.ImportSession()
    s.add_payload(texts[0])
    ev = s.add_payload(OTP)
    assert ev.status == sess.REJECTED_MIXED and not ev.accepted
    assert not s.has_otp() and s.progress()[0].received == 1  # state untouched
    s2 = sess.ImportSession()
    s2.add_payload(OTP)
    assert s2.add_payload(texts[0]).status == sess.REJECTED_MIXED
    assert not s2.has_backup() and bytes(s2.action().otp_uri) == OTP


def test_frame_errors_are_reported_not_raised():
    _, texts = _texts(400)
    s = sess.ImportSession()
    s.add_payload(texts[0])
    # bad CRC
    binary = bytearray(base45.decode(texts[1][4:]))
    binary[13] ^= 1
    assert s.add_payload(b"FB1:" + base45.encode(bytes(binary)).encode()).status == sess.REJECTED_CHECKSUM
    # invalid Base45 group
    assert s.add_payload(b"FB1:GGW").status == sess.REJECTED_FRAME_INVALID
    # conflicting duplicate
    f = frames.parse_frame(texts[0])
    conflict = frames.encode_frame(BID1, 1, f.total, b"X" + f.chunk[1:]).encode()
    ev = s.add_payload(conflict)
    assert ev.status == sess.REJECTED_CONFLICT and ev.index == 1
    # different total, same id
    ev = s.add_payload(frames.encode_frame(BID1, 2, f.total + 1, b"abc").encode())
    assert ev.status == sess.REJECTED_TOTAL_MISMATCH
    assert s.progress()[0].received == 1
    # unsupported content / versions / too large
    assert s.add_payload(b"hello").status == sess.REJECTED_UNSUPPORTED
    assert s.add_payload(b"hello").key == "importer.err.unsupported"
    assert s.add_payload(b"FB2:00").status == sess.REJECTED_BACKUP_VERSION
    assert s.add_payload(b"x" * 4000).status == sess.REJECTED_TOO_LARGE
    assert s.add_payload(b"").key == "importer.err.empty"
    assert s.add_payload(b"FB1:abc").status == sess.REJECTED_UNSUPPORTED


def test_limits_backups_and_bytes():
    s = sess.ImportSession(max_backups=2)
    for i in range(2):
        s.add_payload(frames.encode_frame(bytes([i]) * 8, 1, 2, b"a").encode())
    ev = s.add_payload(frames.encode_frame(b"\x09" * 8, 1, 2, b"a").encode())
    assert ev.status == sess.REJECTED_LIMIT and len(s.progress()) == 2

    s = sess.ImportSession(max_bytes=10)
    assert s.add_payload(frames.encode_frame(BID1, 1, 3, b"123456").encode()).accepted
    assert s.add_payload(frames.encode_frame(BID2, 1, 2, b"12345").encode()).status == sess.REJECTED_LIMIT
    assert len(s.progress()) == 1  # the rejected new sequence was not kept
    assert s.add_payload(frames.encode_frame(BID1, 2, 3, b"12345").encode()).status == sess.REJECTED_LIMIT
    assert s.add_payload(frames.encode_frame(BID1, 2, 3, b"1234").encode()).status == sess.FRAME_ADDED
    assert s.add_payload(frames.encode_frame(BID1, 1, 3, b"123456").encode()).status == sess.DUPLICATE
    assert s.bytes_used() == 10


def test_abort_purges():
    _, texts = _texts(400)
    s = sess.ImportSession()
    s.add_payload(texts[0])
    s.abort()
    assert s.progress() == [] and s.finished and not s.is_ready()
    s2 = sess.ImportSession()
    s2.add_payload(OTP)
    uri = s2.action().otp_uri
    s2.abort()
    assert uri == bytearray(len(OTP)) and not s2.has_otp()


def test_status_keys_translated():
    sess._strings.register()
    for key in sess._STATUS_KEYS.values():
        assert key in set(i18n.keys()), key


@settings(max_examples=200)
@given(st.lists(st.binary(max_size=300), max_size=8))
def test_fuzz_never_raises(payloads):
    s = sess.ImportSession()
    for p in payloads:
        ev = s.add_payload(p)
        assert ev.key
    s.progress()
    s.action()
