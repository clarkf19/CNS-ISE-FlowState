from types import SimpleNamespace

import pytest

from flowstate.core.messages import ProtectedRequest
from flowstate.core.pipeline import Pipeline, RequestContext
from flowstate.core.reasons import ReasonCode, SecurityError
from flowstate.replay import FreshnessStage, NonceCache, ReplayStage

WINDOW = 30_000


def session():
    return SimpleNamespace(last_seq=0, extensions={})


def frame(seq, nonce, ts):
    return ProtectedRequest(b"\x00" * 16, seq, nonce, ts, b"\x00" * 16)


class AttachSession:
    name = "attach"

    def __init__(self, s):
        self.s = s

    def check(self, ctx):
        ctx.session = self.s


class Fail:
    name = "later"

    def check(self, ctx):
        raise SecurityError(ReasonCode.UNAUTHORIZED_OPERATION)


def run(s, f, now, *extra):
    stages = [AttachSession(s), ReplayStage(window_ms=WINDOW), FreshnessStage(max_skew_ms=WINDOW), *extra]
    return Pipeline(stages).run(RequestContext(f, now_ms=now)).reason


def nonce(i):
    return i.to_bytes(12, "big")


def test_accepts_increasing_sequence():
    s = session()
    for i in range(1, 6):
        assert run(s, frame(i, nonce(i), 1000), 1000) is ReasonCode.ACCEPTED
    assert s.last_seq == 5


def test_exact_replay_is_duplicate_nonce():
    s = session()
    f = frame(1, nonce(1), 1000)
    assert run(s, f, 1000) is ReasonCode.ACCEPTED
    assert run(s, f, 1001) is ReasonCode.DUPLICATE_NONCE


def test_old_sequence_with_new_nonce_is_stale():
    s = session()
    run(s, frame(5, nonce(5), 1000), 1000)
    assert run(s, frame(5, nonce(99), 1000), 1000) is ReasonCode.STALE_REQUEST
    assert run(s, frame(3, nonce(98), 1000), 1000) is ReasonCode.STALE_REQUEST


@pytest.mark.parametrize(
    "ts_offset, expected",
    [(0, "ACCEPTED"), (-WINDOW, "ACCEPTED"), (WINDOW, "ACCEPTED"),
     (-WINDOW - 1, "STALE_REQUEST"), (WINDOW + 1, "STALE_REQUEST")],
)
def test_freshness_window_edges(ts_offset, expected):
    now = 1_000_000
    assert run(session(), frame(1, nonce(1), now + ts_offset), now).value == expected


def test_rejected_request_changes_no_replay_state():
    s = session()
    assert run(s, frame(1, nonce(1), 1000), 1000, Fail()) is ReasonCode.UNAUTHORIZED_OPERATION
    assert s.last_seq == 0
    assert len(s.extensions[ReplayStage.EXTENSION_KEY]) == 0
    # The same (legitimate) request is still accepted afterwards.
    assert run(s, frame(1, nonce(1), 1000), 1000) is ReasonCode.ACCEPTED


def test_stale_request_does_not_consume_nonce():
    s = session()
    assert run(s, frame(1, nonce(1), 0), 100_000) is ReasonCode.STALE_REQUEST
    assert s.last_seq == 0


def test_nonce_cache_is_bounded():
    cache = NonceCache(window_ms=WINDOW, max_entries=100)
    for i in range(1000):
        cache.add(nonce(i), 1000, 1000)
    assert len(cache) == 100
    assert cache.contains(nonce(999)) and not cache.contains(nonce(0))


def test_nonce_cache_time_eviction():
    cache = NonceCache(window_ms=1000)
    cache.add(nonce(1), 0, 0)
    cache.add(nonce(2), 5000, 5000)
    assert not cache.contains(nonce(1)) and cache.contains(nonce(2))


def test_evicted_nonce_replay_still_caught_by_sequence():
    s = session()
    stage_cache_size = 2
    stages = lambda: [AttachSession(s), ReplayStage(window_ms=WINDOW, max_entries=stage_cache_size),
                      FreshnessStage(max_skew_ms=WINDOW)]
    first = frame(1, nonce(1), 1000)
    for f in (first, frame(2, nonce(2), 1000), frame(3, nonce(3), 1000)):
        assert Pipeline(stages()).run(RequestContext(f, now_ms=1000)).accepted
    assert Pipeline(stages()).run(RequestContext(first, now_ms=1000)).reason is ReasonCode.STALE_REQUEST
