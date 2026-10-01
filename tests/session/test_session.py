import threading

import pytest

from flowstate.core import crypto
from flowstate.core.messages import ProtectedRequest
from flowstate.core.pipeline import RequestContext
from flowstate.core.reasons import ReasonCode, SecurityError
from flowstate.handshake.keyschedule import SessionKeys
from flowstate.handshake.protocol import EstablishedSession
from flowstate.identity.registry import ClientRecord
from flowstate.session import SessionManager, SessionStage


def established(clock, ttl=1000, sid=None):
    client = ClientRecord("alice", crypto.SigningKey.generate().public_key(), "customer")
    return EstablishedSession(
        client, sid or crypto.random_bytes(16),
        SessionKeys(crypto.random_bytes(32), crypto.random_bytes(32)), clock.now_ms() + ttl,
    )


def ctx(session_id, now):
    return RequestContext(ProtectedRequest(session_id, 1, b"\x00" * 12, now, b"\x00" * 16), now_ms=now)


def test_create_and_lookup(clock):
    mgr = SessionManager(clock)
    s = mgr.create(established(clock))
    assert mgr.lookup(s.session_id) is s
    assert s.client_id == "alice" and s.role == "customer" and s.last_seq == 0


def test_expired_session_removed_and_keys_destroyed(clock):
    mgr = SessionManager(clock)
    s = mgr.create(established(clock, ttl=1000))
    clock.advance(1000)
    with pytest.raises(SecurityError) as exc:
        mgr.lookup(s.session_id)
    assert exc.value.reason is ReasonCode.EXPIRED_SESSION
    assert len(mgr) == 0 and s.c2g is None and s.g2c is None


def test_unknown_session_same_code(clock):
    with pytest.raises(SecurityError) as exc:
        SessionManager(clock).lookup(b"\x00" * 16)
    assert exc.value.reason is ReasonCode.EXPIRED_SESSION


def test_collision_and_capacity(clock):
    mgr = SessionManager(clock, max_sessions=2)
    est = established(clock)
    mgr.create(est)
    with pytest.raises(SecurityError):
        mgr.create(est)
    mgr.create(established(clock, ttl=10))
    clock.advance(20)  # second session expires; cleanup makes room
    mgr.create(established(clock))
    with pytest.raises(SecurityError):
        mgr.create(established(clock))


def test_cleanup_and_terminate(clock):
    mgr = SessionManager(clock)
    a = mgr.create(established(clock, ttl=10))
    b = mgr.create(established(clock, ttl=10_000))
    clock.advance(100)
    assert mgr.cleanup_expired() == 1
    assert mgr.terminate(b.session_id) and not mgr.terminate(b.session_id)
    assert mgr.get(a.session_id) is None


def test_concurrent_creation(clock):
    mgr = SessionManager(clock)
    threads = [threading.Thread(target=lambda: [mgr.create(established(clock)) for _ in range(50)])
               for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(mgr) == 400


def test_stage_attaches_session_and_counts_only_on_commit(clock):
    mgr = SessionManager(clock)
    s = mgr.create(established(clock))
    c = ctx(s.session_id, clock.now_ms())
    SessionStage(mgr).check(c)
    assert c.session is s and s.request_count == 0
    for commit in c._commits:
        commit()
    assert s.request_count == 1


def test_stage_enforces_request_limit(clock):
    mgr = SessionManager(clock)
    s = mgr.create(established(clock))
    s.request_count = 3
    with pytest.raises(SecurityError) as exc:
        SessionStage(mgr, max_requests=3).check(ctx(s.session_id, clock.now_ms()))
    assert exc.value.reason is ReasonCode.EXPIRED_SESSION
    assert mgr.get(s.session_id) is None
