from dataclasses import replace

import pytest

from flowstate.core import crypto
from flowstate.core.reasons import ReasonCode, SecurityError
from flowstate.handshake.keyschedule import derive_session_keys
from flowstate.handshake.protocol import ClientHandshake, GatewayHandshake, HelloReplayCache
from flowstate.identity.registry import ClientRegistry

TTL, SKEW = 300_000, 30_000


@pytest.fixture
def setup(clock):
    gw_key, alice_key = crypto.SigningKey.generate(), crypto.SigningKey.generate()
    reg = ClientRegistry()
    reg.register("alice", alice_key.public_key(), "customer")
    gateway = GatewayHandshake(gw_key, reg, session_ttl_ms=TTL, max_skew_ms=SKEW, clock=clock)

    def client(key=alice_key, pin=gw_key.public_key(), cid="alice"):
        return ClientHandshake(cid, key, pin, clock)

    return gateway, client


def reason(fn, *args):
    with pytest.raises(SecurityError) as exc:
        fn(*args)
    return exc.value.reason


def test_both_sides_derive_same_independent_keys(setup, clock):
    gateway, client = setup
    c = client()
    reply, established = gateway.respond(c.start())
    result = c.finish(reply)
    assert result.keys == established.keys
    assert result.keys.c2g != result.keys.g2c
    assert len(result.keys.c2g) == 32
    assert result.session_id == established.session_id
    assert established.client.role == "customer"
    assert result.expires_at == clock.now_ms() + TTL


def test_fresh_keys_every_session(setup):
    gateway, client = setup
    keys = set()
    for _ in range(5):
        c = client()
        reply, _ = gateway.respond(c.start())
        keys.add(c.finish(reply).keys.c2g)
    assert len(keys) == 5


def test_key_schedule_binds_nonces_and_session():
    base = derive_session_keys(b"s" * 32, b"a" * 16, b"b" * 16, b"i" * 16)
    assert base != derive_session_keys(b"s" * 32, b"a" * 16, b"c" * 16, b"i" * 16)
    assert base != derive_session_keys(b"s" * 32, b"a" * 16, b"b" * 16, b"j" * 16)
    assert "redacted" in repr(base)


def test_forward_secrecy_ephemeral_secrets_destroyed(setup):
    """After the handshake neither side retains an ephemeral private key, so the
    session keys cannot be re-derived later even with the long-term keys."""
    gateway, client = setup
    c = client()
    hello = c.start()
    eph = c._eph
    reply, _ = gateway.respond(hello)
    c.finish(reply)
    assert c._eph is None
    with pytest.raises(crypto.CryptoError):
        eph.exchange(reply.eph_pub)  # the object refuses to be used again


def test_forged_client_signature(setup):
    gateway, client = setup
    assert reason(gateway.respond, client(key=crypto.SigningKey.generate()).start()) is ReasonCode.INVALID_SIGNATURE


def test_substituted_client_ephemeral_key(setup):
    gateway, client = setup
    hello = client().start()
    tampered = replace(hello, eph_pub=crypto.EphemeralKeyPair().public_bytes())
    assert reason(gateway.respond, tampered) is ReasonCode.INVALID_SIGNATURE


@pytest.mark.parametrize("field", ["eph_pub", "session_id", "expires_at", "nonce"])
def test_tampered_server_hello_rejected_by_client(setup, field):
    gateway, client = setup
    c = client()
    reply, _ = gateway.respond(c.start())
    changes = {
        "eph_pub": crypto.EphemeralKeyPair().public_bytes(),
        "session_id": b"\xee" * 16,
        "expires_at": reply.expires_at + 10**9,
        "nonce": b"\xee" * 16,
    }
    assert reason(c.finish, replace(reply, **{field: changes[field]})) is ReasonCode.INVALID_SIGNATURE


def test_client_rejects_wrong_pinned_key(setup):
    gateway, client = setup
    c = client(pin=crypto.SigningKey.generate().public_key())
    reply, _ = gateway.respond(c.start())
    assert reason(c.finish, reply) is ReasonCode.INVALID_SIGNATURE


def test_reply_bound_to_its_own_hello(setup):
    """A ServerHello for one handshake cannot complete a different one (transcript binding)."""
    gateway, client = setup
    c1, c2 = client(), client()
    c2.start()
    reply_for_c1, _ = gateway.respond(c1.start())
    assert reason(c2.finish, reply_for_c1) is ReasonCode.INVALID_SIGNATURE


def test_replayed_hello(setup):
    gateway, client = setup
    hello = client().start()
    gateway.respond(hello)
    assert reason(gateway.respond, hello) is ReasonCode.DUPLICATE_NONCE


def test_stale_and_future_hello(setup, clock):
    gateway, client = setup
    hello = client().start()
    clock.advance(SKEW + 1)
    assert reason(gateway.respond, hello) is ReasonCode.STALE_REQUEST
    future = client().start()
    clock.advance(-2 * (SKEW + 1))
    assert reason(gateway.respond, future) is ReasonCode.STALE_REQUEST


def test_rejected_hello_does_not_consume_nonce(setup):
    gateway, client = setup
    forged = client(key=crypto.SigningKey.generate()).start()
    reason(gateway.respond, forged)
    assert len(gateway.replay_cache) == 0


def test_replay_cache_evicts_and_fails_closed():
    cache = HelloReplayCache(window_ms=1000, max_entries=2)
    cache.add("a", b"1", 0)
    cache.add("a", b"2", 0)
    with pytest.raises(SecurityError):
        cache.add("a", b"3", 10)
    assert not cache.contains("a", b"1", 5000)  # old entries evicted
    cache.add("a", b"3", 5000)
