"""Mutually authenticated key exchange (proposal sections 4.3(a) and 4.3(b)).

  Client  -> Gateway : ClientHello(client_id, eph_C, nonce_C, ts)       signed by client
  Gateway -> Client  : ServerHello(session_id, eph_G, nonce_G, expiry)  signed by gateway,
                       signature also covers SHA-256(ClientHello)

Both sides compute X25519(eph, peer_eph) independently and derive the
direction keys with HKDF. The shared secret is never transmitted.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from dataclasses import dataclass

from flowstate.core import crypto
from flowstate.core.clock import Clock, SystemClock
from flowstate.core.messages import HELLO_NONCE_LEN, SESSION_ID_LEN, ClientHello, ServerHello
from flowstate.core.reasons import ReasonCode, SecurityError
from flowstate.handshake.keyschedule import SessionKeys, derive_session_keys
from flowstate.identity.auth import authenticate_client_hello, sign_client_hello
from flowstate.identity.registry import ClientRecord, ClientRegistry


def transcript_hash(hello: ClientHello) -> bytes:
    return crypto.sha256(hello.encode())


@dataclass(frozen=True)
class HandshakeResult:
    session_id: bytes
    keys: SessionKeys
    expires_at: int


@dataclass(frozen=True)
class EstablishedSession:
    client: ClientRecord
    session_id: bytes
    keys: SessionKeys
    expires_at: int


# ---------------------------------------------------------------- client side


class ClientHandshake:
    def __init__(
        self,
        client_id: str,
        signing_key: crypto.SigningKey,
        gateway_pin: crypto.VerifyKey,
        clock: Clock | None = None,
    ) -> None:
        self.client_id = client_id
        self.signing_key = signing_key
        self.gateway_pin = gateway_pin
        self.clock = clock or SystemClock()
        self._eph: crypto.EphemeralKeyPair | None = None
        self._hello: ClientHello | None = None

    def start(self) -> ClientHello:
        self._eph = crypto.EphemeralKeyPair()
        unsigned = ClientHello(
            client_id=self.client_id,
            eph_pub=self._eph.public_bytes(),
            nonce=crypto.random_bytes(HELLO_NONCE_LEN),
            timestamp=self.clock.now_ms(),
        )
        self._hello = sign_client_hello(unsigned, self.signing_key)
        return self._hello

    def finish(self, reply: ServerHello) -> HandshakeResult:
        if self._hello is None or self._eph is None:
            raise RuntimeError("start() must be called before finish()")
        payload = reply.signed_payload(transcript_hash(self._hello))
        if not self.gateway_pin.verify(reply.signature, payload):
            # Wrong key, substituted ephemeral key, or reply to another hello.
            raise SecurityError(ReasonCode.INVALID_SIGNATURE, "gateway signature did not verify")
        if reply.expires_at <= self.clock.now_ms():
            raise SecurityError(ReasonCode.EXPIRED_SESSION, "gateway offered an expired session")
        try:
            shared = self._eph.exchange(reply.eph_pub)
        except crypto.CryptoError as exc:
            raise SecurityError(ReasonCode.MALFORMED_FRAME, "invalid gateway ephemeral key") from exc
        keys = derive_session_keys(shared, self._hello.nonce, reply.nonce, reply.session_id)
        self._eph = None
        return HandshakeResult(reply.session_id, keys, reply.expires_at)


# ---------------------------------------------------------------- gateway side


class HelloReplayCache:
    """Remembers HELLO nonces seen inside the freshness window.

    Entries older than the window can be dropped safely, because a HELLO that
    old is rejected as STALE_REQUEST before the cache is consulted. If the
    cache is full of in-window entries, new handshakes fail closed.
    """

    def __init__(self, window_ms: int, max_entries: int = 100_000) -> None:
        self.window_ms = window_ms
        self.max_entries = max_entries
        self._seen: OrderedDict[tuple[str, bytes], int] = OrderedDict()
        self._lock = threading.Lock()

    def _evict(self, now_ms: int) -> None:
        while self._seen:
            key, seen_at = next(iter(self._seen.items()))
            if now_ms - seen_at <= 2 * self.window_ms:
                break
            del self._seen[key]

    def contains(self, client_id: str, nonce: bytes, now_ms: int) -> bool:
        with self._lock:
            self._evict(now_ms)
            return (client_id, nonce) in self._seen

    def add(self, client_id: str, nonce: bytes, now_ms: int) -> None:
        with self._lock:
            self._evict(now_ms)
            if len(self._seen) >= self.max_entries:
                raise SecurityError(ReasonCode.INTERNAL_ERROR, "handshake replay cache full")
            self._seen[(client_id, nonce)] = now_ms

    def __len__(self) -> int:
        return len(self._seen)


class GatewayHandshake:
    def __init__(
        self,
        signing_key: crypto.SigningKey,
        registry: ClientRegistry,
        *,
        session_ttl_ms: int,
        max_skew_ms: int,
        clock: Clock | None = None,
    ) -> None:
        self.signing_key = signing_key
        self.registry = registry
        self.session_ttl_ms = session_ttl_ms
        self.max_skew_ms = max_skew_ms
        self.clock = clock or SystemClock()
        self.replay_cache = HelloReplayCache(max_skew_ms)

    def respond(self, hello: ClientHello) -> tuple[ServerHello, EstablishedSession]:
        now = self.clock.now_ms()
        # 1. Signature first, so unauthenticated traffic cannot fill the cache.
        client = authenticate_client_hello(hello, self.registry)
        # 2. Freshness and uniqueness of the HELLO itself.
        if abs(now - hello.timestamp) > self.max_skew_ms:
            raise SecurityError(ReasonCode.STALE_REQUEST, "client hello outside freshness window")
        if self.replay_cache.contains(hello.client_id, hello.nonce, now):
            raise SecurityError(ReasonCode.DUPLICATE_NONCE, "client hello nonce already used")

        eph = crypto.EphemeralKeyPair()
        try:
            shared = eph.exchange(hello.eph_pub)
        except crypto.CryptoError as exc:
            raise SecurityError(ReasonCode.MALFORMED_FRAME, "invalid client ephemeral key") from exc

        session_id = crypto.random_bytes(SESSION_ID_LEN)
        server_nonce = crypto.random_bytes(HELLO_NONCE_LEN)
        expires_at = now + self.session_ttl_ms
        unsigned = ServerHello(session_id, eph.public_bytes(), server_nonce, expires_at)
        signature = self.signing_key.sign(unsigned.signed_payload(transcript_hash(hello)))
        reply = ServerHello(session_id, eph.public_bytes(), server_nonce, expires_at, signature)

        keys = derive_session_keys(shared, hello.nonce, server_nonce, session_id)
        self.replay_cache.add(hello.client_id, hello.nonce, now)
        return reply, EstablishedSession(client, session_id, keys, expires_at)
