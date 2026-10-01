"""Gateway server.

Handshake frames go to the handshake module; protected requests go through
the validation pipeline, in the order defined by proposal section 4.3(e):

    1 session lookup + expiry   (SessionStage)        EXPIRED_SESSION
    2 AES-GCM decrypt + tag     (DecryptStage)        MODIFIED_MESSAGE
    3 nonce + sequence          (ReplayStage)         DUPLICATE_NONCE / STALE_REQUEST
    4 timestamp freshness       (FreshnessStage)      STALE_REQUEST
    5 role-based permission     (AuthorizationStage)  UNAUTHORIZED_OPERATION

Only a request that passes all five is forwarded. Every decision produces
exactly one SecurityEvent.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from dataclasses import dataclass, field

from flowstate.authz import AuthorizationStage, Policy
from flowstate.backend.server import BackendClient
from flowstate.core import crypto
from flowstate.core.clock import Clock, SystemClock
from flowstate.core.codec import read_frame, write_frame
from flowstate.core.events import EventSink, NullSink, SecurityEvent
from flowstate.core.messages import ClientHello, ErrorFrame, ProtectedRequest, decode_message
from flowstate.core.pipeline import Pipeline, RequestContext
from flowstate.core.reasons import ReasonCode, SecurityError
from flowstate.handshake.protocol import GatewayHandshake
from flowstate.identity.registry import ClientRegistry
from flowstate.record.layer import seal_response
from flowstate.record.stage import DecryptStage
from flowstate.replay import FreshnessStage, ReplayStage
from flowstate.session import SessionManager, SessionStage


@dataclass
class GatewaySettings:
    session_ttl_ms: int = 300_000
    max_skew_ms: int = 30_000
    nonce_cache_size: int = 4096
    max_requests_per_session: int = 1_000_000


@dataclass
class StageStats:
    total_ns: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    count: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    def add(self, timings: dict[str, int]) -> None:
        for name, ns in timings.items():
            self.total_ns[name] += ns
            self.count[name] += 1

    def mean_us(self) -> dict[str, float]:
        return {n: self.total_ns[n] / self.count[n] / 1000 for n in self.total_ns}


class Gateway:
    def __init__(
        self,
        *,
        signing_key: crypto.SigningKey,
        registry: ClientRegistry,
        policy: Policy,
        backend: BackendClient,
        sink: EventSink | None = None,
        clock: Clock | None = None,
        settings: GatewaySettings | None = None,
    ) -> None:
        self.clock = clock or SystemClock()
        self.settings = settings or GatewaySettings()
        self.sink = sink or NullSink()
        self.backend = backend
        self.handshake = GatewayHandshake(
            signing_key,
            registry,
            session_ttl_ms=self.settings.session_ttl_ms,
            max_skew_ms=self.settings.max_skew_ms,
            clock=self.clock,
        )
        self.sessions = SessionManager(self.clock)
        self.pipeline = Pipeline(
            [
                SessionStage(self.sessions, max_requests=self.settings.max_requests_per_session),
                DecryptStage(),
                ReplayStage(
                    window_ms=self.settings.max_skew_ms,
                    max_entries=self.settings.nonce_cache_size,
                ),
                FreshnessStage(max_skew_ms=self.settings.max_skew_ms),
                AuthorizationStage(policy),
            ]
        )
        self.stage_stats = StageStats()

    # ------------------------------------------------------------ decisions

    def _emit(self, phase: str, reason: ReasonCode, peer: str | None, **fields) -> None:
        self.sink.record(
            SecurityEvent(self.clock.now_ms(), phase, reason, peer=peer, **fields)
        )

    def _handle_hello(self, hello: ClientHello, peer: str | None) -> bytes:
        try:
            reply, established = self.handshake.respond(hello)
            session = self.sessions.create(established)
        except SecurityError as err:
            self._emit("handshake", err.reason, peer, client_id=hello.client_id, detail=err.detail)
            return ErrorFrame(err.reason.value, err.detail).encode()
        self._emit(
            "handshake", ReasonCode.ACCEPTED, peer,
            client_id=session.client_id, session_id=session.session_hex, detail="session established",
        )
        return reply.encode()

    async def _handle_request(self, frame: ProtectedRequest, peer: str | None) -> bytes:
        ctx = RequestContext(frame=frame, now_ms=self.clock.now_ms(), peer=peer)
        verdict = self.pipeline.run(ctx)
        self.stage_stats.add(verdict.timings_ns)
        session = ctx.session
        fields = {
            "client_id": session.client_id if session else None,
            "session_id": frame.session_id.hex(),
            "operation": ctx.operation,
        }
        if not verdict.accepted:
            self._emit(
                "request", verdict.reason, peer, detail=verdict.detail,
                stage=verdict.failed_stage, **fields,
            )
            return ErrorFrame(verdict.reason.value, verdict.detail).encode()

        result = await self.backend.call(session.client_id, session.role, ctx.operation, ctx.params)
        self._emit("request", ReasonCode.ACCEPTED, peer, detail="forwarded", **fields)
        if session.g2c is None:  # expired while the backend was working
            return ErrorFrame(ReasonCode.EXPIRED_SESSION.value, "session ended").encode()
        return seal_response(session.g2c, frame.session_id, frame.seq, result).encode()

    async def handle_message(self, raw: bytes, peer: str | None = None) -> bytes:
        try:
            msg = decode_message(raw)
        except SecurityError as err:
            self._emit("request", err.reason, peer, detail=err.detail)
            return ErrorFrame(err.reason.value, err.detail).encode()
        if isinstance(msg, ClientHello):
            return self._handle_hello(msg, peer)
        if isinstance(msg, ProtectedRequest):
            return await self._handle_request(msg, peer)
        self._emit("request", ReasonCode.MALFORMED_FRAME, peer, detail="unexpected message type")
        return ErrorFrame(ReasonCode.MALFORMED_FRAME.value, "unexpected message type").encode()

    # ------------------------------------------------------------ network

    async def _on_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        addr = writer.get_extra_info("peername")
        peer = f"{addr[0]}:{addr[1]}" if addr else None
        try:
            while True:
                try:
                    raw = await read_frame(reader)
                except SecurityError as err:  # broken framing: cannot resync, close
                    self._emit("request", err.reason, peer, detail=err.detail)
                    break
                if raw is None:
                    break
                await write_frame(writer, await self.handle_message(raw, peer))
        except ConnectionError:
            pass
        finally:
            writer.close()

    async def start(self, host: str, port: int) -> asyncio.Server:
        return await asyncio.start_server(self._on_connection, host, port)
