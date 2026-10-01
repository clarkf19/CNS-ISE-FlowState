"""SecureClient: the client side of the protocol (proposal section 4.2, client module).

Holds the client's long-term Ed25519 key and the pinned gateway key, runs the
handshake, encrypts each request with the client->gateway key and attaches
session ID, sequence number, nonce and timestamp, then verifies and decrypts
the response with the gateway->client key.
"""

from __future__ import annotations

import socket
from typing import Any

from flowstate.core import crypto
from flowstate.core.clock import Clock, SystemClock
from flowstate.core.codec import recv_frame, send_frame
from flowstate.core.messages import (
    ErrorFrame,
    ProtectedRequest,
    ProtectedResponse,
    ServerHello,
    decode_message,
)
from flowstate.core.reasons import ReasonCode, SecurityError
from flowstate.handshake.protocol import ClientHandshake, HandshakeResult
from flowstate.record.layer import open_response, seal_request


class GatewayRejected(Exception):
    """The gateway refused a handshake or request."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


class SecureClient:
    def __init__(
        self,
        address: tuple[str, int],
        client_id: str,
        signing_key: crypto.SigningKey,
        gateway_pin: crypto.VerifyKey,
        *,
        clock: Clock | None = None,
        timeout_s: float = 5.0,
    ) -> None:
        self.address = address
        self.client_id = client_id
        self.signing_key = signing_key
        self.gateway_pin = gateway_pin
        self.clock = clock or SystemClock()
        self.timeout_s = timeout_s
        self.sock: socket.socket | None = None
        self.session: HandshakeResult | None = None
        self._c2g: crypto.AeadKey | None = None
        self._g2c: crypto.AeadKey | None = None
        self.seq = 0
        self.last_hello = None  # most recent handshake messages, for inspection
        self.last_reply = None

    # ------------------------------------------------------------ connection

    def connect(self) -> "SecureClient":
        if self.sock is None:
            self.sock = socket.create_connection(self.address, timeout=self.timeout_s)
        return self

    def close(self) -> None:
        if self.sock is not None:
            self.sock.close()
            self.sock = None

    def __enter__(self) -> "SecureClient":
        return self.connect()

    def __exit__(self, *exc) -> None:
        self.close()

    def send_raw(self, payload: bytes) -> bytes:
        """Send one raw message and return the raw reply (used by tests and attacks)."""
        self.connect()
        send_frame(self.sock, payload)
        return recv_frame(self.sock)

    # ------------------------------------------------------------ protocol

    def handshake(self) -> HandshakeResult:
        hs = ClientHandshake(self.client_id, self.signing_key, self.gateway_pin, self.clock)
        self.last_hello = hs.start()
        reply = decode_message(self.send_raw(self.last_hello.encode()))
        self.last_reply = reply
        if isinstance(reply, ErrorFrame):
            raise GatewayRejected(reply.reason, reply.detail)
        if not isinstance(reply, ServerHello):
            raise GatewayRejected(ReasonCode.MALFORMED_FRAME.value, "expected ServerHello")
        try:
            result = hs.finish(reply)
        except SecurityError as err:
            raise GatewayRejected(err.reason.value, err.detail) from err
        self.session = result
        self._c2g = crypto.AeadKey(result.keys.c2g)
        self._g2c = crypto.AeadKey(result.keys.g2c)
        self.seq = 0
        return result

    def build_request(self, operation: str, params: dict[str, Any] | None = None) -> ProtectedRequest:
        if self.session is None or self._c2g is None:
            raise RuntimeError("handshake() first")
        self.seq += 1
        return seal_request(
            self._c2g, self.session.session_id, self.seq, self.clock.now_ms(), operation, params
        )

    def parse_reply(self, raw: bytes, request: ProtectedRequest) -> dict[str, Any]:
        reply = decode_message(raw)
        if isinstance(reply, ErrorFrame):
            raise GatewayRejected(reply.reason, reply.detail)
        if not isinstance(reply, ProtectedResponse):
            raise GatewayRejected(ReasonCode.MALFORMED_FRAME.value, "expected ProtectedResponse")
        try:
            return open_response(self._g2c, reply, session_id=request.session_id, seq=request.seq)
        except SecurityError as err:
            raise GatewayRejected(err.reason.value, err.detail) from err

    def send_request(self, request: ProtectedRequest) -> dict[str, Any]:
        return self.parse_reply(self.send_raw(request.encode()), request)

    def request(self, operation: str, **params: Any) -> dict[str, Any]:
        """Send an operation; returns the backend's response payload."""
        if self.session is None:
            self.handshake()
        return self.send_request(self.build_request(operation, params))
