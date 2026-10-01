"""Sealing and opening of protected records (proposal section 4.3(d)).

Request:  session ID || seq || 96-bit nonce || timestamp || AES-256-GCM(ciphertext || 128-bit tag)
The header fields are passed to GCM as associated data, so they are
integrity-protected without being encrypted. Changing any byte of the header,
ciphertext or tag makes the tag check fail.

Each direction has its own key (c2g / g2c) and every record uses a fresh
random 96-bit nonce. Sessions are bounded in lifetime and request count, which
keeps the random-nonce collision probability negligible.
"""

from __future__ import annotations

import json
from typing import Any

from flowstate.core import crypto
from flowstate.core.messages import ProtectedRequest, ProtectedResponse
from flowstate.core.reasons import ReasonCode, SecurityError


def encode_payload(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def decode_payload(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(data.decode())
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SecurityError(ReasonCode.MALFORMED_FRAME, "payload is not JSON") from exc
    if not isinstance(value, dict):
        raise SecurityError(ReasonCode.MALFORMED_FRAME, "payload must be an object")
    return value


# ---------------------------------------------------------------- requests (client -> gateway)


def seal_request(
    key: crypto.AeadKey,
    session_id: bytes,
    seq: int,
    timestamp: int,
    operation: str,
    params: dict[str, Any] | None = None,
) -> ProtectedRequest:
    nonce = crypto.random_bytes(crypto.GCM_NONCE_LEN)
    header = ProtectedRequest(session_id, seq, nonce, timestamp, b"")
    plaintext = encode_payload({"op": operation, "params": params or {}})
    return ProtectedRequest(
        session_id, seq, nonce, timestamp, key.seal(nonce, plaintext, header.aad())
    )


def open_request(key: crypto.AeadKey, frame: ProtectedRequest) -> bytes:
    try:
        return key.open(frame.nonce, frame.ciphertext, frame.aad())
    except crypto.AuthenticationFailed as exc:
        raise SecurityError(ReasonCode.MODIFIED_MESSAGE, "GCM tag verification failed") from exc


# ---------------------------------------------------------------- responses (gateway -> client)


def seal_response(
    key: crypto.AeadKey, session_id: bytes, seq: int, payload: dict[str, Any]
) -> ProtectedResponse:
    nonce = crypto.random_bytes(crypto.GCM_NONCE_LEN)
    header = ProtectedResponse(session_id, seq, nonce, b"")
    return ProtectedResponse(
        session_id, seq, nonce, key.seal(nonce, encode_payload(payload), header.aad())
    )


def open_response(
    key: crypto.AeadKey, frame: ProtectedResponse, *, session_id: bytes, seq: int
) -> dict[str, Any]:
    """Verify and decrypt a response, checking it answers the request we sent."""
    if frame.session_id != session_id or frame.seq != seq:
        raise SecurityError(ReasonCode.MODIFIED_MESSAGE, "response does not match request")
    try:
        plaintext = key.open(frame.nonce, frame.ciphertext, frame.aad())
    except crypto.AuthenticationFailed as exc:
        raise SecurityError(ReasonCode.MODIFIED_MESSAGE, "response tag verification failed") from exc
    return decode_payload(plaintext)
