"""Protocol messages (see docs/protocol-spec.md).

Each message body is: type (1 byte) || version (1 byte) || encode_fields(...).
Field sizes are validated on decode, before any cryptography runs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import IntEnum
from typing import Union

from flowstate import PROTOCOL_VERSION
from flowstate.core import crypto
from flowstate.core.codec import decode_fields, encode_fields, from_u64, malformed, u64

SESSION_ID_LEN = 16
HELLO_NONCE_LEN = 16
CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")

# Domain-separation labels: a signature or tag made for one purpose can never
# be valid for another.
LABEL_CLIENT_HELLO = b"FLOWSTATE/1 client-hello"
LABEL_SERVER_HELLO = b"FLOWSTATE/1 server-hello"
LABEL_REQUEST = b"FLOWSTATE/1 request"
LABEL_RESPONSE = b"FLOWSTATE/1 response"


class MsgType(IntEnum):
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    REQUEST = 3
    RESPONSE = 4
    ERROR = 5


def _expect(name: str, value: bytes, length: int) -> bytes:
    if len(value) != length:
        raise malformed(f"{name} must be {length} bytes")
    return value


def _client_id(raw: bytes) -> str:
    try:
        value = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise malformed("client_id must be ASCII") from exc
    if not CLIENT_ID_RE.match(value):
        raise malformed("invalid client_id")
    return value


def _wrap(t: MsgType, *fields: bytes) -> bytes:
    return bytes([t, PROTOCOL_VERSION]) + encode_fields(*fields)


@dataclass(frozen=True)
class ClientHello:
    client_id: str
    eph_pub: bytes
    nonce: bytes
    timestamp: int
    signature: bytes = b""

    def signed_payload(self) -> bytes:
        return LABEL_CLIENT_HELLO + encode_fields(
            self.client_id.encode("ascii"), self.eph_pub, self.nonce, u64(self.timestamp)
        )

    def encode(self) -> bytes:
        return _wrap(
            MsgType.CLIENT_HELLO,
            self.client_id.encode("ascii"),
            self.eph_pub,
            self.nonce,
            u64(self.timestamp),
            self.signature,
        )

    @classmethod
    def from_fields(cls, f: list[bytes]) -> "ClientHello":
        return cls(
            client_id=_client_id(f[0]),
            eph_pub=_expect("eph_pub", f[1], crypto.X25519_KEY_LEN),
            nonce=_expect("nonce", f[2], HELLO_NONCE_LEN),
            timestamp=from_u64(f[3]),
            signature=_expect("signature", f[4], crypto.ED25519_SIG_LEN),
        )


@dataclass(frozen=True)
class ServerHello:
    session_id: bytes
    eph_pub: bytes
    nonce: bytes
    expires_at: int
    signature: bytes = b""

    def signed_payload(self, transcript_hash: bytes) -> bytes:
        # The gateway signs the hash of the exact ClientHello it answered,
        # binding the two halves of the handshake together.
        return LABEL_SERVER_HELLO + encode_fields(
            transcript_hash, self.session_id, self.eph_pub, self.nonce, u64(self.expires_at)
        )

    def encode(self) -> bytes:
        return _wrap(
            MsgType.SERVER_HELLO,
            self.session_id,
            self.eph_pub,
            self.nonce,
            u64(self.expires_at),
            self.signature,
        )

    @classmethod
    def from_fields(cls, f: list[bytes]) -> "ServerHello":
        return cls(
            session_id=_expect("session_id", f[0], SESSION_ID_LEN),
            eph_pub=_expect("eph_pub", f[1], crypto.X25519_KEY_LEN),
            nonce=_expect("nonce", f[2], HELLO_NONCE_LEN),
            expires_at=from_u64(f[3]),
            signature=_expect("signature", f[4], crypto.ED25519_SIG_LEN),
        )


@dataclass(frozen=True)
class ProtectedRequest:
    """session ID || sequence number || 96-bit nonce || timestamp || ciphertext||tag."""

    session_id: bytes
    seq: int
    nonce: bytes
    timestamp: int
    ciphertext: bytes

    def aad(self) -> bytes:
        return LABEL_REQUEST + encode_fields(
            self.session_id, u64(self.seq), self.nonce, u64(self.timestamp)
        )

    def encode(self) -> bytes:
        return _wrap(
            MsgType.REQUEST,
            self.session_id,
            u64(self.seq),
            self.nonce,
            u64(self.timestamp),
            self.ciphertext,
        )

    @classmethod
    def from_fields(cls, f: list[bytes]) -> "ProtectedRequest":
        if len(f[4]) < crypto.GCM_TAG_LEN:
            raise malformed("ciphertext shorter than GCM tag")
        return cls(
            session_id=_expect("session_id", f[0], SESSION_ID_LEN),
            seq=from_u64(f[1]),
            nonce=_expect("nonce", f[2], crypto.GCM_NONCE_LEN),
            timestamp=from_u64(f[3]),
            ciphertext=f[4],
        )


@dataclass(frozen=True)
class ProtectedResponse:
    session_id: bytes
    seq: int
    nonce: bytes
    ciphertext: bytes

    def aad(self) -> bytes:
        return LABEL_RESPONSE + encode_fields(self.session_id, u64(self.seq), self.nonce)

    def encode(self) -> bytes:
        return _wrap(MsgType.RESPONSE, self.session_id, u64(self.seq), self.nonce, self.ciphertext)

    @classmethod
    def from_fields(cls, f: list[bytes]) -> "ProtectedResponse":
        if len(f[3]) < crypto.GCM_TAG_LEN:
            raise malformed("ciphertext shorter than GCM tag")
        return cls(
            session_id=_expect("session_id", f[0], SESSION_ID_LEN),
            seq=from_u64(f[1]),
            nonce=_expect("nonce", f[2], crypto.GCM_NONCE_LEN),
            ciphertext=f[3],
        )


@dataclass(frozen=True)
class ErrorFrame:
    reason: str
    detail: str = ""

    def encode(self) -> bytes:
        return _wrap(MsgType.ERROR, self.reason.encode(), self.detail.encode())

    @classmethod
    def from_fields(cls, f: list[bytes]) -> "ErrorFrame":
        try:
            return cls(f[0].decode(), f[1].decode())
        except UnicodeDecodeError as exc:
            raise malformed("error frame is not UTF-8") from exc


Message = Union[ClientHello, ServerHello, ProtectedRequest, ProtectedResponse, ErrorFrame]

_DECODERS = {
    MsgType.CLIENT_HELLO: (ClientHello, 5),
    MsgType.SERVER_HELLO: (ServerHello, 5),
    MsgType.REQUEST: (ProtectedRequest, 5),
    MsgType.RESPONSE: (ProtectedResponse, 4),
    MsgType.ERROR: (ErrorFrame, 2),
}


def decode_message(data: bytes) -> Message:
    if len(data) < 2:
        raise malformed("message too short")
    try:
        msg_type = MsgType(data[0])
    except ValueError as exc:
        raise malformed("unknown message type") from exc
    if data[1] != PROTOCOL_VERSION:
        raise malformed("unsupported protocol version")
    cls, count = _DECODERS[msg_type]
    return cls.from_fields(decode_fields(data[2:], count))
