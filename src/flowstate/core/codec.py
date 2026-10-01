"""Canonical binary encoding and stream framing.

Every structure that is signed or authenticated is serialized with
``encode_fields``: each field is a 4-byte big-endian length followed by its
bytes. The encoding is injective (two different field lists can never produce
the same bytes), so a signature or GCM tag over it cannot be re-interpreted
as covering different values. Integers are fixed 8-byte big-endian.

On the wire each message is preceded by a 4-byte big-endian length.
"""

from __future__ import annotations

import asyncio
import socket
import struct

from flowstate.core.reasons import ReasonCode, SecurityError

MAX_FRAME_LEN = 64 * 1024
_U32 = struct.Struct(">I")
_U64 = struct.Struct(">Q")


def malformed(detail: str) -> SecurityError:
    return SecurityError(ReasonCode.MALFORMED_FRAME, detail)


def u64(value: int) -> bytes:
    if not 0 <= value < 2**64:
        raise malformed("integer out of range")
    return _U64.pack(value)


def from_u64(data: bytes) -> int:
    if len(data) != 8:
        raise malformed("integer field must be 8 bytes")
    return _U64.unpack(data)[0]


def encode_fields(*fields: bytes) -> bytes:
    out = bytearray()
    for field in fields:
        out += _U32.pack(len(field))
        out += field
    return bytes(out)


def decode_fields(data: bytes, count: int) -> list[bytes]:
    """Decode exactly ``count`` fields; reject truncation and trailing bytes."""
    fields: list[bytes] = []
    pos = 0
    for _ in range(count):
        if pos + 4 > len(data):
            raise malformed("truncated field length")
        (length,) = _U32.unpack_from(data, pos)
        pos += 4
        if pos + length > len(data):
            raise malformed("truncated field")
        fields.append(bytes(data[pos : pos + length]))
        pos += length
    if pos != len(data):
        raise malformed("trailing bytes after last field")
    return fields


# ---------------------------------------------------------------- framing


def frame(payload: bytes) -> bytes:
    if len(payload) > MAX_FRAME_LEN:
        raise malformed("frame too large")
    return _U32.pack(len(payload)) + payload


async def read_frame(reader: asyncio.StreamReader) -> bytes | None:
    """Read one frame. Returns None on clean EOF before a frame starts."""
    try:
        header = await reader.readexactly(4)
    except asyncio.IncompleteReadError as exc:
        if not exc.partial:
            return None
        raise malformed("truncated frame header") from exc
    (length,) = _U32.unpack(header)
    if length > MAX_FRAME_LEN:
        raise malformed("frame too large")
    try:
        return await reader.readexactly(length)
    except asyncio.IncompleteReadError as exc:
        raise malformed("truncated frame body") from exc


async def write_frame(writer: asyncio.StreamWriter, payload: bytes) -> None:
    writer.write(frame(payload))
    await writer.drain()


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return bytes(buf)


def recv_frame(sock: socket.socket) -> bytes:
    (length,) = _U32.unpack(_recv_exact(sock, 4))
    if length > MAX_FRAME_LEN:
        raise malformed("frame too large")
    return _recv_exact(sock, length)


def send_frame(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(frame(payload))
