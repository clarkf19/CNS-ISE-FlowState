"""Backend TCP server and the gateway's forwarding client.

The backend listens on loopback and accepts a request only if it carries the
gateway's shared forwarding token, so clients cannot bypass the gateway and
call the backend directly.

Wire format: length-prefixed JSON.
  request  {"token": hex, "client_id": str, "role": str, "op": str, "params": {}}
  response {"status": "ok", "result": {...}} | {"status": "error", "error": str}
"""

from __future__ import annotations

import asyncio
import json

from flowstate.backend.service import ServiceError, TransactionService
from flowstate.core import crypto
from flowstate.core.codec import read_frame, write_frame
from flowstate.core.reasons import SecurityError


class BackendServer:
    def __init__(self, service: TransactionService, token: bytes) -> None:
        self.service = service
        self._token = token
        self.rejected_direct_calls = 0

    def handle_request(self, raw: bytes) -> dict:
        try:
            req = json.loads(raw.decode())
            token = bytes.fromhex(req.get("token", ""))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, AttributeError):
            return {"status": "error", "error": "bad request"}
        if not crypto.constant_time_eq(token, self._token):
            self.rejected_direct_calls += 1
            return {"status": "error", "error": "forbidden: requests must come through the gateway"}
        try:
            result = self.service.execute(req["client_id"], req["op"], req.get("params") or {})
        except (ServiceError, KeyError, TypeError) as exc:
            return {"status": "error", "error": str(exc)}
        return {"status": "ok", "result": result}

    async def _on_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while (raw := await read_frame(reader)) is not None:
                await write_frame(writer, json.dumps(self.handle_request(raw)).encode())
        except (SecurityError, ConnectionError):
            pass
        finally:
            writer.close()

    async def start(self, host: str, port: int) -> asyncio.Server:
        return await asyncio.start_server(self._on_connection, host, port)


class BackendClient:
    """Used by the gateway to forward verified requests.

    Keeps a small pool of persistent connections to the backend instead of
    opening one per request. Must be used from a single event loop.
    """

    def __init__(
        self, host: str, port: int, token: bytes, timeout_s: float = 5.0, pool_size: int = 16
    ) -> None:
        self.host, self.port, self._token, self.timeout_s = host, port, token, timeout_s
        self.pool_size = pool_size
        self._idle: list[tuple[asyncio.StreamReader, asyncio.StreamWriter]] = []

    async def _acquire(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        while self._idle:
            reader, writer = self._idle.pop()
            if not writer.is_closing() and not reader.at_eof():
                return reader, writer
            writer.close()
        return await asyncio.open_connection(self.host, self.port)

    def _release(self, conn: tuple[asyncio.StreamReader, asyncio.StreamWriter]) -> None:
        if len(self._idle) < self.pool_size:
            self._idle.append(conn)
        else:
            conn[1].close()

    async def call(self, client_id: str, role: str, op: str, params: dict) -> dict:
        body = json.dumps(
            {"token": self._token.hex(), "client_id": client_id, "role": role,
             "op": op, "params": params}
        ).encode()

        async def roundtrip() -> dict:
            reader, writer = await self._acquire()
            try:
                await write_frame(writer, body)
                raw = await read_frame(reader)
            except BaseException:
                writer.close()  # never return a connection in an unknown state
                raise
            if raw is None:
                writer.close()
                raise ConnectionError("backend closed connection")
            self._release((reader, writer))
            return json.loads(raw.decode())

        try:
            return await asyncio.wait_for(roundtrip(), self.timeout_s)
        except (OSError, asyncio.TimeoutError, SecurityError, json.JSONDecodeError):
            return {"status": "error", "error": "backend unavailable"}
