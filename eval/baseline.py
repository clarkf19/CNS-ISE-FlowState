"""Baseline for comparison: a plain forwarding proxy with no message security.

This models the common "API gateway that just forwards" setup from the
literature survey: the client sends {client_id, op, params} in clear JSON and
the proxy forwards it to the same backend. Used to measure the gateway's
overhead and to show which attacks succeed without it.
"""

from __future__ import annotations

import asyncio
import json
import socket
import threading

from flowstate.backend.server import BackendClient
from flowstate.core.codec import read_frame, recv_frame, send_frame, write_frame
from flowstate.core.reasons import SecurityError
from flowstate.gateway.runtime import Stack, cancel_pending_tasks


class PlainProxy:
    def __init__(self, stack: Stack) -> None:
        self._roles = {rec.client_id: rec.role for rec in stack.identities.registry.records()}
        self._backend = BackendClient(*stack.backend_addr, stack.identities.backend_token)
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self.address: tuple[str, int] | None = None

    async def _on_connection(self, reader, writer) -> None:
        try:
            while (raw := await read_frame(reader)) is not None:
                req = json.loads(raw)
                cid = req.get("client_id", "")
                result = await self._backend.call(cid, self._roles.get(cid, ""), req["op"], req.get("params", {}))
                await write_frame(writer, json.dumps(result).encode())
        except (ConnectionError, SecurityError, ValueError, KeyError, asyncio.CancelledError):
            pass
        finally:
            writer.close()

    def start(self) -> "PlainProxy":
        self._thread.start()

        async def boot():
            return await asyncio.start_server(self._on_connection, "127.0.0.1", 0)

        self._server = asyncio.run_coroutine_threadsafe(boot(), self._loop).result(5)
        self.address = ("127.0.0.1", self._server.sockets[0].getsockname()[1])
        return self

    def stop(self) -> None:
        async def close():
            self._server.close()
            await cancel_pending_tasks()

        asyncio.run_coroutine_threadsafe(close(), self._loop).result(5)
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(5)
        self._loop.close()

    def __enter__(self) -> "PlainProxy":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()


class PlainClient:
    def __init__(self, address: tuple[str, int], client_id: str) -> None:
        self.sock = socket.create_connection(address, timeout=5)
        self.client_id = client_id

    @staticmethod
    def encode(client_id: str, op: str, params: dict) -> bytes:
        return json.dumps({"client_id": client_id, "op": op, "params": params}).encode()

    def send_raw(self, payload: bytes) -> dict:
        send_frame(self.sock, payload)
        return json.loads(recv_frame(self.sock))

    def request(self, op: str, **params) -> dict:
        return self.send_raw(self.encode(self.client_id, op, params))

    def close(self) -> None:
        self.sock.close()


def baseline_attacks(stack: Stack, proxy: PlainProxy) -> dict[str, bool]:
    """Run the same attack ideas against the baseline. True = the attack succeeded."""
    service = stack.backend.service
    results = {}

    # Tampering: attacker on the path rewrites the amount in the clear JSON.
    bob = service.accounts["bob"].balance
    original = PlainClient.encode("alice", "transfer", {"to": "bob", "amount": 100})
    c = PlainClient(proxy.address, "alice")
    c.send_raw(original.replace(b'"amount": 100', b'"amount": 900'))
    results["mitm_tampering"] = service.accounts["bob"].balance - bob == 900

    # Replay: resending the captured request executes it again.
    bob = service.accounts["bob"].balance
    c.send_raw(PlainClient.encode("alice", "transfer", {"to": "bob", "amount": 10}))
    c.send_raw(PlainClient.encode("alice", "transfer", {"to": "bob", "amount": 10}))
    results["replay_request"] = service.accounts["bob"].balance - bob == 20

    # Impersonation: just claim to be someone else.
    m = PlainClient(proxy.address, "bob")
    results["impersonation"] = m.request("balance")["status"] == "ok"
    m.close()

    # Eavesdropping: the request is plaintext on the wire.
    results["eavesdropping"] = b"transfer" in original
    c.close()
    return results
