"""Run backend + gateway in a background event loop.

Used by the integration tests, the attack simulation suite and the
evaluation harness, so all of them exercise the real network stack on
ephemeral loopback ports.
"""

from __future__ import annotations

import asyncio
import threading
from dataclasses import dataclass, field
from pathlib import Path

from flowstate.audit import AuditLogger
from flowstate.authz import Policy
from flowstate.backend.server import BackendClient, BackendServer
from flowstate.backend.service import TransactionService
from flowstate.core import crypto
from flowstate.core.clock import Clock
from flowstate.core.events import MemorySink, MultiSink
from flowstate.gateway.server import Gateway, GatewaySettings
from flowstate.identity.registry import ClientRegistry

DEFAULT_POLICY = {
    "roles": {
        "customer": ["accounts:read", "payments:transfer"],
        "auditor": ["accounts:read", "admin:read"],
        "admin": ["accounts:read", "payments:transfer", "admin:read", "admin:write"],
    },
    "operations": {
        "balance": "accounts:read",
        "transfer": "payments:transfer",
        "list_accounts": "admin:read",
        "freeze_account": "admin:write",
        "create_account": "admin:write",
    },
}

DEMO_ROLES = {"alice": "customer", "bob": "customer", "carol": "auditor", "root": "admin"}


async def cancel_pending_tasks() -> None:
    """Cancel open connection handlers so a background loop can shut down cleanly."""
    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


@dataclass
class Identities:
    gateway_key: crypto.SigningKey
    client_keys: dict[str, crypto.SigningKey]
    registry: ClientRegistry
    backend_token: bytes

    @property
    def gateway_pin(self) -> crypto.VerifyKey:
        return self.gateway_key.public_key()

    @classmethod
    def generate(cls, roles: dict[str, str] | None = None) -> "Identities":
        registry = ClientRegistry()
        keys: dict[str, crypto.SigningKey] = {}
        for client_id, role in (roles or DEMO_ROLES).items():
            keys[client_id] = crypto.SigningKey.generate()
            registry.register(client_id, keys[client_id].public_key(), role)
        return cls(crypto.SigningKey.generate(), keys, registry, crypto.random_bytes(32))


@dataclass
class Stack:
    identities: Identities
    gateway: Gateway
    backend: BackendServer
    events: MemorySink
    gateway_addr: tuple[str, int]
    backend_addr: tuple[str, int]
    _loop: asyncio.AbstractEventLoop = field(repr=False)
    _thread: threading.Thread = field(repr=False)
    _servers: list = field(default_factory=list, repr=False)

    def stop(self) -> None:
        async def close() -> None:
            for srv in self._servers:
                srv.close()
            await cancel_pending_tasks()

        asyncio.run_coroutine_threadsafe(close(), self._loop).result(5)
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(5)
        self._loop.close()

    def __enter__(self) -> "Stack":
        return self

    def __exit__(self, *exc) -> None:
        self.stop()


def start_stack(
    *,
    identities: Identities | None = None,
    policy: Policy | None = None,
    settings: GatewaySettings | None = None,
    clock: Clock | None = None,
    audit_path: str | Path | None = None,
    host: str = "127.0.0.1",
) -> Stack:
    ids = identities or Identities.generate()
    events = MemorySink()
    sink = MultiSink(events, AuditLogger(audit_path)) if audit_path else events
    service = TransactionService()
    backend = BackendServer(service, ids.backend_token)

    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, name="flowstate-stack", daemon=True)
    thread.start()

    async def boot():
        backend_srv = await backend.start(host, 0)
        backend_port = backend_srv.sockets[0].getsockname()[1]
        gateway = Gateway(
            signing_key=ids.gateway_key,
            registry=ids.registry,
            policy=policy or Policy.from_dict(DEFAULT_POLICY),
            backend=BackendClient(host, backend_port, ids.backend_token),
            sink=sink,
            clock=clock,
            settings=settings,
        )
        gateway_srv = await gateway.start(host, 0)
        return gateway, [gateway_srv, backend_srv], backend_port, gateway_srv.sockets[0].getsockname()[1]

    gateway, servers, backend_port, gateway_port = asyncio.run_coroutine_threadsafe(
        boot(), loop
    ).result(5)
    return Stack(
        ids, gateway, backend, events, (host, gateway_port), (host, backend_port),
        loop, thread, servers,
    )
