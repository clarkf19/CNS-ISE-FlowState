"""Registry of clients allowed to connect: client ID -> Ed25519 public key + role."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from pathlib import Path

from flowstate.core.crypto import VerifyKey
from flowstate.core.messages import CLIENT_ID_RE


@dataclass(frozen=True)
class ClientRecord:
    client_id: str
    public_key: VerifyKey
    role: str


class ClientRegistry:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self._clients: dict[str, ClientRecord] = {}
        self._lock = threading.Lock()

    @classmethod
    def load(cls, path: str | Path) -> "ClientRegistry":
        reg = cls(path)
        data = json.loads(Path(path).read_text())
        for client_id, entry in data.get("clients", {}).items():
            reg.register(client_id, VerifyKey(bytes.fromhex(entry["public_key"])), entry["role"])
        return reg

    def save(self, path: str | Path | None = None) -> None:
        target = Path(path) if path else self.path
        if target is None:
            raise ValueError("no registry path")
        target.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            data = {
                "clients": {
                    r.client_id: {"public_key": r.public_key.public_bytes().hex(), "role": r.role}
                    for r in sorted(self._clients.values(), key=lambda r: r.client_id)
                }
            }
        target.write_text(json.dumps(data, indent=2) + "\n")

    def register(
        self, client_id: str, public_key: VerifyKey, role: str, *, replace: bool = False
    ) -> ClientRecord:
        if not CLIENT_ID_RE.match(client_id):
            raise ValueError(f"invalid client id {client_id!r}")
        if not role:
            raise ValueError("role is required")
        record = ClientRecord(client_id, public_key, role)
        with self._lock:
            if client_id in self._clients and not replace:
                raise ValueError(f"client {client_id!r} already registered")
            self._clients[client_id] = record
        return record

    def revoke(self, client_id: str) -> None:
        with self._lock:
            self._clients.pop(client_id, None)

    def get(self, client_id: str) -> ClientRecord | None:
        with self._lock:
            return self._clients.get(client_id)

    def records(self) -> list[ClientRecord]:
        with self._lock:
            return list(self._clients.values())

    def __len__(self) -> int:
        return len(self._clients)

    def __contains__(self, client_id: str) -> bool:
        return self.get(client_id) is not None
