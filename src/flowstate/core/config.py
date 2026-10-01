"""Gateway configuration, loaded from TOML.

Relative paths are resolved against the directory containing the config file.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, fields
from pathlib import Path


@dataclass
class GatewayConfig:
    host: str = "127.0.0.1"
    port: int = 9000
    backend_host: str = "127.0.0.1"
    backend_port: int = 9100
    session_ttl_s: int = 300
    max_skew_ms: int = 30_000
    nonce_cache_size: int = 4096
    max_requests_per_session: int = 1_000_000
    registry_path: Path = Path("clients.json")
    policy_path: Path = Path("policy.toml")
    gateway_key_path: Path = Path("../keys/gateway.key")
    backend_token_path: Path = Path("../keys/backend.token")
    audit_log_path: Path = Path("../logs/audit.jsonl")


_PATH_FIELDS = {f.name for f in fields(GatewayConfig) if f.name.endswith("_path")}


def load_config(path: str | Path) -> GatewayConfig:
    path = Path(path)
    with path.open("rb") as fh:
        raw = tomllib.load(fh)
    known = {f.name for f in fields(GatewayConfig)}
    unknown = set(raw) - known
    if unknown:
        raise ValueError(f"unknown config keys: {sorted(unknown)}")
    cfg = GatewayConfig(**raw)
    for name in _PATH_FIELDS:
        value = Path(getattr(cfg, name))
        if not value.is_absolute():
            value = (path.parent / value).resolve()
        setattr(cfg, name, value)
    return cfg
