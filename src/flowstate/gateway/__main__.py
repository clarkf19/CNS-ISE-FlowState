"""Run the Secure Network Gateway: python -m flowstate.gateway"""

from __future__ import annotations

import argparse
import asyncio

from flowstate.audit import AuditLogger
from flowstate.authz import Policy
from flowstate.backend.server import BackendClient
from flowstate.core.config import load_config
from flowstate.core.events import MultiSink, SecurityEvent
from flowstate.gateway.server import Gateway, GatewaySettings
from flowstate.identity.keys import load_secret, load_signing_key
from flowstate.identity.registry import ClientRegistry


class ConsoleSink:
    def record(self, event: SecurityEvent) -> None:
        mark = "OK " if event.accepted else "REJ"
        print(
            f"[{mark}] {event.phase:<9} {event.reason.value:<24} "
            f"client={event.client_id or '-':<8} op={event.operation or '-':<14} {event.detail}",
            flush=True,
        )


async def serve(config_path: str) -> None:
    cfg = load_config(config_path)
    audit = AuditLogger(cfg.audit_log_path)
    gateway = Gateway(
        signing_key=load_signing_key(cfg.gateway_key_path),
        registry=ClientRegistry.load(cfg.registry_path),
        policy=Policy.load(cfg.policy_path),
        backend=BackendClient(cfg.backend_host, cfg.backend_port, load_secret(cfg.backend_token_path)),
        sink=MultiSink(audit, ConsoleSink()),
        settings=GatewaySettings(
            session_ttl_ms=cfg.session_ttl_s * 1000,
            max_skew_ms=cfg.max_skew_ms,
            nonce_cache_size=cfg.nonce_cache_size,
            max_requests_per_session=cfg.max_requests_per_session,
        ),
    )
    srv = await gateway.start(cfg.host, cfg.port)
    print(f"gateway listening on {cfg.host}:{cfg.port}; audit log {cfg.audit_log_path}")

    async def reaper() -> None:  # periodically drop expired sessions and their keys
        while True:
            await asyncio.sleep(30)
            gateway.sessions.cleanup_expired()

    reaper_task = asyncio.create_task(reaper())
    async with srv:
        try:
            await srv.serve_forever()
        finally:
            reaper_task.cancel()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="flowstate-gateway")
    parser.add_argument("--config", default="config/gateway.toml")
    args = parser.parse_args(argv)
    try:
        asyncio.run(serve(args.config))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
