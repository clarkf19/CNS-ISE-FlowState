"""Run the backend transaction service: python -m flowstate.backend"""

from __future__ import annotations

import argparse
import asyncio

from flowstate.backend.server import BackendServer
from flowstate.backend.service import TransactionService
from flowstate.core.config import load_config
from flowstate.identity.keys import load_secret


async def serve(config_path: str) -> None:
    cfg = load_config(config_path)
    server = BackendServer(TransactionService(), load_secret(cfg.backend_token_path))
    srv = await server.start(cfg.backend_host, cfg.backend_port)
    print(f"backend listening on {cfg.backend_host}:{cfg.backend_port}")
    async with srv:
        await srv.serve_forever()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="flowstate-backend")
    parser.add_argument("--config", default="config/gateway.toml")
    args = parser.parse_args(argv)
    try:
        asyncio.run(serve(args.config))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
