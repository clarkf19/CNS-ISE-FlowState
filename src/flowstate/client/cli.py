"""Demo client.

  flowstate-client --id alice balance
  flowstate-client --id alice transfer --to bob --amount 1000
  flowstate-client --id carol list-accounts
  flowstate-client --id root  freeze --account bob
  flowstate-client --id root  create-account --account dave --initial 100
"""

from __future__ import annotations

import argparse
import json
import sys

from flowstate.client.client import GatewayRejected, SecureClient
from flowstate.core.config import load_config
from flowstate.identity.cli import client_key_path, gateway_pub_path
from flowstate.identity.keys import load_public_key, load_signing_key


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="flowstate-client")
    parser.add_argument("--config", default="config/gateway.toml")
    parser.add_argument("--id", required=True, help="client id (key read from keys/<id>.key)")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("balance")
    t = sub.add_parser("transfer")
    t.add_argument("--to", required=True)
    t.add_argument("--amount", type=int, required=True)
    sub.add_parser("list-accounts")
    f = sub.add_parser("freeze")
    f.add_argument("--account", required=True)
    f.add_argument("--unfreeze", action="store_true")
    c = sub.add_parser("create-account")
    c.add_argument("--account", required=True)
    c.add_argument("--initial", type=int, default=0)
    args = parser.parse_args(argv)

    cfg = load_config(args.config)
    client = SecureClient(
        (cfg.host, cfg.port),
        args.id,
        load_signing_key(client_key_path(cfg, args.id)),
        load_public_key(gateway_pub_path(cfg)),
    )
    calls = {
        "balance": lambda: client.request("balance"),
        "transfer": lambda: client.request("transfer", to=args.to, amount=args.amount),
        "list-accounts": lambda: client.request("list_accounts"),
        "freeze": lambda: client.request(
            "freeze_account", account=args.account, frozen=not args.unfreeze
        ),
        "create-account": lambda: client.request(
            "create_account", account=args.account, initial=args.initial
        ),
    }
    try:
        with client:
            print(json.dumps(calls[args.cmd](), indent=2))
    except GatewayRejected as exc:
        print(f"rejected by gateway: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"cannot reach gateway at {cfg.host}:{cfg.port}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
