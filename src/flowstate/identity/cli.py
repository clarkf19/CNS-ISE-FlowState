"""Key generation and client registration (proposal section 4.2, step 1).

Registration is split the way the proposal describes it: the *client*
generates its own Ed25519 key pair and keeps the private key; only the public
key and the client's role are registered with the gateway.

  Client side:   flowstate-keys keygen   --client-id dave
                   -> keys/dave.key (private, stays with the client)
                   -> keys/dave.pub (public, sent to the gateway operator)
  Gateway side:  flowstate-keys register --client-id dave --role customer --public-key keys/dave.pub
  Gateway setup: flowstate-keys init-gateway   (gateway key pair; gateway.pub is pinned on clients)
  Demo:          flowstate-keys bootstrap      (all of the above for alice, bob, carol, root)
"""

from __future__ import annotations

import argparse
from pathlib import Path

from flowstate.core import crypto
from flowstate.core.config import GatewayConfig, load_config
from flowstate.identity.keys import (
    load_public_key,
    save_public_key,
    save_secret,
    save_signing_key,
)
from flowstate.identity.registry import ClientRegistry

DEMO_CLIENTS = {
    "alice": "customer",
    "bob": "customer",
    "carol": "auditor",
    "root": "admin",
}


def keys_dir(cfg: GatewayConfig) -> Path:
    return cfg.gateway_key_path.parent


def gateway_pub_path(cfg: GatewayConfig) -> Path:
    return cfg.gateway_key_path.with_suffix(".pub")


def client_key_path(cfg: GatewayConfig, client_id: str) -> Path:
    return keys_dir(cfg) / f"{client_id}.key"


def client_pub_path(cfg: GatewayConfig, client_id: str) -> Path:
    return keys_dir(cfg) / f"{client_id}.pub"


def init_gateway(cfg: GatewayConfig) -> None:
    key = crypto.SigningKey.generate()
    save_signing_key(cfg.gateway_key_path, key)
    # The public key is the pinning bundle installed on every client.
    save_public_key(gateway_pub_path(cfg), key.public_key())
    save_secret(cfg.backend_token_path, crypto.random_bytes(32))


def generate_client_key(cfg: GatewayConfig, client_id: str) -> tuple[Path, Path]:
    """Client side: create a key pair. Returns (private key path, public key path)."""
    key = crypto.SigningKey.generate()
    priv, pub = client_key_path(cfg, client_id), client_pub_path(cfg, client_id)
    save_signing_key(priv, key)
    save_public_key(pub, key.public_key())
    return priv, pub


def register_client(
    cfg: GatewayConfig, client_id: str, role: str, public_key: crypto.VerifyKey,
    *, replace: bool = False,
) -> None:
    """Gateway side: register a client's public key and role. Never sees the private key."""
    registry = (
        ClientRegistry.load(cfg.registry_path)
        if cfg.registry_path.exists()
        else ClientRegistry(cfg.registry_path)
    )
    registry.register(client_id, public_key, role, replace=replace)
    registry.save()


def bootstrap(cfg: GatewayConfig, *, force: bool = False) -> None:
    if cfg.gateway_key_path.exists() and not force:
        raise SystemExit(f"{cfg.gateway_key_path} exists; pass --force to regenerate")
    if cfg.registry_path.exists():
        cfg.registry_path.unlink()
    init_gateway(cfg)
    for client_id, role in DEMO_CLIENTS.items():
        _, pub = generate_client_key(cfg, client_id)
        register_client(cfg, client_id, role, load_public_key(pub))


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="flowstate-keys")
    parser.add_argument("--config", default="config/gateway.toml")
    sub = parser.add_subparsers(dest="cmd", required=True)
    boot = sub.add_parser("bootstrap", help="create gateway keys and the demo clients")
    boot.add_argument("--force", action="store_true")
    sub.add_parser("init-gateway", help="create the gateway key pair and backend token")
    gen = sub.add_parser("keygen", help="[client] generate this client's key pair")
    gen.add_argument("--client-id", required=True)
    reg = sub.add_parser("register", help="[gateway] register a client's public key and role")
    reg.add_argument("--client-id", required=True)
    reg.add_argument("--role", required=True)
    reg.add_argument("--public-key", required=True, help="path to the client's .pub file")
    reg.add_argument("--replace", action="store_true")
    args = parser.parse_args(argv)

    cfg = load_config(args.config)
    if args.cmd == "bootstrap":
        bootstrap(cfg, force=args.force)
        print(f"gateway key, pin and backend token written to {keys_dir(cfg)}")
        for client_id, role in DEMO_CLIENTS.items():
            print(f"  registered {client_id:<6} role={role}")
    elif args.cmd == "init-gateway":
        init_gateway(cfg)
        print(f"gateway key written to {cfg.gateway_key_path}; pin clients to {gateway_pub_path(cfg)}")
    elif args.cmd == "keygen":
        priv, pub = generate_client_key(cfg, args.client_id)
        print(f"private key: {priv} (keep secret)\npublic key:  {pub} (give to the gateway operator)")
    else:
        register_client(
            cfg, args.client_id, args.role, load_public_key(args.public_key), replace=args.replace
        )
        print(f"registered {args.client_id} ({args.role})")


if __name__ == "__main__":
    main()
