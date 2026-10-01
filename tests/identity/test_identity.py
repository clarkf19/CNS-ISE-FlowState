from dataclasses import replace

import pytest

from flowstate.core import crypto
from flowstate.core.config import load_config
from flowstate.core.messages import ClientHello
from flowstate.core.reasons import ReasonCode, SecurityError
from flowstate.identity import cli
from flowstate.identity.auth import authenticate_client_hello, sign_client_hello
from flowstate.identity.keys import (
    load_public_key,
    load_signing_key,
    save_public_key,
    save_signing_key,
)
from flowstate.identity.registry import ClientRegistry


def hello(client_id="alice"):
    return ClientHello(client_id, crypto.EphemeralKeyPair().public_bytes(), b"\x01" * 16, 1000)


class TestRegistry:
    def test_register_get_save_load(self, tmp_path):
        reg = ClientRegistry()
        key = crypto.SigningKey.generate().public_key()
        reg.register("alice", key, "customer")
        assert reg.get("alice").role == "customer"
        assert "alice" in reg and "bob" not in reg
        reg.save(tmp_path / "r.json")
        loaded = ClientRegistry.load(tmp_path / "r.json")
        assert loaded.get("alice").public_key == key

    def test_duplicates_and_invalid_ids(self):
        reg = ClientRegistry()
        key = crypto.SigningKey.generate().public_key()
        reg.register("alice", key, "customer")
        with pytest.raises(ValueError):
            reg.register("alice", key, "admin")
        reg.register("alice", key, "admin", replace=True)
        assert reg.get("alice").role == "admin"
        with pytest.raises(ValueError):
            reg.register("not valid!", key, "customer")
        with pytest.raises(ValueError):
            reg.register("dave", key, "")

    def test_revoke(self):
        reg = ClientRegistry()
        reg.register("alice", crypto.SigningKey.generate().public_key(), "customer")
        reg.revoke("alice")
        assert reg.get("alice") is None


class TestAuthentication:
    def setup_method(self):
        self.key = crypto.SigningKey.generate()
        self.reg = ClientRegistry()
        self.reg.register("alice", self.key.public_key(), "customer")

    def test_valid_signature(self):
        record = authenticate_client_hello(sign_client_hello(hello(), self.key), self.reg)
        assert record.client_id == "alice"

    @pytest.mark.parametrize("field", ["eph_pub", "nonce", "timestamp", "client_id"])
    def test_any_signed_field_change_rejected(self, field):
        signed = sign_client_hello(hello(), self.key)
        changes = {
            "eph_pub": crypto.EphemeralKeyPair().public_bytes(),
            "nonce": b"\x02" * 16,
            "timestamp": 1001,
            "client_id": "bob",
        }
        self.reg.register("bob", self.key.public_key(), "customer")
        with pytest.raises(SecurityError) as exc:
            authenticate_client_hello(replace(signed, **{field: changes[field]}), self.reg)
        assert exc.value.reason is ReasonCode.INVALID_SIGNATURE

    def test_forged_key_and_unknown_client(self):
        forged = sign_client_hello(hello(), crypto.SigningKey.generate())
        for msg in (forged, sign_client_hello(hello("mallory"), self.key)):
            with pytest.raises(SecurityError) as exc:
                authenticate_client_hello(msg, self.reg)
            assert exc.value.reason is ReasonCode.INVALID_SIGNATURE


def test_key_files_roundtrip(tmp_path):
    key = crypto.SigningKey.generate()
    save_signing_key(tmp_path / "a.key", key)
    save_public_key(tmp_path / "a.pub", key.public_key())
    assert load_signing_key(tmp_path / "a.key").private_bytes() == key.private_bytes()
    assert load_public_key(tmp_path / "a.pub") == key.public_key()


def test_bootstrap_creates_working_identities(tmp_path):
    (tmp_path / "config").mkdir()
    cfg_path = tmp_path / "config" / "gateway.toml"
    cfg_path.write_text(
        'registry_path = "../keys/clients.json"\n'
        'gateway_key_path = "../keys/gateway.key"\n'
        'backend_token_path = "../keys/backend.token"\n'
    )
    cli.main(["--config", str(cfg_path), "bootstrap"])
    cfg = load_config(cfg_path)
    reg = ClientRegistry.load(cfg.registry_path)
    assert {r.client_id for r in reg.records()} == set(cli.DEMO_CLIENTS)
    alice = load_signing_key(cli.client_key_path(cfg, "alice"))
    assert reg.get("alice").public_key == alice.public_key()
    gw = load_signing_key(cfg.gateway_key_path)
    assert load_public_key(cli.gateway_pub_path(cfg)) == gw.public_key()

    with pytest.raises(SystemExit):  # refuses to overwrite without --force
        cli.main(["--config", str(cfg_path), "bootstrap"])


def test_registration_uses_only_the_clients_public_key(tmp_path):
    """Proposal step 1: the client generates its key pair; only the public key is registered."""
    (tmp_path / "config").mkdir()
    cfg_path = tmp_path / "config" / "gateway.toml"
    cfg_path.write_text('registry_path = "../gw/clients.json"\ngateway_key_path = "../keys/gateway.key"\n')
    cfg = load_config(cfg_path)

    cli.main(["--config", str(cfg_path), "keygen", "--client-id", "dave"])  # client side
    pub = cli.client_pub_path(cfg, "dave")
    cli.main(["--config", str(cfg_path), "register", "--client-id", "dave",
              "--role", "customer", "--public-key", str(pub)])                 # gateway side

    dave = load_signing_key(cli.client_key_path(cfg, "dave"))
    record = ClientRegistry.load(cfg.registry_path).get("dave")
    assert record.role == "customer" and record.public_key == dave.public_key()
    registry_text = cfg.registry_path.read_text()
    assert dave.private_bytes().hex() not in registry_text

