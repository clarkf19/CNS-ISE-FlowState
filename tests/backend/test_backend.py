import json

import pytest

from flowstate.backend.server import BackendServer
from flowstate.backend.service import ServiceError, TransactionService


@pytest.fixture
def svc():
    return TransactionService()


def test_balance_and_transfer(svc):
    assert svc.execute("alice", "balance", {}) == {"account": "alice", "balance": 5000}
    tx = svc.execute("alice", "transfer", {"to": "bob", "amount": 1000})
    assert tx["balance"] == 4000 and tx["tx_id"] == 1
    assert svc.accounts["bob"].balance == 2000
    assert svc.ledger == [{"tx_id": 1, "from": "alice", "to": "bob", "amount": 1000}]


@pytest.mark.parametrize(
    "params",
    [{"to": "bob", "amount": 0}, {"to": "bob", "amount": -5}, {"to": "bob", "amount": "10"},
     {"to": "bob", "amount": True}, {"to": "bob", "amount": 10**9}, {"to": "zed", "amount": 1},
     {"to": "alice", "amount": 1}],
)
def test_invalid_transfers(svc, params):
    with pytest.raises(ServiceError):
        svc.execute("alice", "transfer", params)
    assert svc.accounts["alice"].balance == 5000


def test_admin_operations(svc):
    svc.execute("root", "freeze_account", {"account": "bob"})
    with pytest.raises(ServiceError):
        svc.execute("alice", "transfer", {"to": "bob", "amount": 1})
    svc.execute("root", "create_account", {"account": "dave", "initial": 10})
    names = [a["account"] for a in svc.execute("root", "list_accounts", {})["accounts"]]
    assert "dave" in names
    with pytest.raises(ServiceError):
        svc.execute("root", "create_account", {"account": "dave"})
    with pytest.raises(ServiceError):
        svc.execute("root", "nope", {})


def test_server_requires_gateway_token(svc):
    server = BackendServer(svc, b"\x01" * 32)
    body = {"client_id": "alice", "role": "admin", "op": "transfer", "params": {"to": "bob", "amount": 1}}
    bad = server.handle_request(json.dumps({**body, "token": "00" * 32}).encode())
    assert bad["status"] == "error" and "forbidden" in bad["error"]
    assert server.rejected_direct_calls == 1
    assert server.handle_request(b"not json")["status"] == "error"
    good = server.handle_request(json.dumps({**body, "token": "01" * 32}).encode())
    assert good["status"] == "ok"
