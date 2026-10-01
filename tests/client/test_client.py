import pytest

from flowstate.client import GatewayRejected, SecureClient
from flowstate.core import crypto


def test_request_performs_handshake_automatically(make_client):
    c = make_client("alice")
    assert c.session is None
    c.request("balance")
    assert c.session is not None and c.seq == 1
    c.request("balance")
    assert c.seq == 2


def test_wrong_pinned_gateway_key(stack):
    c = SecureClient(
        stack.gateway_addr, "alice", stack.identities.client_keys["alice"],
        crypto.SigningKey.generate().public_key(),
    )
    with c, pytest.raises(GatewayRejected) as exc:
        c.handshake()
    assert exc.value.reason == "INVALID_SIGNATURE"


def test_build_request_requires_session(make_client):
    with pytest.raises(RuntimeError):
        make_client("alice").build_request("balance")


def test_new_handshake_resets_sequence(make_client):
    c = make_client("alice")
    c.request("balance")
    first = c.session.session_id
    c.handshake()
    assert c.seq == 0 and c.session.session_id != first
    assert c.request("balance")["status"] == "ok"
