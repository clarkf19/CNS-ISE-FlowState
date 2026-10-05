"""End-to-end tests through the real TCP gateway and backend."""

import socket
import struct
import threading

import pytest

from flowstate.client import GatewayRejected
from flowstate.core.codec import recv_frame, send_frame
from flowstate.core.messages import ErrorFrame, ServerHello, decode_message
from flowstate.core.reasons import ReasonCode
from flowstate.gateway.runtime import start_stack
from flowstate.gateway.server import GatewaySettings


def test_builtin_policy_matches_config_file(policy):
    """The in-process stack (tests, attacks, dashboard) must enforce the shipped policy."""
    from flowstate.authz import Policy
    from flowstate.gateway.runtime import DEFAULT_POLICY

    assert Policy.from_dict(DEFAULT_POLICY) == policy


def raw(stack, payload: bytes):
    with socket.create_connection(stack.gateway_addr, timeout=5) as sock:
        send_frame(sock, payload)
        return decode_message(recv_frame(sock))


def test_full_transaction(stack, make_client):
    c = make_client("alice").connect()
    assert c.request("balance")["result"]["balance"] == 5000
    tx = c.request("transfer", to="bob", amount=1000)
    assert tx["status"] == "ok" and tx["result"]["balance"] == 4000
    assert stack.backend.service.accounts["bob"].balance == 2000
    assert [e.reason for e in stack.events.events] == [ReasonCode.ACCEPTED] * 3
    assert stack.events.events[-1].operation == "transfer"


def test_backend_errors_are_returned_encrypted(make_client):
    reply = make_client("alice").request("transfer", to="bob", amount=10**9)
    assert reply["status"] == "error"


def test_roles_enforced_end_to_end(stack, make_client):
    assert make_client("carol").request("list_accounts")["status"] == "ok"
    assert make_client("root").request("freeze_account", account="bob")["status"] == "ok"
    with pytest.raises(GatewayRejected) as exc:
        make_client("carol").request("transfer", to="bob", amount=1)
    assert exc.value.reason == "UNAUTHORIZED_OPERATION"


def test_malformed_message_rejected_and_logged(stack):
    reply = raw(stack, b"\x03\x01garbage")
    assert isinstance(reply, ErrorFrame) and reply.reason == "MALFORMED_FRAME"
    assert stack.events.events[-1].reason is ReasonCode.MALFORMED_FRAME


def test_unexpected_message_type(stack):
    reply = raw(stack, ServerHello(b"\x00" * 16, b"\x00" * 32, b"\x00" * 16, 0, b"\x00" * 64).encode())
    assert reply.reason == "MALFORMED_FRAME"


def test_oversized_frame_closes_connection(stack):
    with socket.create_connection(stack.gateway_addr, timeout=5) as sock:
        sock.sendall(struct.pack(">I", 10**8))
        assert sock.recv(10) == b""
    assert stack.events.events[-1].reason is ReasonCode.MALFORMED_FRAME


def test_one_event_per_decision(stack, make_client):
    c = make_client("alice")
    c.request("balance")
    with pytest.raises(GatewayRejected):
        c.request("list_accounts")
    c.request("balance")
    assert len(stack.events.events) == 4  # handshake + 3 requests


def test_concurrent_clients(stack, make_client):
    errors = []

    def work(cid):
        try:
            c = make_client(cid)
            for _ in range(20):
                assert c.request("balance")["status"] == "ok"
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(cid,)) for cid in ("alice", "bob", "carol", "root") * 2]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert len(stack.gateway.sessions) == 8


def test_session_request_limit(identities, offset_clock):
    from flowstate.client import SecureClient

    with start_stack(identities=identities, settings=GatewaySettings(max_requests_per_session=2)) as st:
        c = SecureClient(st.gateway_addr, "alice", identities.client_keys["alice"], identities.gateway_pin)
        with c:
            c.request("balance")
            c.request("balance")
            with pytest.raises(GatewayRejected) as exc:
                c.request("balance")
            assert exc.value.reason == "EXPIRED_SESSION"
            c.handshake()  # a new session works
            assert c.request("balance")["status"] == "ok"


def test_audit_log_written(tmp_path, identities):
    from flowstate.audit import verify_chain
    from flowstate.client import SecureClient

    path = tmp_path / "audit.jsonl"
    with start_stack(identities=identities, audit_path=path) as st:
        with SecureClient(st.gateway_addr, "alice", identities.client_keys["alice"], identities.gateway_pin) as c:
            c.request("balance")
    text = path.read_text()
    assert verify_chain(path).entries == 2
    # Secrets never reach the log.
    assert "5000" not in text and identities.client_keys["alice"].private_bytes().hex() not in text
