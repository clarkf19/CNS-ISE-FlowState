"""The dashboard drives the real gateway; check its API end to end over HTTP."""

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from dashboard.__main__ import make_handler
from dashboard.app import Dashboard


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    app = Dashboard(audit_path=tmp_path_factory.mktemp("dash") / "audit.jsonl")
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(app))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    app.close()


def call(base, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read())


def test_static_page_served(server):
    with urllib.request.urlopen(server + "/", timeout=5) as resp:
        assert b"FlowState" in resp.read()
    with pytest.raises(urllib.error.HTTPError):
        urllib.request.urlopen(server + "/../pyproject.toml", timeout=5)


def test_live_flow(server):
    status, r = call(server, "/api/request", {"client_id": "alice", "op": "transfer",
                                               "params": {"to": "bob", "amount": 100}})
    assert status == 200 and r["ok"] and r["handshake"]["ok"]
    assert r["frame"]["seq"] == 1 and len(r["frame"]["tag"]) == 32
    assert [e["reason"] for e in r["events"]] == ["ACCEPTED", "ACCEPTED"]

    _, replay = call(server, "/api/replay", {"client_id": "alice"})
    assert replay["reason"] == "DUPLICATE_NONCE" and replay["events"][-1]["stage"] == "replay"
    _, tamper = call(server, "/api/tamper", {"client_id": "alice"})
    assert tamper["reason"] == "MODIFIED_MESSAGE" and tamper["events"][-1]["stage"] == "decrypt"
    _, denied = call(server, "/api/request", {"client_id": "alice", "op": "freeze_account",
                                              "params": {"account": "bob"}})
    assert denied["reason"] == "UNAUTHORIZED_OPERATION"

    _, state = call(server, "/api/state")
    assert next(a for a in state["accounts"] if a["account"] == "bob")["balance"] == 1100
    assert state["audit"]["ok"] and state["audit"]["entries"] == len(state["events"])


def test_session_expiry_via_clock(server):
    call(server, "/api/request", {"client_id": "bob", "op": "balance"})
    _, state = call(server, "/api/state")
    call(server, "/api/clock", {"advance_ms": state["settings"]["session_ttl_ms"] + 1000})
    _, r = call(server, "/api/request", {"client_id": "bob", "op": "balance"})
    assert r["reason"] == "EXPIRED_SESSION"
    _, h = call(server, "/api/handshake", {"client_id": "bob"})
    assert h["ok"] and h["server_hello"] and h["keys"]["c2g"] != h["keys"]["g2c"]


def test_attack_endpoint(server):
    _, results = call(server, "/api/attack", {"name": "replay_request"})
    assert results[0]["blocked"]
    status, _ = call(server, "/api/attack", {"name": "nope"})
    assert status == 400


def test_bad_input(server):
    assert call(server, "/api/request", {"client_id": "mallory", "op": "balance"})[0] == 400
    assert call(server, "/api/replay", {"client_id": "carol"})[0] == 400
    assert call(server, "/api/unknown", {})[0] == 404
