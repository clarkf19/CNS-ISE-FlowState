"""Dashboard application state: one live gateway stack plus the attack and evaluation runners.

Everything the page shows comes from the real components: requests go through
the real TCP gateway, attacks are the scenarios in ``attacks/``, and the
evaluation is ``eval.benchmark``. Nothing is simulated in the browser.
"""

from __future__ import annotations

import json
import threading
from dataclasses import replace
from pathlib import Path
from typing import Any

from attacks.runner import run_scenarios
from attacks.scenarios import ALL_SCENARIOS
from eval.benchmark import run as run_evaluation
from flowstate.audit import verify_chain
from flowstate.client import GatewayRejected, SecureClient
from flowstate.core import crypto
from flowstate.core.clock import OffsetClock
from flowstate.core.messages import ProtectedRequest
from flowstate.gateway.runtime import DEFAULT_POLICY, start_stack

ROOT = Path(__file__).resolve().parent.parent
AUDIT_PATH = ROOT / "logs" / "dashboard_audit.jsonl"
RESULTS_PATH = ROOT / "eval" / "results" / "results.json"

# Proposal section 4.4 / section 5: what each scenario demonstrates.
ATTACK_INFO = {
    "mitm_tampering": ("MITM message tampering", "AES-256-GCM tag verification"),
    "mitm_header_tampering": ("MITM header tampering", "Header authenticated as GCM associated data"),
    "mitm_key_substitution_client": ("MITM key substitution (client → gateway)", "Ed25519-signed ClientHello"),
    "mitm_key_substitution_gateway": ("MITM key substitution (gateway → client)", "Ed25519-signed ServerHello + pinned gateway key"),
    "replay_request": ("Replay attack", "Nonce uniqueness"),
    "delayed_request": ("Replay after a delay", "Timestamp freshness window"),
    "reordered_request": ("Out-of-order replay", "Sequence-number ordering"),
    "handshake_replay": ("Handshake replay", "HELLO nonce + timestamp check"),
    "impersonation": ("Client impersonation", "Ed25519 signature vs registered public key"),
    "session_hijack": ("Session hijacking", "Session ID useless without session keys"),
    "expired_session_reuse": ("Expired session reuse", "Session expiry"),
    "unauthorized_operation": ("Unauthorized operation", "Role-based access control"),
    "eavesdropping": ("Eavesdropping", "AES-256-GCM encryption"),
    "recorded_traffic_key_compromise": ("Long-term key compromise", "Forward secrecy (ephemeral X25519)"),
    "backend_bypass": ("Bypass the gateway", "Backend accepts only gateway-forwarded requests"),
}


def _hex(b: bytes, limit: int | None = None) -> str:
    h = b.hex()
    return h if limit is None or len(h) <= limit else h[:limit] + "…"


def _fingerprint(key: bytes) -> str:
    return crypto.sha256(key)[:8].hex()


def describe_request(frame: ProtectedRequest) -> dict:
    return {
        "session_id": _hex(frame.session_id),
        "seq": frame.seq,
        "nonce": _hex(frame.nonce),
        "timestamp": frame.timestamp,
        "ciphertext": _hex(frame.ciphertext[:-16], 96),
        "tag": _hex(frame.ciphertext[-16:]),
        "ciphertext_bytes": len(frame.ciphertext) - 16,
    }


class Dashboard:
    def __init__(self, audit_path: Path = AUDIT_PATH) -> None:
        self.audit_path = Path(audit_path)
        self._lock = threading.RLock()
        self._eval_lock = threading.Lock()
        self.last_evaluation: dict | None = None
        if RESULTS_PATH.exists():
            try:
                self.last_evaluation = json.loads(RESULTS_PATH.read_text())
            except (OSError, json.JSONDecodeError):
                pass
        self._start()

    # ------------------------------------------------------------ lifecycle

    def _start(self) -> None:
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        if self.audit_path.exists():
            self.audit_path.unlink()
        self.clock = OffsetClock()
        self.stack = start_stack(clock=self.clock, audit_path=self.audit_path)
        self.clients: dict[str, SecureClient] = {}
        self.last_frames: dict[str, ProtectedRequest] = {}

    def reset(self) -> dict:
        with self._lock:
            for c in self.clients.values():
                c.close()
            self.stack.stop()
            self._start()
            return self.state()

    def close(self) -> None:
        with self._lock:
            for c in self.clients.values():
                c.close()
            self.stack.stop()

    def _client(self, client_id: str) -> SecureClient:
        if client_id not in self.stack.identities.client_keys:
            raise ValueError(f"unknown demo client {client_id!r}")
        if client_id not in self.clients:
            ids = self.stack.identities
            self.clients[client_id] = SecureClient(
                self.stack.gateway_addr, client_id, ids.client_keys[client_id],
                ids.gateway_pin, clock=self.clock,
            ).connect()
        return self.clients[client_id]

    def _events_since(self, mark: int) -> list[dict]:
        return [self._event(i, e) for i, e in enumerate(self.stack.events.events[mark:], start=mark)]

    @staticmethod
    def _event(index: int, e) -> dict:
        d = e.to_dict()
        d["index"] = index
        d.pop("peer", None)
        return d

    # ------------------------------------------------------------ state

    def state(self) -> dict:
        with self._lock:
            gw = self.stack.gateway
            now = self.clock.now_ms()
            users = []
            for rec in sorted(self.stack.identities.registry.records(), key=lambda r: r.client_id):
                c = self.clients.get(rec.client_id)
                session = None
                if c and c.session:
                    live = gw.sessions.get(c.session.session_id)
                    session = {
                        "id": _hex(c.session.session_id),
                        "seq": c.seq,
                        "expires_in_ms": c.session.expires_at - now,
                        "live": live is not None and not live.is_expired(now),
                    }
                users.append({"id": rec.client_id, "role": rec.role, "session": session,
                              "has_last_request": rec.client_id in self.last_frames})
            accounts = [
                {"account": n, "balance": a.balance, "frozen": a.frozen}
                for n, a in sorted(self.stack.backend.service.accounts.items())
            ]
            chain = verify_chain(self.audit_path) if self.audit_path.exists() else None
            return {
                "users": users,
                "accounts": accounts,
                "policy": DEFAULT_POLICY,
                "stages": gw.pipeline.stage_names(),
                "settings": {"session_ttl_ms": gw.settings.session_ttl_ms,
                             "max_skew_ms": gw.settings.max_skew_ms},
                "clock_offset_ms": self.clock.offset_ms,
                "events": self._events_since(0)[-300:],
                "audit": {"entries": chain.entries if chain else 0, "ok": chain.ok if chain else True,
                          "problem": chain.problem if chain else ""},
                "has_evaluation": self.last_evaluation is not None,
            }

    # ------------------------------------------------------------ live gateway

    def handshake(self, client_id: str) -> dict:
        with self._lock:
            mark = len(self.stack.events.events)
            c = self._client(client_id)
            out: dict[str, Any] = {"client_id": client_id}
            try:
                result = c.handshake()
                out["ok"] = True
            except GatewayRejected as exc:
                out.update(ok=False, reason=exc.reason, detail=exc.detail)
                result = None
            h, r = c.last_hello, c.last_reply
            out["client_hello"] = {
                "client_id": h.client_id, "eph_pub": _hex(h.eph_pub), "nonce": _hex(h.nonce),
                "timestamp": h.timestamp, "signature": _hex(h.signature),
            }
            if result is not None:
                out["server_hello"] = {
                    "session_id": _hex(r.session_id), "eph_pub": _hex(r.eph_pub),
                    "nonce": _hex(r.nonce), "expires_at": r.expires_at, "signature": _hex(r.signature),
                }
                out["keys"] = {"c2g": _fingerprint(result.keys.c2g), "g2c": _fingerprint(result.keys.g2c)}
            self.last_frames.pop(client_id, None)
            out["events"] = self._events_since(mark)
            return out

    def _send(self, client_id: str, frame: ProtectedRequest, mark: int, note: str) -> dict:
        c = self._client(client_id)
        out: dict[str, Any] = {"client_id": client_id, "note": note, "frame": describe_request(frame)}
        try:
            out["response"] = c.parse_reply(c.send_raw(frame.encode()), frame)
            out["ok"] = True
        except GatewayRejected as exc:
            out.update(ok=False, reason=exc.reason, detail=exc.detail)
        out["events"] = self._events_since(mark)
        return out

    def request(self, client_id: str, op: str, params: dict) -> dict:
        with self._lock:
            mark = len(self.stack.events.events)
            c = self._client(client_id)
            handshake = None
            if c.session is None:
                handshake = self.handshake(client_id)
                if not handshake["ok"]:
                    return {**handshake, "events": self._events_since(mark)}
            frame = c.build_request(op, params)
            self.last_frames[client_id] = frame
            out = self._send(client_id, frame, mark, "legitimate request")
            out["operation"], out["params"] = op, params
            if handshake:
                out["handshake"] = handshake
            return out

    def replay_last(self, client_id: str) -> dict:
        """Resend the client's last request byte-for-byte (replay attack)."""
        with self._lock:
            frame = self.last_frames.get(client_id)
            if frame is None:
                raise ValueError("send a request first")
            mark = len(self.stack.events.events)
            return self._send(client_id, frame, mark, "replayed: identical bytes resent")

    def tamper_last(self, client_id: str) -> dict:
        """Flip one ciphertext bit of the last request and resend it (MITM tampering)."""
        with self._lock:
            frame = self.last_frames.get(client_id)
            if frame is None:
                raise ValueError("send a request first")
            ct = bytearray(frame.ciphertext)
            ct[len(ct) // 3] ^= 0x01
            tampered = replace(frame, ciphertext=bytes(ct))
            mark = len(self.stack.events.events)
            return self._send(client_id, tampered, mark, "tampered: one ciphertext bit flipped in transit")

    def advance_clock(self, ms: int) -> dict:
        with self._lock:
            self.clock.advance(int(ms))
            return self.state()

    # ------------------------------------------------------------ attacks & evaluation

    @staticmethod
    def attack_catalog() -> list[dict]:
        out = []
        for s in ALL_SCENARIOS:
            title, defence = ATTACK_INFO.get(s.__name__, (s.__name__, ""))
            out.append({"name": s.__name__, "title": title, "defence": defence,
                        "description": (s.__doc__ or "").strip().split("\n")[0]})
        return out

    def run_attack(self, name: str | None = None) -> list[dict]:
        names = [name] if name else None
        if name and name not in {s.__name__ for s in ALL_SCENARIOS}:
            raise ValueError(f"unknown scenario {name!r}")
        return [r.__dict__ for r in run_scenarios(names)]

    def evaluate(self, requests: int, clients: int) -> dict:
        if not self._eval_lock.acquire(blocking=False):
            raise RuntimeError("an evaluation is already running")
        try:
            results = run_evaluation(max(20, min(requests, 2000)), max(1, min(clients, 16)))
            RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
            RESULTS_PATH.write_text(json.dumps(results, indent=2))
            self.last_evaluation = results
            return results
        finally:
            self._eval_lock.release()
