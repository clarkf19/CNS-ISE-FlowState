"""Attack scenarios, one per row of the proposal's section 4.4 table (plus extras).

Every scenario runs a real attack against a running gateway over TCP and
reports the reason code the defence produced. A scenario is BLOCKED only if
the expected reason code was produced *and* the attack had no effect on the
backend (e.g. no money moved).
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, replace
from typing import Callable

from attacks.proxy import MitmProxy
from flowstate.client import GatewayRejected, SecureClient
from flowstate.core import crypto
from flowstate.core.clock import OffsetClock
from flowstate.core.codec import recv_frame, send_frame
from flowstate.core.messages import (
    ClientHello,
    ErrorFrame,
    ProtectedRequest,
    ServerHello,
    decode_message,
)
from flowstate.gateway.runtime import Stack
from flowstate.record.layer import encode_payload, seal_request


@dataclass
class ScenarioResult:
    name: str
    attack: str
    expected: str
    observed: str
    blocked: bool
    legit_ok: bool = True
    detail: str = ""


class Attack:
    """Shared helpers for scenarios."""

    def __init__(self, stack: Stack, clock: OffsetClock) -> None:
        self.stack = stack
        self.clock = clock

    def client(self, client_id: str, address: tuple[str, int] | None = None) -> SecureClient:
        ids = self.stack.identities
        return SecureClient(
            address or self.stack.gateway_addr, client_id,
            ids.client_keys[client_id], ids.gateway_pin, clock=self.clock,
        )

    def balance(self, account: str) -> int:
        return self.stack.backend.service.accounts[account].balance

    def mark(self) -> int:
        return len(self.stack.events.events)

    def reasons_since(self, mark: int) -> list[str]:
        return [e.reason.value for e in self.stack.events.events[mark:]]

    def raw_send(self, payload: bytes) -> object:
        """Send one message on a fresh attacker connection and decode the reply."""
        with socket.create_connection(self.stack.gateway_addr, timeout=5) as sock:
            send_frame(sock, payload)
            return decode_message(recv_frame(sock))

    @staticmethod
    def reply_reason(reply: object) -> str:
        return reply.reason if isinstance(reply, ErrorFrame) else "ACCEPTED"

    def legit_still_works(self) -> bool:
        try:
            with self.client("bob") as c:
                return c.request("balance")["status"] == "ok"
        except (GatewayRejected, OSError):
            return False


# ---------------------------------------------------------------- scenarios


def mitm_tampering(a: Attack) -> ScenarioResult:
    """Attacker flips ciphertext bits to turn 'amount 1000' into 'amount 9000'.

    AES-GCM uses counter mode, so without the tag this edit would decrypt
    cleanly to the attacker's chosen amount. The tag check catches it.
    """
    known = encode_payload({"op": "transfer", "params": {"amount": 1000, "to": "bob"}})
    pos = known.index(b"1000")

    def tamper(raw: bytes) -> bytes:
        msg = decode_message(raw)
        if isinstance(msg, ProtectedRequest):
            ct = bytearray(msg.ciphertext)
            ct[pos] ^= ord("1") ^ ord("9")
            return replace(msg, ciphertext=bytes(ct)).encode()
        return raw

    bob_before, m = a.balance("bob"), a.mark()
    with MitmProxy(a.stack.gateway_addr, on_client_frame=tamper) as proxy:
        try:
            with a.client("alice", proxy.address) as c:
                c.request("transfer", to="bob", amount=1000)
            observed = "ACCEPTED"
        except GatewayRejected as exc:
            observed = exc.reason
    moved = a.balance("bob") - bob_before
    return ScenarioResult(
        "mitm_tampering", "Modify encrypted payload in transit (1,000 -> 9,000)",
        "MODIFIED_MESSAGE", observed,
        observed == "MODIFIED_MESSAGE" and moved == 0 and "MODIFIED_MESSAGE" in a.reasons_since(m),
        a.legit_still_works(), f"money moved: {moved}",
    )


def mitm_header_tampering(a: Attack) -> ScenarioResult:
    """Attacker changes the unencrypted sequence number in the header (covered as AAD)."""

    def tamper(raw: bytes) -> bytes:
        msg = decode_message(raw)
        return replace(msg, seq=msg.seq + 7).encode() if isinstance(msg, ProtectedRequest) else raw

    with MitmProxy(a.stack.gateway_addr, on_client_frame=tamper) as proxy:
        try:
            with a.client("alice", proxy.address) as c:
                c.request("balance")
            observed = "ACCEPTED"
        except GatewayRejected as exc:
            observed = exc.reason
    return ScenarioResult(
        "mitm_header_tampering", "Modify authenticated header field (sequence number)",
        "MODIFIED_MESSAGE", observed, observed == "MODIFIED_MESSAGE", a.legit_still_works(),
    )


def mitm_key_substitution_client(a: Attack) -> ScenarioResult:
    """Attacker swaps the client's ephemeral X25519 key in the ClientHello for their own."""
    attacker_eph = crypto.EphemeralKeyPair()

    def swap(raw: bytes) -> bytes:
        msg = decode_message(raw)
        if isinstance(msg, ClientHello):
            return replace(msg, eph_pub=attacker_eph.public_bytes()).encode()
        return raw

    m = a.mark()
    with MitmProxy(a.stack.gateway_addr, on_client_frame=swap) as proxy:
        try:
            with a.client("alice", proxy.address) as c:
                c.handshake()
            observed = "ACCEPTED"
        except GatewayRejected as exc:
            observed = exc.reason
    return ScenarioResult(
        "mitm_key_substitution_client", "Replace client ephemeral key during handshake",
        "INVALID_SIGNATURE", observed,
        observed == "INVALID_SIGNATURE" and "INVALID_SIGNATURE" in a.reasons_since(m),
        a.legit_still_works(), "gateway rejects: client signature covers eph key",
    )


def mitm_key_substitution_gateway(a: Attack) -> ScenarioResult:
    """Attacker swaps the gateway's ephemeral key in the ServerHello for their own."""
    attacker_eph = crypto.EphemeralKeyPair()

    def swap(raw: bytes) -> bytes:
        msg = decode_message(raw)
        if isinstance(msg, ServerHello):
            return replace(msg, eph_pub=attacker_eph.public_bytes()).encode()
        return raw

    with MitmProxy(a.stack.gateway_addr, on_server_frame=swap) as proxy:
        try:
            with a.client("alice", proxy.address) as c:
                c.handshake()
            observed = "ACCEPTED"
        except GatewayRejected as exc:
            observed = exc.reason
    return ScenarioResult(
        "mitm_key_substitution_gateway", "Replace gateway ephemeral key during handshake",
        "INVALID_SIGNATURE", observed, observed == "INVALID_SIGNATURE", a.legit_still_works(),
        "client rejects: pinned gateway key does not verify",
    )


def replay_request(a: Attack) -> ScenarioResult:
    """Attacker captures a valid transfer and resends it on a new connection."""
    with MitmProxy(a.stack.gateway_addr) as proxy:
        with a.client("alice", proxy.address) as c:
            c.request("transfer", to="bob", amount=100)
        captured = next(f for f in proxy.client_frames if isinstance(decode_message(f), ProtectedRequest))
    bob_before, m = a.balance("bob"), a.mark()
    observed = a.reply_reason(a.raw_send(captured))
    return ScenarioResult(
        "replay_request", "Resend a captured valid transfer",
        "DUPLICATE_NONCE", observed,
        observed == "DUPLICATE_NONCE" and a.balance("bob") == bob_before
        and "DUPLICATE_NONCE" in a.reasons_since(m),
        a.legit_still_works(), "transfer executed once only",
    )


def delayed_request(a: Attack) -> ScenarioResult:
    """Attacker withholds a request and releases it minutes later."""
    with a.client("alice") as c:
        c.handshake()
        held = c.build_request("transfer", {"to": "bob", "amount": 50})
    bob_before = a.balance("bob")
    a.clock.advance(120_000)  # two minutes pass (session itself still valid)
    observed = a.reply_reason(a.raw_send(held.encode()))
    return ScenarioResult(
        "delayed_request", "Hold a request and release it 2 minutes later",
        "STALE_REQUEST", observed, observed == "STALE_REQUEST" and a.balance("bob") == bob_before,
        a.legit_still_works(), "timestamp outside freshness window",
    )


def reordered_request(a: Attack) -> ScenarioResult:
    """Attacker delays request #1 until after request #2 has been accepted."""
    with a.client("alice") as c:
        c.handshake()
        first = c.build_request("balance")
        second = c.build_request("balance")
        c.send_request(second)
        observed = a.reply_reason(a.raw_send(first.encode()))
    return ScenarioResult(
        "reordered_request", "Deliver an older sequence number after a newer one",
        "STALE_REQUEST", observed, observed == "STALE_REQUEST", a.legit_still_works(),
    )


def handshake_replay(a: Attack) -> ScenarioResult:
    """Attacker replays a captured ClientHello to open a session as alice."""
    with MitmProxy(a.stack.gateway_addr) as proxy:
        with a.client("alice", proxy.address) as c:
            c.handshake()
        hello = proxy.client_frames[0]
    observed = a.reply_reason(a.raw_send(hello))
    return ScenarioResult(
        "handshake_replay", "Replay a captured ClientHello",
        "DUPLICATE_NONCE", observed, observed == "DUPLICATE_NONCE", a.legit_still_works(),
    )


def impersonation(a: Attack) -> ScenarioResult:
    """Attacker claims to be alice but signs with their own key."""
    mallory = crypto.SigningKey.generate()
    forged = SecureClient(
        a.stack.gateway_addr, "alice", mallory, a.stack.identities.gateway_pin, clock=a.clock
    )
    m = a.mark()
    try:
        with forged:
            forged.handshake()
        observed = "ACCEPTED"
    except GatewayRejected as exc:
        observed = exc.reason
    return ScenarioResult(
        "impersonation", "Handshake as 'alice' with a forged signature",
        "INVALID_SIGNATURE", observed,
        observed == "INVALID_SIGNATURE" and "INVALID_SIGNATURE" in a.reasons_since(m),
        a.legit_still_works(),
    )


def session_hijack(a: Attack) -> ScenarioResult:
    """Attacker sniffs alice's session ID and sends requests under it without the keys."""
    with MitmProxy(a.stack.gateway_addr) as proxy:
        c = a.client("alice", proxy.address).connect()
        c.request("balance")
        sniffed = next(
            decode_message(f) for f in proxy.client_frames
            if isinstance(decode_message(f), ProtectedRequest)
        )
        forged = seal_request(
            crypto.AeadKey(crypto.random_bytes(32)), sniffed.session_id, sniffed.seq + 1,
            a.clock.now_ms(), "transfer", {"to": "carol", "amount": 4000},
        )
        bob_before, carol_before = a.balance("bob"), a.balance("carol")
        observed = a.reply_reason(a.raw_send(forged.encode()))
        still_ok = c.request("balance")["status"] == "ok"  # victim session unaffected
        c.close()
    return ScenarioResult(
        "session_hijack", "Reuse a sniffed session ID without the session keys",
        "MODIFIED_MESSAGE", observed,
        observed == "MODIFIED_MESSAGE" and a.balance("carol") == carol_before
        and a.balance("bob") == bob_before,
        still_ok and a.legit_still_works(), "victim's session kept working",
    )


def expired_session_reuse(a: Attack) -> ScenarioResult:
    """A captured session is used after it expired."""
    with a.client("alice") as c:
        c.request("balance")
        ttl = a.stack.gateway.settings.session_ttl_ms
        a.clock.advance(ttl + 1_000)
        try:
            c.request("balance")
            observed = "ACCEPTED"
        except GatewayRejected as exc:
            observed = exc.reason
    return ScenarioResult(
        "expired_session_reuse", "Send a request on an expired session",
        "EXPIRED_SESSION", observed, observed == "EXPIRED_SESSION", a.legit_still_works(),
    )


def unauthorized_operation(a: Attack) -> ScenarioResult:
    """Authenticated customer calls an admin-only operation."""
    try:
        with a.client("alice") as c:
            c.request("freeze_account", account="bob")
        observed = "ACCEPTED"
    except GatewayRejected as exc:
        observed = exc.reason
    frozen = a.stack.backend.service.accounts["bob"].frozen
    return ScenarioResult(
        "unauthorized_operation", "Customer calls admin-only freeze_account",
        "UNAUTHORIZED_OPERATION", observed,
        observed == "UNAUTHORIZED_OPERATION" and not frozen, a.legit_still_works(),
    )


def eavesdropping(a: Attack) -> ScenarioResult:
    """Passive attacker records all traffic and searches it for request contents."""
    secrets = [b"transfer", b"amount", b"carol", b"777", b"balance"]
    with MitmProxy(a.stack.gateway_addr) as proxy:
        with a.client("alice", proxy.address) as c:
            c.request("transfer", to="carol", amount=777)
    traffic = [
        f for f in proxy.client_frames + proxy.server_frames
        if not isinstance(decode_message(f), (ClientHello, ServerHello))
    ]
    leaked = [s.decode() for s in secrets if any(s in f for f in traffic)]
    return ScenarioResult(
        "eavesdropping", "Passively capture request and response traffic",
        "NO_PLAINTEXT", "LEAKED " + ",".join(leaked) if leaked else "NO_PLAINTEXT",
        not leaked, a.legit_still_works(), f"{len(traffic)} protected frames inspected",
    )


def recorded_traffic_key_compromise(a: Attack) -> ScenarioResult:
    """Forward secrecy (proposal section 4.3(c)).

    The attacker records a full session, then later steals BOTH long-term
    private keys (alice's and the gateway's). The stolen keys are real: they
    let the attacker open new sessions as alice. But the recorded session was
    keyed from ephemeral X25519 secrets that were destroyed after the
    handshake, so the recording still cannot be decrypted.
    """
    from flowstate.handshake.keyschedule import derive_session_keys
    from flowstate.record.layer import open_request

    with MitmProxy(a.stack.gateway_addr) as proxy:
        with a.client("alice", proxy.address) as c:
            c.request("transfer", to="bob", amount=250)
        frames = [decode_message(f) for f in proxy.client_frames + proxy.server_frames]
    hello = next(f for f in frames if isinstance(f, ClientHello))
    reply = next(f for f in frames if isinstance(f, ServerHello))
    recorded = next(f for f in frames if isinstance(f, ProtectedRequest))

    # --- later: long-term keys are compromised -------------------------------
    stolen_client = a.stack.identities.client_keys["alice"]
    stolen_gateway = a.stack.identities.gateway_key
    thief = SecureClient(a.stack.gateway_addr, "alice", stolen_client,
                         a.stack.identities.gateway_pin, clock=a.clock)
    try:
        with thief:
            thief.handshake()
        compromise_real = True
    except GatewayRejected:
        compromise_real = False

    # Every key the attacker can now compute from what they hold.
    candidate_secrets = []
    for long_term in (stolen_client, stolen_gateway):
        for peer_eph in (hello.eph_pub, reply.eph_pub):
            try:
                pair = crypto.EphemeralKeyPair.from_private_bytes(long_term.private_bytes())
                candidate_secrets.append(pair.exchange(peer_eph))
            except crypto.CryptoError:
                pass
    candidate_keys = [
        derive_session_keys(s, hello.nonce, reply.nonce, reply.session_id).c2g
        for s in candidate_secrets
    ] + ([thief._c2g] if thief._c2g else [])

    decrypted = 0
    for key in candidate_keys:
        aead = key if isinstance(key, crypto.AeadKey) else crypto.AeadKey(key)
        try:
            open_request(aead, recorded)
            decrypted += 1
        except Exception:
            pass
    observed = "DECRYPTED" if decrypted else "NO_DECRYPTION"
    return ScenarioResult(
        "recorded_traffic_key_compromise",
        "Steal both long-term keys, then decrypt a recorded session",
        "NO_DECRYPTION", observed, compromise_real and not decrypted, a.legit_still_works(),
        f"stolen keys opened a new session: {compromise_real}; "
        f"{len(candidate_keys)} candidate keys tried on the recording",
    )


def backend_bypass(a: Attack) -> ScenarioResult:
    """Attacker skips the gateway and calls the backend directly."""
    import json

    with socket.create_connection(a.stack.backend_addr, timeout=5) as sock:
        body = {"token": "00" * 32, "client_id": "alice", "role": "admin",
                "op": "transfer", "params": {"to": "carol", "amount": 1}}
        send_frame(sock, json.dumps(body).encode())
        reply = json.loads(recv_frame(sock))
    blocked = reply.get("status") == "error" and "forbidden" in reply.get("error", "")
    return ScenarioResult(
        "backend_bypass", "Call the backend directly, bypassing the gateway",
        "FORBIDDEN", "FORBIDDEN" if blocked else "EXECUTED", blocked, a.legit_still_works(),
    )


ALL_SCENARIOS: list[Callable[[Attack], ScenarioResult]] = [
    mitm_tampering,
    mitm_header_tampering,
    mitm_key_substitution_client,
    mitm_key_substitution_gateway,
    replay_request,
    delayed_request,
    reordered_request,
    handshake_replay,
    impersonation,
    session_hijack,
    expired_session_reuse,
    unauthorized_operation,
    eavesdropping,
    recorded_traffic_key_compromise,
    backend_bypass,
]
