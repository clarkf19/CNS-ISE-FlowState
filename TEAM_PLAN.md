# FlowState: Team Plan

**Project:** Secure Network Gateway Against MITM & Session Attacks (ACNS-DC 2026-27, CE305/CS305)
**Team:** FlowState, 10 members

This document defines each member's **scope**: the part of the system they own, build, test and must
be able to explain. It also defines the **order** in which work is pushed. The folder structure is
fixed (see the [README](README.md)), and every file belongs to exactly one owner.

---

## 1. Ownership at a glance

| Member | Area | Owns |
|---|---|---|
| **M1** | Protocol foundation & gateway core | `src/flowstate/core/`, `src/flowstate/gateway/`, `src/flowstate/__init__.py`, `client/__init__.py` + `client/client.py` skeleton, `pyproject.toml`, `.gitignore`, `.github/workflows/ci.yml`, `config/gateway.toml`, `README.md`, `docs/protocol-spec.md`, `docs/architecture.md`, `docs/threat-model.md`, `tests/conftest.py`, `tests/core/`, `tests/gateway/` |
| **M2** | Identity & authentication | `src/flowstate/identity/`, `keys/.gitkeep`, signing in `client/client.py`, `tests/identity/` |
| **M3** | Authenticated handshake & key derivation | `src/flowstate/handshake/`, handshake in `client/client.py`, `tests/handshake/` |
| **M4** | Session manager | `src/flowstate/session/`, `tests/session/` |
| **M5** | Protected record layer (AES-256-GCM) | `src/flowstate/record/`, request/response encryption in `client/client.py`, `tests/record/` |
| **M6** | Replay & freshness detection | `src/flowstate/replay/`, `tests/replay/` |
| **M7** | Access control, backend & client CLI | `src/flowstate/authz/`, `src/flowstate/backend/`, `src/flowstate/client/cli.py`, `config/policy.toml`, `tests/authz/`, `tests/backend/`, `tests/client/` |
| **M8** | Security event logging & audit | `src/flowstate/audit/`, `tests/audit/` |
| **M9** | Attack simulation | `attacks/`, `tests/attacks/` |
| **M10** | Evaluation, results & dashboard | `eval/`, `dashboard/`, `docs/results.md`, `tests/eval/`, `tests/dashboard/` |

---

## 2. Scope of each member

### M1: Protocol foundation & gateway core
**Role:** defines the rules every other component follows, and the engine that enforces them.
- **Protocol specification:** the exact byte format of every message (ClientHello, ServerHello,
  protected request/response, error) and the canonical encoding used for anything signed or
  authenticated.
- **Crypto facade (`core/crypto.py`):** the only module that touches the `cryptography` library
  (Ed25519, X25519, HKDF-SHA256, AES-256-GCM, random bytes, constant-time compare).
- **Codec & messages:** encoding/decoding with strict length checks; malformed input becomes
  `MALFORMED_FRAME`.
- **Validation pipeline (`core/pipeline.py`):** runs the checks in the fixed order, stops at the first
  failure, and applies state changes **only if every check passes**.
- **Reason codes, events, clock, config:** shared vocabulary and test helpers.
- **Gateway server (`gateway/`):** network server, handshake/request routing, forwarding to the
  backend; at the end, wires in the stages built by M4–M7.
- **Project setup:** packaging, CI, README and the architecture, protocol and threat-model docs.
- **Tests:** official test vectors for every primitive (RFC 8032, RFC 7748, RFC 5869, SP 800-38D),
  codec fuzzing, pipeline order/commit rules, the architecture rule, end-to-end tests.

### M2: Identity & authentication
**Role:** decides *who is who*.
- The client generates its own Ed25519 key pair; the gateway registers only the public key + role.
- Gateway key pair; the gateway public key is pinned on every client.
- Client registry (load, save, register, revoke).
- Authentication module: verifies the ClientHello signature, rejecting with `INVALID_SIGNATURE`
  (unknown clients get the same code).
- `flowstate-keys` CLI: `keygen`, `register`, `init-gateway`, `bootstrap`.
- **Tests:** valid/forged signatures, every signed field, registry, key files, CLI flow.

### M3: Authenticated handshake & key derivation
**Role:** the secure login.
- HELLO → reply exchange of signed ephemeral X25519 keys and nonces (both sides).
- The gateway signature covers the client's hello (transcript binding); the client verifies it
  against the pinned key.
- HKDF-SHA256 (salt = both nonces, context labels) produces separate client→gateway and
  gateway→client keys.
- Rejects stale (`STALE_REQUEST`) and replayed (`DUPLICATE_NONCE`) hellos.
- **Tests:** both sides derive identical keys, key substitution, wrong pin, transcript binding,
  forward secrecy (ephemeral secrets destroyed).

### M4: Session manager
**Role:** keeps track of logged-in sessions.
- Stores client, role, keys, expiry, last sequence number per session.
- Pipeline **step 1**: session lookup + expiry → `EXPIRED_SESSION`.
- Per-session request limit, cleanup of expired sessions, key destruction, thread safety.
- **Tests:** create/lookup/expire, unknown session, capacity, concurrency, request limit.

### M5: Protected record layer
**Role:** locks every message.
- Client: AES-256-GCM encryption of each request with a fresh 96-bit nonce; the header
  (session ID, sequence number, nonce, timestamp) is authenticated data.
- Pipeline **step 2**: decrypt + tag check → `MODIFIED_MESSAGE`.
- Responses encrypted with the gateway→client key and verified by the client.
- **Tests:** round trips, every field tampered, wrong-direction key, no plaintext on the wire.

### M6: Replay & freshness detection
**Role:** catches copied, delayed and reordered messages.
- Pipeline **step 3**: per-session nonce cache (`DUPLICATE_NONCE`) + strictly increasing sequence
  numbers (`STALE_REQUEST`).
- Pipeline **step 4**: timestamp freshness window (`STALE_REQUEST`).
- State recorded only after the whole pipeline passes; bounded memory.
- **Tests:** replays, old sequence numbers, window edges, rejected requests don't consume nonces.

### M7: Access control, backend & client CLI
**Role:** decides *what each role may do*, and provides the application being protected.
- RBAC policy (`config/policy.toml`), deny by default.
- Pipeline **step 5**: role vs operation → `UNAUTHORIZED_OPERATION`.
- Backend transaction service (balance, transfer, admin operations) that accepts only
  gateway-forwarded requests (shared token).
- `flowstate-client` command-line app.
- **Tests:** role × operation matrix, invalid transfers, direct-access refusal, client behaviour.

### M8: Security event logging & audit
**Role:** the tamper-evident logbook.
- One log entry per decision: time, client, session, operation, reason code (never secrets).
- SHA-256 hash chain so edits, deletions and reordering are detected.
- `flowstate-audit` CLI: `verify`, `summary`, `show`.
- **Tests:** every reason code logged, tamper detection, restart continuity, no secrets.

### M9: Attack simulation
**Role:** the attacker.
- Man-in-the-middle TCP proxy that records and rewrites traffic.
- 15 scenarios: tampering (payload, header), key substitution (both directions), replay,
  delayed and reordered delivery, handshake replay, impersonation, session hijacking,
  expired-session reuse, unauthorized operation, eavesdropping, long-term key compromise,
  gateway bypass.
- Each scenario asserts the expected reason code **and** that legitimate traffic still works.
- **Tests:** every scenario blocked; every attack in proposal §4.4 covered.

### M10: Evaluation, results & dashboard
**Role:** proves it works, and presents it.
- Plain forwarding baseline for comparison, showing the same attacks succeed without the gateway.
- Metrics from proposal §4.4: attack-blocking rate, authentication-failure and replay detection
  rates, latency, encryption overhead, throughput.
- `docs/results.md` report generation.
- Web dashboard: overview, live gateway, animated attack lab, security log, evaluation.
- **Tests:** metric calculations, small benchmark run, dashboard API.

---

## 3. Push order

Code imports code, so some parts must exist before others can be built.

```
           ┌──────────────── M1  core (first) ────────────────┐
           │                                                   │
   M2 identity → M3 handshake → M4 session        M5 record · M6 replay · M7 authz/backend · M8 audit
           │                                                   │        (in parallel, any order)
           └──────────────────────┬────────────────────────────┘
                                  ▼
                     M1  gateway integration
                                  ▼
                           M9  attacks
                                  ▼
                     M10  evaluation + dashboard (last)
```

| Step | Member | Pushes | Can start when |
|---|---|---|---|
| 1 | **M1** | `core/`, project setup, docs, `tests/core/`, `tests/conftest.py`, `client/` skeleton | — |
| 2 | **M2** | `identity/`, `keys/.gitkeep`, `tests/identity/` | step 1 is on `main` |
| 3 | **M3** | `handshake/`, `tests/handshake/` | step 2 is on `main` |
| 4 | **M4** | `session/`, `tests/session/` | step 3 is on `main` |
| 4 (parallel) | **M5** | `record/`, `tests/record/` | step 1 is on `main` |
| 4 (parallel) | **M6** | `replay/`, `tests/replay/` | step 1 is on `main` |
| 4 (parallel) | **M7** | `authz/`, `backend/`, `client/cli.py`, `config/policy.toml`, tests | step 1 is on `main` |
| 4 (parallel) | **M8** | `audit/`, `tests/audit/` | step 1 is on `main` |
| 5 | **M1** | `gateway/` (wires steps 2–8 together), `tests/gateway/` | steps 2–8 are on `main` |
| 6 | **M9** | `attacks/`, `tests/attacks/` | step 5 is on `main` |
| 7 | **M10** | `eval/`, `dashboard/`, `docs/results.md`, tests | step 6 is on `main` |

A strict M1 → M10 order also works; it's simpler but slower.

---

## 4. Rules for every push

1. `git pull` before starting, so you build on everyone's latest work.
2. Change **only the files you own**. If you need something changed in another member's file, ask them.
3. Run your own tests before pushing: `pytest tests/<your-folder>`. From step 5 onwards, run the full `pytest`.
4. Commit with a clear message describing what you built, e.g. `Add replay detector and freshness stage`.
5. Push, then tell the next member they can start.

## 5. Definition of done (per member)

- Your files are complete and pushed.
- Your tests pass, and nobody else's tests broke.
- You can explain your part: what it does, which attack it stops, and which reason code it produces.
