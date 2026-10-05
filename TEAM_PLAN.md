# FlowState: Team Plan

**Project:** Secure Network Gateway Against MITM & Session Attacks (ACNS-DC 2026-27, CE305/CS305)
**Team:** FlowState, 10 members

This document defines **who is in charge of which files**, what each member's role covers, and the
**exact order** in which work is pushed. Every file in the repository belongs to exactly one member.

---

## 1. The push flow

Work is pushed in **strict order**, one member at a time. Member 1 pushes twice: first the
foundation everyone builds on, then the gateway that joins everyone's parts together.

**M1 → M2 → M3 → M4 → M5 → M6 → M7 → M8 → M1 → M9 → M10**

| Step | Member | Builds |
|---|---|---|
| 1 | **M1** | Foundation: core protocol, crypto, pipeline, project setup, docs |
| 2 | **M2** | Identity & authentication |
| 3 | **M3** | Secure handshake, key derivation, client |
| 4 | **M4** | Session manager |
| 5 | **M5** | Encryption (record layer) |
| 6 | **M6** | Replay & freshness detection |
| 7 | **M7** | Access control, bank server, client app |
| 8 | **M8** | Security audit log |
| 9 | **M1** | Gateway integration: joins steps 1–8 into the running gateway |
| 10 | **M9** | Attack simulation |
| 11 | **M10** | Evaluation, results & dashboard |

This order was checked by replaying it file by file in an empty folder: after every step, all the
tests that exist at that point pass, and after step 11 the full project works (15/15 attacks blocked).

---

## 2. Who is in charge of which files

### Step 1: Member 1, push 1 (foundation): 23 files
```
pyproject.toml
.gitignore
README.md
TEAM_PLAN.md
config/gateway.toml
docs/protocol-spec.md
docs/architecture.md
docs/threat-model.md
src/flowstate/__init__.py
src/flowstate/core/__init__.py
src/flowstate/core/reasons.py
src/flowstate/core/clock.py
src/flowstate/core/config.py
src/flowstate/core/crypto.py
src/flowstate/core/codec.py
src/flowstate/core/messages.py
src/flowstate/core/pipeline.py
src/flowstate/core/events.py
tests/conftest.py
tests/core/test_crypto_vectors.py
tests/core/test_codec_messages.py
tests/core/test_pipeline.py
tests/core/test_config.py
```

### Step 2: Member 2 (identity): 7 files
```
src/flowstate/identity/__init__.py
src/flowstate/identity/keys.py
src/flowstate/identity/registry.py
src/flowstate/identity/auth.py
src/flowstate/identity/cli.py
keys/.gitkeep
tests/identity/test_identity.py
```

### Step 3: Member 3 (handshake + client): 6 files
```
src/flowstate/handshake/__init__.py
src/flowstate/handshake/keyschedule.py
src/flowstate/handshake/protocol.py
src/flowstate/client/__init__.py
src/flowstate/client/client.py
tests/handshake/test_handshake.py
```

### Step 4: Member 4 (session): 4 files
```
src/flowstate/session/__init__.py
src/flowstate/session/manager.py
src/flowstate/session/stage.py
tests/session/test_session.py
```

### Step 5: Member 5 (record layer): 4 files
```
src/flowstate/record/__init__.py
src/flowstate/record/layer.py
src/flowstate/record/stage.py
tests/record/test_record.py
```

### Step 6: Member 6 (replay): 3 files
```
src/flowstate/replay/__init__.py
src/flowstate/replay/detector.py
tests/replay/test_replay.py
```

### Step 7: Member 7 (access control + backend + client CLI): 11 files
```
src/flowstate/authz/__init__.py
src/flowstate/authz/policy.py
src/flowstate/authz/stage.py
src/flowstate/backend/__init__.py
src/flowstate/backend/service.py
src/flowstate/backend/server.py
src/flowstate/backend/__main__.py
src/flowstate/client/cli.py
config/policy.toml
tests/authz/test_authz.py
tests/backend/test_backend.py
```

### Step 8: Member 8 (audit log): 4 files
```
src/flowstate/audit/__init__.py
src/flowstate/audit/logger.py
src/flowstate/audit/cli.py
tests/audit/test_audit.py
```

### Step 9: Member 1, push 2 (gateway integration): 8 files
```
src/flowstate/gateway/__init__.py
src/flowstate/gateway/server.py
src/flowstate/gateway/runtime.py
src/flowstate/gateway/__main__.py
tests/core/test_architecture.py
tests/gateway/test_gateway_e2e.py
tests/client/test_client.py
.github/workflows/ci.yml
```

### Step 10: Member 9 (attacks): 5 files
```
attacks/__init__.py
attacks/proxy.py
attacks/scenarios.py
attacks/runner.py
tests/attacks/test_attack_scenarios.py
```

### Step 11: Member 10 (evaluation + dashboard): 13 files
```
eval/__init__.py
eval/baseline.py
eval/benchmark.py
eval/report.py
dashboard/__init__.py
dashboard/__main__.py
dashboard/app.py
dashboard/static/index.html
dashboard/static/style.css
dashboard/static/app.js
docs/results.md
tests/eval/test_evaluation.py
tests/dashboard/test_dashboard.py
```

**Total: 88 files (including this plan).**

---

## 3. Role of each member

### Member 1: Protocol foundation & gateway core
Defines the rules every other component follows, and later joins all the parts into one gateway.
- **Protocol specification:** the exact format of every message (ClientHello, ServerHello, protected
  request/response, error) and the encoding used for anything signed or authenticated.
- **Crypto module (`core/crypto.py`):** the only file allowed to use the `cryptography` library
  (Ed25519, X25519, HKDF-SHA256, AES-256-GCM, random bytes, constant-time compare).
- **Codec & messages:** strict encoding/decoding; malformed input → `MALFORMED_FRAME`.
- **Validation pipeline (`core/pipeline.py`):** runs the checks in order, stops at the first
  failure, and saves state changes **only if every check passes**.
- **Reason codes, events, clock, config, shared test fixtures.**
- **Gateway (push 2):** network server, handshake/request routing, forwarding to the backend, and
  plugging in the checks built by Members 4–7; end-to-end tests and CI.
- **Docs:** README, protocol spec, architecture, threat model.

### Member 2: Identity & authentication
Decides *who is who*.
- The client generates its own Ed25519 key pair; the gateway registers only the public key + role.
- Gateway key pair; the gateway's public key is pinned on every client.
- Client registry (load, save, register, revoke).
- Checks the ClientHello signature at login → `INVALID_SIGNATURE` (unknown clients get the same code).
- `flowstate-keys` tool: `keygen`, `register`, `init-gateway`, `bootstrap`.

### Member 3: Secure handshake, key derivation & the client
The secure login, and the client program that uses it.
- Signed exchange of temporary X25519 keys and nonces; the gateway's signature also covers the
  client's hello; the client checks it against the pinned gateway key.
- HKDF-SHA256 (salt = both nonces) creates two separate keys: client→gateway and gateway→client.
- Rejects stale (`STALE_REQUEST`) and replayed (`DUPLICATE_NONCE`) logins.
- **Client (`client/client.py`):** connects, runs the handshake, sends encrypted requests and
  verifies replies. It uses Member 5's encryption code, so it runs fully once step 5 is pushed.

### Member 4: Session manager
Keeps track of logged-in sessions.
- Stores client, role, keys, expiry and last sequence number for each session.
- Pipeline **step 1**: session lookup + expiry → `EXPIRED_SESSION`.
- Per-session request limit, cleanup of expired sessions and their keys, safe concurrent access.

### Member 5: Protected record layer (encryption)
Locks every message.
- AES-256-GCM encryption with a fresh 96-bit nonce per message; the header (session ID,
  sequence number, nonce, timestamp) is sealed as authenticated data.
- Pipeline **step 2**: decrypt + tag check → `MODIFIED_MESSAGE` (any changed bit is caught).
- Replies encrypted with the gateway→client key and checked by the client.

### Member 6: Replay & freshness detection
Catches copied, delayed and reordered messages.
- Pipeline **step 3**: per-session nonce memory (`DUPLICATE_NONCE`) and strictly increasing
  sequence numbers (`STALE_REQUEST`).
- Pipeline **step 4**: timestamp freshness window (`STALE_REQUEST`).
- State is saved only after the whole pipeline passes; memory use is bounded.

### Member 7: Access control, bank server & client app
Decides *what each role may do*, and provides the application being protected.
- Role-based permissions (`config/policy.toml`), deny by default.
- Pipeline **step 5**: role vs operation → `UNAUTHORIZED_OPERATION`.
- Bank server (balance, transfer, admin operations) that accepts only gateway-forwarded requests.
- `flowstate-client` command-line app.

### Member 8: Security event logging & audit
The tamper-evident logbook.
- One entry per decision: time, client, session, operation, reason code (never keys or contents).
- SHA-256 hash chain: any edit, deletion or reordering is detected.
- `flowstate-audit` tool: `verify`, `summary`, `show`.

### Member 9: Attack simulation
Plays the attacker.
- Man-in-the-middle proxy that records and rewrites traffic.
- 15 attacks: payload & header tampering, key substitution (both directions), replay, delayed and
  reordered delivery, handshake replay, impersonation, session hijacking, expired-session reuse,
  unauthorized operation, eavesdropping, long-term key compromise, gateway bypass.
- Each attack checks the expected reason code **and** that normal users still work.

### Member 10: Evaluation, results & dashboard
Proves it works, and presents it.
- Plain forwarding baseline, showing the same attacks succeed without the gateway.
- Proposal §4.4 metrics: attack-blocking rate, fake-login and replay detection rates, latency,
  encryption overhead, throughput; generates `docs/results.md`.
- Web dashboard: overview, live gateway, animated attack lab, security log, evaluation.

---

## 4. How to do your push

1. **Wait** until the member before you says they've pushed.
2. `git pull` to get everything pushed so far.
3. Add **only your files** (listed in section 2). Don't change anyone else's files; if you need a
   change in one, ask its owner.
4. **Test before pushing:**
   ```bash
   pip install -e ".[dev]"
   pytest
   ```
   Everything that exists so far must pass.
5. Commit with a message saying what you built, then push:
   ```bash
   git add <your files>
   git commit -m "Add replay detector and freshness check"
   git push
   ```
6. Tell the next member it's their turn.

## 5. Things to expect

- **Steps 3–4:** `client/client.py` is pushed in step 3 but can only run once Member 5's
  encryption code arrives in step 5. Nothing fails in between; the client just isn't usable yet.
- **Steps 9–10:** the GitHub CI check shows **red** after step 9, because it also runs the attack
  suite and benchmark, which arrive in steps 10 and 11. It turns green after step 11.
- **After step 11** the project is complete:
  ```bash
  pytest                      # all tests
  python -m attacks.runner    # 15/15 attacks blocked
  python -m dashboard         # http://localhost:8080
  ```

## 6. Definition of done (every member)

- All your files are pushed.
- `pytest` passes, and nobody else's tests broke.
- You can explain your part: what it does, which attack it stops, and which reason code it produces.
