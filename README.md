# FlowState — Secure Network Gateway Against MITM & Session Attacks

ACNS-DC 2026-27 · Cryptography and Network Security (CE305/CS305) · Sardar Patel Institute of Technology

A gateway that sits between clients and a backend server and verifies **every
request**. For each one it checks who sent it, that it was not modified, that
its session is valid and current, that it has not been processed before, and
that the sender is allowed to perform the operation. Each decision is recorded
in a tamper-evident log.

```
Client ──(signed X25519 handshake, AES-256-GCM records)──► Secure Gateway ──► Backend
```

| Mechanism | Primitive |
|---|---|
| Client and gateway authentication | Ed25519 (RFC 8032), pinned gateway key |
| Key exchange | X25519 (RFC 7748), ephemeral, signed |
| Key derivation | HKDF-SHA256 (RFC 5869), one key per direction |
| Confidentiality + integrity | AES-256-GCM (SP 800-38D), header as AAD |
| Replay protection | nonces + sequence numbers + timestamps |
| Authorization | role-based access control, deny by default |
| Accountability | hash-chained security log with reason codes |

## Quick start

Requires Python 3.11+.

```bash
python -m venv .venv
.venv/Scripts/activate            # Windows  (Linux/macOS: source .venv/bin/activate)
pip install -e ".[dev]"
flowstate-keys bootstrap          # gateway key, pinned public key, demo clients
```

Registration follows the proposal: each client generates its own key pair and only the
public key and role are registered with the gateway (`bootstrap` does this for the demo
clients). For a new client:

```bash
flowstate-keys keygen   --client-id dave                                        # on the client
flowstate-keys register --client-id dave --role customer --public-key keys/dave.pub   # on the gateway
```

Run the system in three terminals:

```bash
flowstate-backend
flowstate-gateway
flowstate-client --id alice transfer --to bob --amount 1000
```

More client commands:

```bash
flowstate-client --id alice balance
flowstate-client --id alice freeze --account bob          # rejected: UNAUTHORIZED_OPERATION
flowstate-client --id carol list-accounts                 # auditor role
flowstate-client --id root  freeze --account bob          # admin role
flowstate-audit summary
flowstate-audit verify                                    # checks the hash chain
```

Demo identities: `alice`, `bob` (customer), `carol` (auditor), `root` (admin).

## Web dashboard

```bash
python -m dashboard            # then open http://localhost:8080
```

A visual front end over the real components (it starts its own gateway and backend):

* **Overview** — the architecture, validation pipeline and threat-to-mechanism mapping from the proposal.
* **Live gateway** — act as any registered client, send requests and watch the protected frame,
  the handshake messages and each validation stage; replay or tamper with the last request, or
  move the gateway clock forward to see sessions expire.
* **Attack lab** — run each attack scenario, or all of them, and see the defence that stopped it.
* **Security log** — every decision with its reason code, filterable, with hash-chain status.
* **Evaluation** — run the benchmark and view detection rates, latency, throughput and overhead.

## Attack demonstration

```bash
python -m attacks.runner --audit logs/attack_audit.jsonl
```

This runs 15 controlled attacks against a live gateway through a
man-in-the-middle proxy: payload and header tampering, key substitution in both
directions, replay, delayed and reordered delivery, handshake replay,
impersonation, session hijacking, expired-session reuse, privilege escalation,
eavesdropping, long-term key compromise (forward secrecy) and backend bypass. For each attack it reports the reason code
that stopped it and confirms legitimate traffic still works.

## Evaluation

```bash
python -m eval.benchmark          # writes eval/results/results.json and docs/results.md
```

The benchmark measures attack-blocking rate, replay and forged-signature
detection rates, latency and throughput against a plain forwarding baseline,
per-stage pipeline cost and primitive-level encryption overhead. It also runs
the same attacks against the baseline to show they succeed without the gateway.

## Tests

```bash
pytest
```

The suite covers known-answer tests for every primitive (RFC 8032, RFC 7748,
RFC 5869, SP 800-38D), codec fuzzing, unit tests per package, end-to-end tests
over TCP, every attack scenario, and an architecture test that keeps all
cryptography inside `core/crypto.py`.

## Repository layout

```
docs/            protocol-spec, architecture, threat-model, results
config/          gateway.toml, policy.toml
src/flowstate/
  core/          codec, messages, crypto facade, pipeline, reason codes, events, clock, config
  gateway/       gateway server, in-process runtime, entry point
  client/        SecureClient SDK and CLI
  identity/      key files, client registry, Ed25519 authentication, key CLI
  handshake/     signed X25519 handshake, HKDF key schedule
  session/       session manager, expiry stage
  record/        AES-256-GCM record layer, decrypt stage
  replay/        nonce cache, sequence + freshness stages
  authz/         RBAC policy and stage
  backend/       transaction service and backend server
  audit/         hash-chained security log and CLI
attacks/         MITM proxy, attack scenarios, runner
eval/            baseline, benchmark, report
dashboard/       local web dashboard (standard-library HTTP server + static page)
tests/           mirrors the packages above
```

See [docs/protocol-spec.md](docs/protocol-spec.md) for the byte-level protocol,
[docs/architecture.md](docs/architecture.md) for the design, and
[docs/threat-model.md](docs/threat-model.md) for what is and is not defended.
