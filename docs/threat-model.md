# Threat Model

## Assets

Data in transit (transaction details, identities), session state (session IDs
and keys), client identities (Ed25519 private keys), the backend service, and
the audit trail.

## Adversary

A network attacker who can read, modify, drop, delay, reorder, replay and inject
any traffic between client and gateway. This includes on-path positions via a
rogue access point, ARP or DNS spoofing, or a compromised proxy. The attacker
may also be a registered, low-privilege client.

The attacker **cannot** read the client's or gateway's private keys from their
hosts, and cannot break Ed25519, X25519, HKDF-SHA256 or AES-256-GCM.

## Threats and defences

| Threat | Defence | Reason code | Attack scenario |
|---|---|---|---|
| Payload tampering (1,000 → 9,000) | AES-256-GCM tag over ciphertext | MODIFIED_MESSAGE | `mitm_tampering` |
| Header tampering (seq, session ID, timestamp) | Header is GCM associated data | MODIFIED_MESSAGE | `mitm_header_tampering` |
| Key substitution in handshake | Both hellos signed; client pins gateway key; transcript binding | INVALID_SIGNATURE | `mitm_key_substitution_client`, `_gateway` |
| Request replay | Per-session nonce cache | DUPLICATE_NONCE | `replay_request` |
| Delayed delivery | Timestamp freshness window | STALE_REQUEST | `delayed_request` |
| Reordering | Strictly increasing sequence numbers | STALE_REQUEST | `reordered_request` |
| Handshake replay | HELLO nonce cache + freshness | DUPLICATE_NONCE / STALE_REQUEST | `handshake_replay` |
| Client impersonation | Ed25519 signature against registered key | INVALID_SIGNATURE | `impersonation` |
| Session hijacking with a stolen session ID | Requests must be encrypted under session keys | MODIFIED_MESSAGE | `session_hijack` |
| Expired-session reuse | Session expiry and key destruction | EXPIRED_SESSION | `expired_session_reuse` |
| Privilege escalation | RBAC, deny by default | UNAUTHORIZED_OPERATION | `unauthorized_operation` |
| Eavesdropping | Payload, including operation name, encrypted | — | `eavesdropping` |
| Decrypting recorded traffic after long-term keys leak | Forward secrecy: session keys come from ephemeral X25519 secrets destroyed after the handshake | — | `recorded_traffic_key_compromise` |
| Gateway bypass | Backend requires gateway forwarding token | — | `backend_bypass` |
| Replay-state poisoning by forged frames | State committed only after all checks pass | — | `tests/replay` |
| Silent attacks / log tampering | Event per decision; SHA-256 hash chain | — | `tests/audit` |
| Malformed-input crashes | Strict decoder, size limits, fail-closed pipeline | MALFORMED_FRAME | `tests/core` fuzz test |

## Out of scope and known limitations

* **Endpoint compromise.** If a client's private key is stolen, the attacker can
  authenticate as that client in *new* sessions (past sessions stay protected by
  forward secrecy). Mitigation is revocation (`ClientRegistry.revoke`).
* **Traffic analysis.** Frame sizes and timing are visible. ClientHello carries
  the client ID in clear, so an observer learns *who* connects, but not what
  they do.
* **Denial of service.** There are bounds on frames, sessions and caches, but no
  rate limiting. Handshakes cost the gateway one signature verification each.
* **Persistence.** Sessions, replay state and the backend ledger are in memory.
  A gateway restart ends all sessions, which is safe because clients simply
  handshake again.
* **Time.** Freshness depends on loosely synchronized clocks (±`max_skew_ms`).
* **Defence in depth.** The protocol runs over plain TCP for the demonstration.
  In deployment it would run inside TLS, adding protection rather than
  replacing it.
