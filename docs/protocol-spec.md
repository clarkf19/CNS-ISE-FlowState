# FlowState Protocol Specification (v1)

This document defines the exact bytes exchanged between client, gateway and
backend. The code in `src/flowstate/core/messages.py` and `codec.py` is the
reference implementation; if the two ever disagree, fix whichever is wrong
and add a test.

## 1. Primitives

| Purpose | Primitive | Standard | Sizes |
|---|---|---|---|
| Long-term identity, handshake signatures | Ed25519 | RFC 8032 | 32-byte keys, 64-byte signatures |
| Ephemeral key agreement | X25519 | RFC 7748 | 32-byte keys |
| Session key derivation | HKDF-SHA256 | RFC 5869 | 32-byte output keys |
| Record protection | AES-256-GCM | NIST SP 800-38D | 96-bit nonce, 128-bit tag |
| Transcript / audit hashing | SHA-256 | FIPS 180-4 | 32 bytes |

All primitives are reached through `flowstate.core.crypto`. No other module
imports the `cryptography` library (enforced by `tests/core/test_architecture.py`).

## 2. Encoding

**Fields.** Every signed or authenticated structure is encoded as a sequence
of fields, each `u32 length (big-endian) || bytes`. Integers are `u64`
big-endian (8 bytes). Decoding requires the exact field count and rejects
truncation and trailing bytes. Because every field carries its own length,
the encoding is injective, so a signature over it cannot be reinterpreted.

**Messages.** `type (1 byte) || version (1 byte = 0x01) || fields`.

**Transport framing.** On TCP, each message is preceded by a `u32` length.
Frames larger than 64 KiB are rejected and the connection is closed.

Any decoding failure yields `MALFORMED_FRAME` before any cryptographic work.

## 3. Messages

| Type | Name | Fields (in order) |
|---|---|---|
| 1 | ClientHello | client_id (ASCII, `[A-Za-z0-9_.-]{1,64}`), eph_pub (32), nonce (16), timestamp (u64 ms), signature (64) |
| 2 | ServerHello | session_id (16), eph_pub (32), nonce (16), expires_at (u64 ms), signature (64) |
| 3 | ProtectedRequest | session_id (16), seq (u64), nonce (12), timestamp (u64 ms), ciphertext‖tag (≥16) |
| 4 | ProtectedResponse | session_id (16), seq (u64), nonce (12), ciphertext‖tag (≥16) |
| 5 | Error | reason (UTF-8), detail (UTF-8) |

## 4. Handshake

```
Client                                                Gateway
------                                                -------
eph_C, nonce_C ← random
CH = ClientHello(id, eph_C, nonce_C, ts)
CH.sig = Ed25519_sign(sk_client,
         "FLOWSTATE/1 client-hello" || fields(id, eph_C, nonce_C, ts))
                         ── CH ──►
                                         1. look up id; verify CH.sig   → INVALID_SIGNATURE
                                         2. |now − ts| ≤ max_skew        → STALE_REQUEST
                                         3. (id, nonce_C) unseen          → DUPLICATE_NONCE
                                         eph_G, nonce_G, session_id ← random
                                         expires_at = now + ttl
                                         SH.sig = Ed25519_sign(sk_gateway,
                                            "FLOWSTATE/1 server-hello" ||
                                            fields(SHA256(CH), sid, eph_G, nonce_G, expires_at))
                         ◄── SH ──
verify SH.sig with the PINNED gateway key  → INVALID_SIGNATURE
check expires_at > now
```

The gateway signature covers `SHA-256(ClientHello)`, so a ServerHello cannot be
replayed into, or spliced with, a different handshake. The gateway records a
HELLO nonce only after the signature verifies, so forged HELLOs cannot fill
its cache.

## 5. Key schedule

```
shared = X25519(eph_own, eph_peer)               (all-zero output rejected)
salt   = nonce_C || nonce_G
k_c2g  = HKDF-SHA256(shared, salt, "FLOWSTATE/1 key client-to-gateway " || session_id, 32)
k_g2c  = HKDF-SHA256(shared, salt, "FLOWSTATE/1 key gateway-to-client " || session_id, 32)
```

Ephemeral keys are single-use. Each session therefore has fresh keys, which
gives forward secrecy.

## 6. Protected records

```
AAD_req  = "FLOWSTATE/1 request"  || fields(session_id, seq, nonce, timestamp)
CT_req   = AES-256-GCM(k_c2g, nonce, plaintext, AAD_req)
AAD_resp = "FLOWSTATE/1 response" || fields(session_id, seq, nonce)
CT_resp  = AES-256-GCM(k_g2c, nonce, plaintext, AAD_resp)
```

* The plaintext is canonical JSON: `{"op": <string>, "params": {...}}`. The
  operation is encrypted, so an observer cannot see what a client is doing.
* `seq` starts at 1 and strictly increases per session. The response echoes the
  request's `seq` and `session_id`, and the client checks both.
* The nonce is 12 random bytes per record. It is also the replay nonce.
  Sessions are bounded by lifetime and `max_requests_per_session`.

## 7. Gateway validation order

| # | Stage | Check | Reason on failure |
|---|---|---|---|
| 1 | session | session exists, not expired, under request limit | EXPIRED_SESSION |
| 2 | decrypt | GCM tag verifies with k_c2g; payload well-formed | MODIFIED_MESSAGE / MALFORMED_FRAME |
| 3 | replay | nonce unseen in session; seq > last_seq | DUPLICATE_NONCE / STALE_REQUEST |
| 4 | freshness | \|now − timestamp\| ≤ max_skew | STALE_REQUEST |
| 5 | authorization | role grants the operation's permission | UNAUTHORIZED_OPERATION |

Stages register state changes with `ctx.defer`. The pipeline applies them
**only if all five stages pass**. Any unexpected exception in a stage is
`INTERNAL_ERROR` (fail closed).

## 8. Reason codes

`ACCEPTED`, `INVALID_SIGNATURE`, `MODIFIED_MESSAGE`, `DUPLICATE_NONCE`,
`STALE_REQUEST`, `EXPIRED_SESSION`, `UNAUTHORIZED_OPERATION` (from the
proposal), plus `MALFORMED_FRAME` and `INTERNAL_ERROR` for input that never
reaches a cryptographic check.

Unknown client IDs return `INVALID_SIGNATURE`, and unknown session IDs return
`EXPIRED_SESSION`. This means the gateway does not reveal which identifiers exist.

## 9. Gateway → backend

The backend listens on loopback and accepts length-prefixed JSON
`{"token", "client_id", "role", "op", "params"}`. It executes the request only
if `token` matches the 32-byte forwarding secret (compared in constant time).
Clients never hold this token, so they cannot call the backend directly.
