"""Session key derivation (proposal section 4.3(c)).

HKDF-SHA256 with salt = client nonce || server nonce, and a context label per
direction, turns the X25519 shared secret into two independent AES-256 keys.
The session ID is mixed into the label so keys are bound to their session.
"""

from __future__ import annotations

from dataclasses import dataclass

from flowstate.core import crypto

LABEL_C2G = b"FLOWSTATE/1 key client-to-gateway "
LABEL_G2C = b"FLOWSTATE/1 key gateway-to-client "


@dataclass(frozen=True)
class SessionKeys:
    c2g: bytes  # client -> gateway
    g2c: bytes  # gateway -> client

    def __repr__(self) -> str:  # never print key material
        return "SessionKeys(<redacted>)"


def derive_session_keys(
    shared_secret: bytes, client_nonce: bytes, server_nonce: bytes, session_id: bytes
) -> SessionKeys:
    salt = client_nonce + server_nonce
    return SessionKeys(
        c2g=crypto.hkdf_sha256(shared_secret, salt=salt, info=LABEL_C2G + session_id),
        g2c=crypto.hkdf_sha256(shared_secret, salt=salt, info=LABEL_G2C + session_id),
    )
