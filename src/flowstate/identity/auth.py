"""Authentication module: verifies Ed25519 signatures on ClientHello messages."""

from __future__ import annotations

from flowstate.core.crypto import SigningKey
from flowstate.core.messages import ClientHello
from flowstate.core.reasons import ReasonCode, SecurityError
from flowstate.identity.registry import ClientRecord, ClientRegistry


def sign_client_hello(hello: ClientHello, key: SigningKey) -> ClientHello:
    return ClientHello(
        hello.client_id, hello.eph_pub, hello.nonce, hello.timestamp,
        key.sign(hello.signed_payload()),
    )


def authenticate_client_hello(hello: ClientHello, registry: ClientRegistry) -> ClientRecord:
    """Return the registered client, or raise INVALID_SIGNATURE.

    An unknown client ID is reported with the same code as a bad signature so
    the gateway does not reveal which client IDs exist.
    """
    record = registry.get(hello.client_id)
    if record is None:
        raise SecurityError(ReasonCode.INVALID_SIGNATURE, "unknown client")
    if not record.public_key.verify(hello.signature, hello.signed_payload()):
        raise SecurityError(ReasonCode.INVALID_SIGNATURE, "client signature did not verify")
    return record
