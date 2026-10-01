"""Cryptographic primitive facade.

This is the only module in the project allowed to import ``cryptography``.
Every other package uses these functions, which keeps primitive usage in
one reviewed place and makes misuse (wrong key sizes, reused objects,
non-constant-time comparison) harder.

Primitives (proposal section 4.1):
  Ed25519 (RFC 8032)      - signatures for authentication
  X25519 (RFC 7748)       - ephemeral key agreement
  HKDF-SHA256 (RFC 5869)  - session key derivation
  AES-256-GCM (SP 800-38D) - authenticated encryption
"""

from __future__ import annotations

import hashlib
import hmac
import os

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ED25519_KEY_LEN = 32
ED25519_SIG_LEN = 64
X25519_KEY_LEN = 32
AES_KEY_LEN = 32
GCM_NONCE_LEN = 12  # 96-bit nonce
GCM_TAG_LEN = 16  # 128-bit tag

_RAW = serialization.Encoding.Raw
_RAW_PUB = serialization.PublicFormat.Raw
_RAW_PRIV = serialization.PrivateFormat.Raw
_NO_ENC = serialization.NoEncryption()


class CryptoError(Exception):
    """Invalid key material or a failed cryptographic operation."""


class AuthenticationFailed(CryptoError):
    """AEAD tag did not verify: the ciphertext, nonce, AAD or key is wrong."""


def random_bytes(n: int) -> bytes:
    return os.urandom(n)


def constant_time_eq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _check_len(name: str, value: bytes, expected: int) -> None:
    if not isinstance(value, (bytes, bytearray)) or len(value) != expected:
        raise CryptoError(f"{name} must be {expected} bytes")


# ---------------------------------------------------------------- Ed25519


class SigningKey:
    """Long-term Ed25519 private key."""

    def __init__(self, raw: bytes) -> None:
        _check_len("Ed25519 private key", raw, ED25519_KEY_LEN)
        self._key = Ed25519PrivateKey.from_private_bytes(bytes(raw))

    @classmethod
    def generate(cls) -> "SigningKey":
        return cls(Ed25519PrivateKey.generate().private_bytes(_RAW, _RAW_PRIV, _NO_ENC))

    def private_bytes(self) -> bytes:
        return self._key.private_bytes(_RAW, _RAW_PRIV, _NO_ENC)

    def public_key(self) -> "VerifyKey":
        return VerifyKey(self._key.public_key().public_bytes(_RAW, _RAW_PUB))

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)


class VerifyKey:
    """Ed25519 public key."""

    def __init__(self, raw: bytes) -> None:
        _check_len("Ed25519 public key", raw, ED25519_KEY_LEN)
        try:
            self._key = Ed25519PublicKey.from_public_bytes(bytes(raw))
        except ValueError as exc:
            raise CryptoError("invalid Ed25519 public key") from exc
        self._raw = bytes(raw)

    def public_bytes(self) -> bytes:
        return self._raw

    def verify(self, signature: bytes, message: bytes) -> bool:
        if not isinstance(signature, (bytes, bytearray)) or len(signature) != ED25519_SIG_LEN:
            return False
        try:
            self._key.verify(bytes(signature), message)
            return True
        except InvalidSignature:
            return False

    def __eq__(self, other: object) -> bool:
        return isinstance(other, VerifyKey) and constant_time_eq(self._raw, other._raw)

    def __hash__(self) -> int:
        return hash(self._raw)


# ---------------------------------------------------------------- X25519


class EphemeralKeyPair:
    """Single-use X25519 key pair. ``exchange`` may be called only once."""

    def __init__(self, private: X25519PrivateKey | None = None) -> None:
        self._key: X25519PrivateKey | None = private or X25519PrivateKey.generate()
        self._public = self._key.public_key().public_bytes(_RAW, _RAW_PUB)

    @classmethod
    def from_private_bytes(cls, raw: bytes) -> "EphemeralKeyPair":
        _check_len("X25519 private key", raw, X25519_KEY_LEN)
        return cls(X25519PrivateKey.from_private_bytes(bytes(raw)))

    def public_bytes(self) -> bytes:
        return self._public

    def exchange(self, peer_public: bytes) -> bytes:
        if self._key is None:
            raise CryptoError("ephemeral key already used")
        _check_len("X25519 public key", peer_public, X25519_KEY_LEN)
        try:
            shared = self._key.exchange(X25519PublicKey.from_public_bytes(bytes(peer_public)))
        except ValueError as exc:  # all-zero output from a low-order point
            raise CryptoError("X25519 exchange produced an invalid shared secret") from exc
        finally:
            self._key = None  # ephemeral: never reuse
        if constant_time_eq(shared, bytes(X25519_KEY_LEN)):
            raise CryptoError("X25519 exchange produced an all-zero shared secret")
        return shared


# ---------------------------------------------------------------- HKDF


def hkdf_sha256(ikm: bytes, *, salt: bytes, info: bytes, length: int = AES_KEY_LEN) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


# ---------------------------------------------------------------- AES-256-GCM


class AeadKey:
    """AES-256-GCM key. The 128-bit tag is appended to the ciphertext."""

    def __init__(self, raw: bytes) -> None:
        _check_len("AES-256 key", raw, AES_KEY_LEN)
        self._aead = AESGCM(bytes(raw))

    def seal(self, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        _check_len("GCM nonce", nonce, GCM_NONCE_LEN)
        return self._aead.encrypt(bytes(nonce), plaintext, aad)

    def open(self, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        if len(nonce) != GCM_NONCE_LEN or len(ciphertext) < GCM_TAG_LEN:
            raise AuthenticationFailed("malformed AEAD input")
        try:
            return self._aead.decrypt(bytes(nonce), bytes(ciphertext), aad)
        except InvalidTag as exc:
            raise AuthenticationFailed("GCM tag verification failed") from exc
