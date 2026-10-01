"""Storage of long-term Ed25519 keys and the pinned gateway key.

Keys are stored hex-encoded. Private key files are created with owner-only
permissions where the OS supports it, and the keys/ directory is git-ignored.
"""

from __future__ import annotations

import os
from pathlib import Path

from flowstate.core.crypto import CryptoError, SigningKey, VerifyKey


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text + "\n")


def _read_hex(path: Path) -> bytes:
    try:
        return bytes.fromhex(Path(path).read_text().strip())
    except ValueError as exc:
        raise CryptoError(f"{path} does not contain hex key material") from exc


def save_signing_key(path: str | Path, key: SigningKey) -> None:
    _write_private(Path(path), key.private_bytes().hex())


def load_signing_key(path: str | Path) -> SigningKey:
    return SigningKey(_read_hex(Path(path)))


def save_public_key(path: str | Path, key: VerifyKey) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(key.public_bytes().hex() + "\n")


def load_public_key(path: str | Path) -> VerifyKey:
    return VerifyKey(_read_hex(Path(path)))


def save_secret(path: str | Path, secret: bytes) -> None:
    _write_private(Path(path), secret.hex())


def load_secret(path: str | Path) -> bytes:
    return _read_hex(Path(path))
