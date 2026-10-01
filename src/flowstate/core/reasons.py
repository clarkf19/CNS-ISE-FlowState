"""Reason codes and the exception every security check raises on failure."""

from __future__ import annotations

from enum import Enum


class ReasonCode(str, Enum):
    # The seven codes defined in the proposal, section 4.3(f).
    ACCEPTED = "ACCEPTED"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    MODIFIED_MESSAGE = "MODIFIED_MESSAGE"
    DUPLICATE_NONCE = "DUPLICATE_NONCE"
    STALE_REQUEST = "STALE_REQUEST"
    EXPIRED_SESSION = "EXPIRED_SESSION"
    UNAUTHORIZED_OPERATION = "UNAUTHORIZED_OPERATION"
    # Fail-closed codes for input that never reaches a cryptographic check.
    MALFORMED_FRAME = "MALFORMED_FRAME"
    INTERNAL_ERROR = "INTERNAL_ERROR"

    def __str__(self) -> str:
        return self.value


class SecurityError(Exception):
    """Raised by a security check. Carries the reason code that gets logged.

    ``detail`` is safe to log: it must never contain key material or plaintext.
    """

    def __init__(self, reason: ReasonCode, detail: str = "") -> None:
        super().__init__(f"{reason.value}: {detail}" if detail else reason.value)
        self.reason = reason
        self.detail = detail
