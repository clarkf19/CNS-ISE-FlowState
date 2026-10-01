"""Session manager (proposal section 4.2).

Stores, per session: client identity, role, direction keys, expiry and the
last accepted sequence number. ``extensions`` holds per-session state owned
by later pipeline stages (e.g. the replay detector's nonce cache).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

from flowstate.core import crypto
from flowstate.core.clock import Clock, SystemClock
from flowstate.core.reasons import ReasonCode, SecurityError
from flowstate.handshake.protocol import EstablishedSession


@dataclass
class Session:
    session_id: bytes
    client_id: str
    role: str
    c2g: crypto.AeadKey | None
    g2c: crypto.AeadKey | None
    created_at: int
    expires_at: int
    last_seq: int = 0  # sequence numbers start at 1
    request_count: int = 0
    extensions: dict[str, Any] = field(default_factory=dict)

    @property
    def session_hex(self) -> str:
        return self.session_id.hex()

    def is_expired(self, now_ms: int) -> bool:
        return now_ms >= self.expires_at

    def destroy_keys(self) -> None:
        # Best effort: drop the only references so the key objects can be freed.
        self.c2g = None
        self.g2c = None
        self.extensions.clear()

    def __repr__(self) -> str:
        return f"Session({self.session_hex}, client={self.client_id}, role={self.role})"


class SessionManager:
    def __init__(self, clock: Clock | None = None, *, max_sessions: int = 10_000) -> None:
        self.clock = clock or SystemClock()
        self.max_sessions = max_sessions
        self._sessions: dict[bytes, Session] = {}
        self._lock = threading.RLock()

    def create(self, est: EstablishedSession) -> Session:
        now = self.clock.now_ms()
        session = Session(
            session_id=est.session_id,
            client_id=est.client.client_id,
            role=est.client.role,
            c2g=crypto.AeadKey(est.keys.c2g),
            g2c=crypto.AeadKey(est.keys.g2c),
            created_at=now,
            expires_at=est.expires_at,
        )
        with self._lock:
            if est.session_id in self._sessions:
                raise SecurityError(ReasonCode.INTERNAL_ERROR, "session id collision")
            if len(self._sessions) >= self.max_sessions:
                self.cleanup_expired()
                if len(self._sessions) >= self.max_sessions:
                    raise SecurityError(ReasonCode.INTERNAL_ERROR, "session table full")
            self._sessions[est.session_id] = session
        return session

    def get(self, session_id: bytes) -> Session | None:
        with self._lock:
            return self._sessions.get(session_id)

    def lookup(self, session_id: bytes, now_ms: int | None = None) -> Session:
        """Return a live session or raise EXPIRED_SESSION.

        Unknown and expired sessions share one reason code so an attacker
        cannot probe which session IDs were ever valid.
        """
        now = self.clock.now_ms() if now_ms is None else now_ms
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise SecurityError(ReasonCode.EXPIRED_SESSION, "unknown session")
            if session.is_expired(now):
                self._remove(session_id)
                raise SecurityError(ReasonCode.EXPIRED_SESSION, "session expired")
            return session

    def terminate(self, session_id: bytes) -> bool:
        with self._lock:
            return self._remove(session_id)

    def cleanup_expired(self, now_ms: int | None = None) -> int:
        now = self.clock.now_ms() if now_ms is None else now_ms
        with self._lock:
            dead = [sid for sid, s in self._sessions.items() if s.is_expired(now)]
            for sid in dead:
                self._remove(sid)
            return len(dead)

    def _remove(self, session_id: bytes) -> bool:
        session = self._sessions.pop(session_id, None)
        if session is None:
            return False
        session.destroy_keys()
        return True

    def __len__(self) -> int:
        with self._lock:
            return len(self._sessions)
