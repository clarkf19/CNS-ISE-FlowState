"""Pipeline stage 1: session lookup and expiry check."""

from __future__ import annotations

from flowstate.core.pipeline import RequestContext
from flowstate.core.reasons import ReasonCode, SecurityError
from flowstate.session.manager import SessionManager


class SessionStage:
    name = "session"

    def __init__(self, manager: SessionManager, *, max_requests: int = 1_000_000) -> None:
        self.manager = manager
        self.max_requests = max_requests

    def check(self, ctx: RequestContext) -> None:
        session = self.manager.lookup(ctx.frame.session_id, ctx.now_ms)
        if session.request_count >= self.max_requests:
            # Bounds the number of messages encrypted under one key.
            self.manager.terminate(session.session_id)
            raise SecurityError(ReasonCode.EXPIRED_SESSION, "session request limit reached")
        ctx.session = session

        def count() -> None:
            session.request_count += 1

        ctx.defer(count)
