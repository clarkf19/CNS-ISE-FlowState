"""Replay detector (proposal section 4.3(e), checks 3 and 4).

Three independent defences, each sufficient against a verbatim replay:
  * nonce cache  - a nonce accepted once in a session is never accepted again
  * sequence     - sequence numbers must strictly increase within a session
  * freshness    - timestamps must be within +/- max_skew_ms of gateway time

The nonce cache is bounded. Evicting an old nonce is safe because a replay of
that request is still caught by the sequence check and the freshness window.

All state changes are deferred to the pipeline commit, so a request rejected
by any later stage (or a forged frame rejected earlier) changes nothing.
The gateway runs the pipeline on a single event loop, so check-then-commit is
atomic per request.
"""

from __future__ import annotations

from collections import OrderedDict

from flowstate.core.pipeline import RequestContext
from flowstate.core.reasons import ReasonCode, SecurityError


class NonceCache:
    def __init__(self, window_ms: int, max_entries: int = 4096) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be positive")
        self.window_ms = window_ms
        self.max_entries = max_entries
        self._seen: OrderedDict[bytes, int] = OrderedDict()

    def contains(self, nonce: bytes) -> bool:
        return nonce in self._seen

    def add(self, nonce: bytes, timestamp_ms: int, now_ms: int) -> None:
        self._seen[nonce] = timestamp_ms
        self._seen.move_to_end(nonce)
        # Drop nonces whose requests would now fail the freshness window anyway.
        while self._seen:
            oldest_nonce, oldest_ts = next(iter(self._seen.items()))
            if now_ms - oldest_ts <= 2 * self.window_ms and len(self._seen) <= self.max_entries:
                break
            del self._seen[oldest_nonce]

    def __len__(self) -> int:
        return len(self._seen)


class ReplayStage:
    """Check 3: nonce uniqueness and sequence-number ordering."""

    name = "replay"
    EXTENSION_KEY = "replay.nonces"

    def __init__(self, *, window_ms: int, max_entries: int = 4096) -> None:
        self.window_ms = window_ms
        self.max_entries = max_entries

    def check(self, ctx: RequestContext) -> None:
        session, frame = ctx.session, ctx.frame
        cache: NonceCache = session.extensions.setdefault(
            self.EXTENSION_KEY, NonceCache(self.window_ms, self.max_entries)
        )
        if cache.contains(frame.nonce):
            raise SecurityError(ReasonCode.DUPLICATE_NONCE, "nonce already used in this session")
        if frame.seq <= session.last_seq:
            raise SecurityError(
                ReasonCode.STALE_REQUEST,
                f"sequence {frame.seq} not greater than last accepted {session.last_seq}",
            )

        def commit() -> None:
            cache.add(frame.nonce, frame.timestamp, ctx.now_ms)
            session.last_seq = frame.seq

        ctx.defer(commit)


class FreshnessStage:
    """Check 4: timestamp within the freshness window (both directions)."""

    name = "freshness"

    def __init__(self, *, max_skew_ms: int) -> None:
        self.max_skew_ms = max_skew_ms

    def check(self, ctx: RequestContext) -> None:
        age = ctx.now_ms - ctx.frame.timestamp
        if age > self.max_skew_ms:
            raise SecurityError(ReasonCode.STALE_REQUEST, f"request is {age} ms old")
        if -age > self.max_skew_ms:
            raise SecurityError(ReasonCode.STALE_REQUEST, f"request is {-age} ms in the future")
