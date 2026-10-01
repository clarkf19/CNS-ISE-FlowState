"""Security events emitted for every gateway decision, and the sink interface.

The gateway emits exactly one event per handshake attempt and per request.
Stages never log directly; they raise SecurityError and the gateway turns the
resulting verdict into an event. ``flowstate.audit`` provides the persistent
sink.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Protocol

from flowstate.core.reasons import ReasonCode


@dataclass(frozen=True)
class SecurityEvent:
    timestamp_ms: int
    phase: str  # "handshake" or "request"
    reason: ReasonCode
    client_id: str | None = None
    session_id: str | None = None  # hex
    operation: str | None = None
    detail: str = ""
    peer: str | None = None
    stage: str | None = None  # pipeline stage that rejected the request, if any

    @property
    def accepted(self) -> bool:
        return self.reason is ReasonCode.ACCEPTED

    def to_dict(self) -> dict:
        d = asdict(self)
        d["reason"] = self.reason.value
        return d


class EventSink(Protocol):
    def record(self, event: SecurityEvent) -> None: ...


class NullSink:
    def record(self, event: SecurityEvent) -> None:
        pass


class MemorySink:
    def __init__(self) -> None:
        self.events: list[SecurityEvent] = []

    def record(self, event: SecurityEvent) -> None:
        self.events.append(event)

    def reasons(self) -> list[ReasonCode]:
        return [e.reason for e in self.events]


class MultiSink:
    def __init__(self, *sinks: EventSink) -> None:
        self.sinks = list(sinks)

    def record(self, event: SecurityEvent) -> None:
        for sink in self.sinks:
            sink.record(event)
