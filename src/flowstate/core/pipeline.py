"""Ordered request-validation pipeline (proposal section 4.3(e)).

Stages run in a fixed order and the first failure stops the pipeline.
Stages must not mutate shared state directly: they register changes with
``ctx.defer`` and the pipeline applies them only after *every* stage has
passed. A rejected request therefore never consumes a nonce or advances a
sequence number, so forged traffic cannot poison replay state.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from flowstate.core.messages import ProtectedRequest
from flowstate.core.reasons import ReasonCode, SecurityError


@dataclass
class RequestContext:
    frame: ProtectedRequest
    now_ms: int
    peer: str | None = None
    session: Any = None  # flowstate.session.Session once the session stage passes
    plaintext: bytes | None = None
    operation: str | None = None
    params: dict = field(default_factory=dict)
    _commits: list[Callable[[], None]] = field(default_factory=list)

    def defer(self, action: Callable[[], None]) -> None:
        self._commits.append(action)


class Stage(Protocol):
    name: str

    def check(self, ctx: RequestContext) -> None:
        """Raise SecurityError to reject; register state changes with ctx.defer."""


@dataclass
class Verdict:
    reason: ReasonCode
    detail: str
    ctx: RequestContext
    failed_stage: str | None = None
    timings_ns: dict[str, int] = field(default_factory=dict)

    @property
    def accepted(self) -> bool:
        return self.reason is ReasonCode.ACCEPTED


class Pipeline:
    def __init__(self, stages: list[Stage]) -> None:
        names = [s.name for s in stages]
        if len(set(names)) != len(names):
            raise ValueError("stage names must be unique")
        self.stages = list(stages)

    def stage_names(self) -> list[str]:
        return [s.name for s in self.stages]

    def run(self, ctx: RequestContext) -> Verdict:
        timings: dict[str, int] = {}
        for stage in self.stages:
            start = time.perf_counter_ns()
            try:
                stage.check(ctx)
            except SecurityError as err:
                timings[stage.name] = time.perf_counter_ns() - start
                return Verdict(err.reason, err.detail, ctx, stage.name, timings)
            except Exception as exc:  # fail closed on any bug in a stage
                timings[stage.name] = time.perf_counter_ns() - start
                return Verdict(
                    ReasonCode.INTERNAL_ERROR, type(exc).__name__, ctx, stage.name, timings
                )
            timings[stage.name] = time.perf_counter_ns() - start
        for commit in ctx._commits:
            commit()
        return Verdict(ReasonCode.ACCEPTED, "", ctx, None, timings)
