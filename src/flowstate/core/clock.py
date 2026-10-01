"""Injectable clock so freshness and expiry logic can be tested deterministically."""

from __future__ import annotations

import time
from typing import Protocol


class Clock(Protocol):
    def now_ms(self) -> int: ...


class SystemClock:
    def now_ms(self) -> int:
        return time.time_ns() // 1_000_000


class OffsetClock:
    """Real time plus an adjustable offset: lets live demos 'wait' minutes instantly."""

    def __init__(self) -> None:
        self.offset_ms = 0

    def now_ms(self) -> int:
        return time.time_ns() // 1_000_000 + self.offset_ms

    def advance(self, ms: int) -> None:
        self.offset_ms += ms


class FakeClock:
    def __init__(self, start_ms: int = 1_700_000_000_000) -> None:
        self._now = start_ms

    def now_ms(self) -> int:
        return self._now

    def advance(self, ms: int) -> None:
        self._now += ms

    def set(self, ms: int) -> None:
        self._now = ms
