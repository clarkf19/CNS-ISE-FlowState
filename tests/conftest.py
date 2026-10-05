"""Shared fixtures.

Only ``flowstate.core`` is imported at module level. Fixtures that need later
packages import them inside the fixture, so each package's tests can run as
soon as that package exists (the project is built one member at a time).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flowstate.core.clock import FakeClock, OffsetClock

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def offset_clock() -> OffsetClock:
    return OffsetClock()


@pytest.fixture
def policy():
    from flowstate.authz import Policy

    return Policy.load(ROOT / "config" / "policy.toml")


@pytest.fixture
def identities():
    from flowstate.gateway.runtime import Identities

    return Identities.generate()


@pytest.fixture
def stack(identities, offset_clock):
    from flowstate.gateway.runtime import start_stack

    with start_stack(identities=identities, clock=offset_clock) as s:
        yield s


@pytest.fixture
def make_client(stack, offset_clock):
    from flowstate.client import SecureClient

    clients = []

    def make(client_id: str = "alice", address=None) -> SecureClient:
        ids = stack.identities
        c = SecureClient(
            address or stack.gateway_addr, client_id, ids.client_keys[client_id],
            ids.gateway_pin, clock=offset_clock,
        )
        clients.append(c)
        return c

    yield make
    for c in clients:
        c.close()
