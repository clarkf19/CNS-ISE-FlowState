from __future__ import annotations

import pytest

from flowstate.authz import Policy
from flowstate.core.clock import FakeClock, OffsetClock
from flowstate.gateway.runtime import DEFAULT_POLICY, Identities, start_stack


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def identities() -> Identities:
    return Identities.generate()


@pytest.fixture
def policy() -> Policy:
    return Policy.from_dict(DEFAULT_POLICY)


@pytest.fixture
def offset_clock() -> OffsetClock:
    return OffsetClock()


@pytest.fixture
def stack(identities, offset_clock):
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
