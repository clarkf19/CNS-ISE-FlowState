"""Every attack in the suite must be blocked while legitimate traffic keeps working."""

import pytest

from attacks.runner import main as runner_main
from attacks.scenarios import ALL_SCENARIOS, Attack
from flowstate.audit import verify_chain
from flowstate.gateway.runtime import start_stack

PROPOSAL_TABLE = {  # proposal section 4.4: attack -> reason code
    "mitm_tampering": "MODIFIED_MESSAGE",
    "mitm_key_substitution_client": "INVALID_SIGNATURE",
    "replay_request": "DUPLICATE_NONCE",
    "delayed_request": "STALE_REQUEST",
    "impersonation": "INVALID_SIGNATURE",
    "expired_session_reuse": "EXPIRED_SESSION",
    "unauthorized_operation": "UNAUTHORIZED_OPERATION",
    "eavesdropping": "NO_PLAINTEXT",
}


@pytest.mark.parametrize("scenario", ALL_SCENARIOS, ids=lambda s: s.__name__)
def test_attack_blocked(scenario, offset_clock):
    with start_stack(clock=offset_clock) as stack:
        result = scenario(Attack(stack, offset_clock))
    assert result.blocked, f"{result.name}: expected {result.expected}, got {result.observed}"
    assert result.observed == result.expected
    assert result.legit_ok


def test_every_proposal_attack_is_covered():
    names = {s.__name__ for s in ALL_SCENARIOS}
    assert set(PROPOSAL_TABLE) <= names
    expected = {s.__name__: s for s in ALL_SCENARIOS}
    assert all(expected[n] for n in PROPOSAL_TABLE)


def test_runner_with_audit_log(tmp_path, capsys):
    path = tmp_path / "attack.jsonl"
    assert runner_main(["--audit", str(path), "--only", "replay_request", "impersonation"]) == 0
    assert "2/2 attacks blocked" in capsys.readouterr().out
    assert verify_chain(path).ok
