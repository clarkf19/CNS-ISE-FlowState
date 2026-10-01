import json

import pytest

from flowstate.audit import AuditLogger, read_entries, verify_chain
from flowstate.audit.cli import main as audit_main
from flowstate.audit.cli import summarize
from flowstate.core.events import SecurityEvent
from flowstate.core.reasons import ReasonCode


def event(reason=ReasonCode.ACCEPTED, client="alice", op="balance", detail=""):
    return SecurityEvent(1_700_000_000_000, "request", reason, client, "ab" * 16, op, detail)


@pytest.fixture
def log(tmp_path):
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path)
    for reason in ReasonCode:
        logger.record(event(reason))
    return path, logger


def test_one_entry_per_event_with_required_fields(log):
    path, logger = log
    entries = read_entries(path)
    assert [e["reason"] for e in entries] == [r.value for r in ReasonCode]
    for e in entries:
        for key in ("time", "client_id", "session_id", "operation", "reason", "hash", "prev_hash"):
            assert key in e
    assert logger.counters["MODIFIED_MESSAGE"] == 1


def test_chain_verifies(log):
    assert verify_chain(log[0]).ok


def rewrite(path, fn):
    lines = path.read_text().splitlines()
    path.write_text("\n".join(fn(lines)) + "\n")


@pytest.mark.parametrize(
    "tamper, problem",
    [
        (lambda ls: [ls[0], ls[1].replace('"balance"', '"transfer"'), *ls[2:]], "modified"),
        (lambda ls: [ls[0], *ls[2:]], "chain link broken"),
        (lambda ls: [ls[1], ls[0], *ls[2:]], "chain link broken"),
        (lambda ls: ls[:-1] + ["{broken"], "unparseable"),
    ],
    ids=["edit", "delete", "reorder", "corrupt"],
)
def test_tampering_detected(log, tamper, problem):
    path, _ = log
    rewrite(path, tamper)
    result = verify_chain(path)
    assert not result.ok and problem in result.problem


def test_edit_with_recomputed_field_still_detected(log):
    path, _ = log
    lines = path.read_text().splitlines()
    entry = json.loads(lines[3])
    entry["reason"] = "ACCEPTED"
    lines[3] = json.dumps(entry, sort_keys=True)
    path.write_text("\n".join(lines) + "\n")
    result = verify_chain(path)
    assert not result.ok and result.first_bad_line == 4 and "modified" in result.problem


def test_chain_continues_after_restart(log):
    path, _ = log
    AuditLogger(path).record(event())
    assert verify_chain(path).ok and verify_chain(path).entries == len(ReasonCode) + 1


def test_detail_is_truncated(tmp_path):
    path = tmp_path / "a.jsonl"
    AuditLogger(path).record(event(detail="x" * 5000))
    assert len(read_entries(path)[0]["detail"]) == 200


def test_summary_and_cli(log, capsys):
    path, _ = log
    s = summarize(read_entries(path))
    assert s["total"] == len(ReasonCode) and s["accepted"] == 1
    assert audit_main(["verify", "--log", str(path)]) == 0
    assert audit_main(["show", "--log", str(path), "--reason", "STALE_REQUEST"]) == 0
    assert "STALE_REQUEST" in capsys.readouterr().out
