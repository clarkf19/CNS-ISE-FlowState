import pytest

from flowstate.core.messages import ProtectedRequest
from flowstate.core.pipeline import Pipeline, RequestContext
from flowstate.core.reasons import ReasonCode, SecurityError


class Recorder:
    def __init__(self, name, log, fail=None, crash=False):
        self.name, self.log, self.fail, self.crash = name, log, fail, crash

    def check(self, ctx):
        self.log.append(self.name)
        ctx.defer(lambda: self.log.append(f"commit:{self.name}"))
        if self.crash:
            raise ZeroDivisionError
        if self.fail:
            raise SecurityError(self.fail, f"{self.name} failed")


def ctx():
    return RequestContext(ProtectedRequest(b"\x00" * 16, 1, b"\x00" * 12, 0, b"\x00" * 16), now_ms=0)


def test_stages_run_in_order_and_commit_on_accept():
    log = []
    verdict = Pipeline([Recorder(n, log) for n in "abc"]).run(ctx())
    assert verdict.accepted and verdict.reason is ReasonCode.ACCEPTED
    assert log == ["a", "b", "c", "commit:a", "commit:b", "commit:c"]
    assert set(verdict.timings_ns) == {"a", "b", "c"}


def test_first_failure_short_circuits_and_nothing_commits():
    log = []
    stages = [Recorder("a", log), Recorder("b", log, ReasonCode.DUPLICATE_NONCE), Recorder("c", log)]
    verdict = Pipeline(stages).run(ctx())
    assert verdict.reason is ReasonCode.DUPLICATE_NONCE
    assert verdict.failed_stage == "b"
    assert log == ["a", "b"]  # c never ran, no commit ran


def test_unexpected_exception_fails_closed():
    log = []
    verdict = Pipeline([Recorder("a", log, crash=True)]).run(ctx())
    assert verdict.reason is ReasonCode.INTERNAL_ERROR
    assert not verdict.accepted
    assert log == ["a"]


def test_stage_names_must_be_unique():
    with pytest.raises(ValueError):
        Pipeline([Recorder("a", []), Recorder("a", [])])
