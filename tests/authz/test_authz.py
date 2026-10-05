from types import SimpleNamespace

import pytest

from flowstate.authz import AuthorizationStage, Policy
from flowstate.core.messages import ProtectedRequest
from flowstate.core.pipeline import RequestContext
from flowstate.core.reasons import ReasonCode, SecurityError

EXPECTED = {
    #             balance transfer list_accounts freeze create
    "customer": (True, True, False, False, False),
    "auditor": (True, False, True, False, False),
    "admin": (True, True, True, True, True),
}
OPS = ("balance", "transfer", "list_accounts", "freeze_account", "create_account")


@pytest.mark.parametrize("role", EXPECTED)
def test_role_operation_matrix(policy, role):
    assert tuple(policy.is_allowed(role, op) for op in OPS) == EXPECTED[role]


def test_deny_by_default(policy):
    assert not policy.is_allowed("admin", "drop_database")
    assert not policy.is_allowed("ghost", "balance")
    assert not policy.is_allowed("", "balance")


def test_policy_validation():
    with pytest.raises(ValueError):
        Policy.from_dict({"operations": {"x": ""}})


def stage_ctx(role, op):
    ctx = RequestContext(ProtectedRequest(b"\x00" * 16, 1, b"\x00" * 12, 0, b"\x00" * 16), 0)
    ctx.session, ctx.operation = SimpleNamespace(role=role), op
    return ctx


def test_stage(policy):
    AuthorizationStage(policy).check(stage_ctx("customer", "transfer"))
    for role, op, text in [("customer", "freeze_account", "may not"), ("admin", "nope", "not defined")]:
        with pytest.raises(SecurityError) as exc:
            AuthorizationStage(policy).check(stage_ctx(role, op))
        assert exc.value.reason is ReasonCode.UNAUTHORIZED_OPERATION and text in exc.value.detail
