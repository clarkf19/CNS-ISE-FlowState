"""Pipeline stage 5: role-based permission check for the requested operation."""

from __future__ import annotations

from flowstate.authz.policy import Policy
from flowstate.core.pipeline import RequestContext
from flowstate.core.reasons import ReasonCode, SecurityError


class AuthorizationStage:
    name = "authorization"

    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def check(self, ctx: RequestContext) -> None:
        role, op = ctx.session.role, ctx.operation
        if not self.policy.is_allowed(role, op):
            if self.policy.required_permission(op) is None:
                detail = f"operation {op!r} is not defined"
            else:
                detail = f"role {role!r} may not call {op!r}"
            raise SecurityError(ReasonCode.UNAUTHORIZED_OPERATION, detail)
