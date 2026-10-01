"""Pipeline stage 2: AES-GCM decryption and tag verification."""

from __future__ import annotations

from flowstate.core.pipeline import RequestContext
from flowstate.core.reasons import ReasonCode, SecurityError
from flowstate.record.layer import decode_payload, open_request


class DecryptStage:
    name = "decrypt"

    def check(self, ctx: RequestContext) -> None:
        key = ctx.session.c2g
        if key is None:  # session destroyed between lookup and decryption
            raise SecurityError(ReasonCode.EXPIRED_SESSION, "session keys destroyed")
        ctx.plaintext = open_request(key, ctx.frame)
        payload = decode_payload(ctx.plaintext)
        op, params = payload.get("op"), payload.get("params", {})
        if not isinstance(op, str) or not op or not isinstance(params, dict):
            raise SecurityError(ReasonCode.MALFORMED_FRAME, "payload needs 'op' and 'params'")
        ctx.operation = op
        ctx.params = params
