from dataclasses import replace
from types import SimpleNamespace

import pytest

from flowstate.core import crypto
from flowstate.core.pipeline import RequestContext
from flowstate.core.reasons import ReasonCode, SecurityError
from flowstate.record.layer import (
    decode_payload,
    encode_payload,
    open_request,
    open_response,
    seal_request,
    seal_response,
)
from flowstate.record.stage import DecryptStage

SID = b"\x01" * 16


@pytest.fixture
def keys():
    return crypto.AeadKey(crypto.random_bytes(32)), crypto.AeadKey(crypto.random_bytes(32))


def reason(fn, *args, **kw):
    with pytest.raises(SecurityError) as exc:
        fn(*args, **kw)
    return exc.value.reason


def test_request_roundtrip(keys):
    c2g, _ = keys
    frame = seal_request(c2g, SID, 1, 1000, "transfer", {"to": "bob", "amount": 1000})
    assert decode_payload(open_request(c2g, frame)) == {
        "op": "transfer", "params": {"to": "bob", "amount": 1000}
    }


def test_fresh_nonce_per_record(keys):
    c2g, _ = keys
    nonces = {seal_request(c2g, SID, i, 0, "balance").nonce for i in range(200)}
    assert len(nonces) == 200


def test_ciphertext_hides_plaintext(keys):
    frame = seal_request(keys[0], SID, 1, 0, "transfer", {"amount": 1000, "to": "bob"})
    assert b"transfer" not in frame.encode() and b"1000" not in frame.encode()


@pytest.mark.parametrize("field", ["session_id", "seq", "nonce", "timestamp", "ciphertext", "tag"])
def test_any_modification_is_modified_message(keys, field):
    c2g, _ = keys
    f = seal_request(c2g, SID, 5, 1000, "transfer", {"amount": 1000})
    ct = bytearray(f.ciphertext)
    if field == "ciphertext":
        ct[0] ^= 1
    if field == "tag":
        ct[-1] ^= 1
    tampered = {
        "session_id": replace(f, session_id=b"\x02" * 16),
        "seq": replace(f, seq=6),
        "nonce": replace(f, nonce=b"\x00" * 12),
        "timestamp": replace(f, timestamp=1001),
        "ciphertext": replace(f, ciphertext=bytes(ct)),
        "tag": replace(f, ciphertext=bytes(ct)),
    }[field]
    assert reason(open_request, c2g, tampered) is ReasonCode.MODIFIED_MESSAGE


def test_direction_keys_not_interchangeable(keys):
    c2g, g2c = keys
    assert reason(open_request, g2c, seal_request(c2g, SID, 1, 0, "balance")) is ReasonCode.MODIFIED_MESSAGE


def test_response_roundtrip_and_binding(keys):
    _, g2c = keys
    resp = seal_response(g2c, SID, 3, {"status": "ok"})
    assert open_response(g2c, resp, session_id=SID, seq=3) == {"status": "ok"}
    assert reason(open_response, g2c, resp, session_id=SID, seq=4) is ReasonCode.MODIFIED_MESSAGE
    bad = replace(resp, ciphertext=resp.ciphertext[:-1] + bytes([resp.ciphertext[-1] ^ 1]))
    assert reason(open_response, g2c, bad, session_id=SID, seq=3) is ReasonCode.MODIFIED_MESSAGE


def test_payload_validation():
    assert reason(decode_payload, b"\xff") is ReasonCode.MALFORMED_FRAME
    assert reason(decode_payload, b"[1]") is ReasonCode.MALFORMED_FRAME
    assert encode_payload({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_decrypt_stage(keys):
    c2g, _ = keys
    session = SimpleNamespace(c2g=c2g)
    good = RequestContext(seal_request(c2g, SID, 1, 0, "balance", {}), 0, session=session)
    DecryptStage().check(good)
    assert good.operation == "balance" and good.params == {}

    missing_op = seal_request(c2g, SID, 1, 0, "", {})
    assert reason(DecryptStage().check, RequestContext(missing_op, 0, session=session)) is ReasonCode.MALFORMED_FRAME
    gone = RequestContext(seal_request(c2g, SID, 1, 0, "balance"), 0, session=SimpleNamespace(c2g=None))
    assert reason(DecryptStage().check, gone) is ReasonCode.EXPIRED_SESSION
