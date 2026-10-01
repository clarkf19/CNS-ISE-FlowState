import itertools
import random

import pytest

from flowstate.core import codec
from flowstate.core.messages import (
    LABEL_CLIENT_HELLO,
    LABEL_REQUEST,
    LABEL_RESPONSE,
    LABEL_SERVER_HELLO,
    ClientHello,
    ErrorFrame,
    MsgType,
    ProtectedRequest,
    ProtectedResponse,
    ServerHello,
    decode_message,
)
from flowstate.core.reasons import ReasonCode, SecurityError


def malformed(fn, *args):
    with pytest.raises(SecurityError) as exc:
        fn(*args)
    assert exc.value.reason is ReasonCode.MALFORMED_FRAME


class TestFields:
    def test_roundtrip(self):
        fields = [b"", b"a", b"\x00" * 300, "ü".encode()]
        assert codec.decode_fields(codec.encode_fields(*fields), 4) == fields

    def test_encoding_is_injective(self):
        # Same concatenation, different field boundaries -> different encodings.
        assert codec.encode_fields(b"ab", b"c") != codec.encode_fields(b"a", b"bc")

    def test_truncation_and_trailing_bytes(self):
        data = codec.encode_fields(b"abc", b"de")
        for cut in range(len(data)):
            malformed(codec.decode_fields, data[:cut], 2)
        malformed(codec.decode_fields, data + b"\x00", 2)
        malformed(codec.decode_fields, data, 3)

    def test_u64(self):
        assert codec.from_u64(codec.u64(2**64 - 1)) == 2**64 - 1
        malformed(codec.u64, -1)
        malformed(codec.u64, 2**64)
        malformed(codec.from_u64, b"\x00" * 7)

    def test_frame_size_limit(self):
        malformed(codec.frame, b"x" * (codec.MAX_FRAME_LEN + 1))


SAMPLES = [
    ClientHello("alice", b"\x01" * 32, b"\x02" * 16, 123, b"\x03" * 64),
    ServerHello(b"\x04" * 16, b"\x05" * 32, b"\x06" * 16, 999, b"\x07" * 64),
    ProtectedRequest(b"\x08" * 16, 7, b"\x09" * 12, 456, b"\x0a" * 40),
    ProtectedResponse(b"\x0b" * 16, 7, b"\x0c" * 12, b"\x0d" * 20),
    ErrorFrame("STALE_REQUEST", "too old"),
]


class TestMessages:
    @pytest.mark.parametrize("msg", SAMPLES, ids=lambda m: type(m).__name__)
    def test_roundtrip(self, msg):
        assert decode_message(msg.encode()) == msg

    def test_unknown_type_and_version(self):
        raw = SAMPLES[0].encode()
        malformed(decode_message, b"\x63" + raw[1:])
        malformed(decode_message, raw[:1] + b"\x09" + raw[2:])
        malformed(decode_message, b"\x01")

    @pytest.mark.parametrize(
        "bad",
        [
            ClientHello("alice", b"\x01" * 31, b"\x02" * 16, 1, b"\x03" * 64),
            ClientHello("alice", b"\x01" * 32, b"\x02" * 15, 1, b"\x03" * 64),
            ClientHello("alice", b"\x01" * 32, b"\x02" * 16, 1, b"\x03" * 63),
            ClientHello("bad id!", b"\x01" * 32, b"\x02" * 16, 1, b"\x03" * 64),
            ProtectedRequest(b"\x08" * 15, 7, b"\x09" * 12, 456, b"\x0a" * 40),
            ProtectedRequest(b"\x08" * 16, 7, b"\x09" * 16, 456, b"\x0a" * 40),
            ProtectedRequest(b"\x08" * 16, 7, b"\x09" * 12, 456, b"\x0a" * 15),
        ],
    )
    def test_field_lengths_validated(self, bad):
        malformed(decode_message, bad.encode())

    def test_aad_covers_every_header_field(self):
        base = SAMPLES[2]
        variants = [
            ProtectedRequest(b"\xff" * 16, base.seq, base.nonce, base.timestamp, base.ciphertext),
            ProtectedRequest(base.session_id, base.seq + 1, base.nonce, base.timestamp, base.ciphertext),
            ProtectedRequest(base.session_id, base.seq, b"\xff" * 12, base.timestamp, base.ciphertext),
            ProtectedRequest(base.session_id, base.seq, base.nonce, base.timestamp + 1, base.ciphertext),
        ]
        assert len({v.aad() for v in variants} | {base.aad()}) == 5

    def test_domain_separation(self):
        assert SAMPLES[2].aad().startswith(LABEL_REQUEST)
        assert SAMPLES[3].aad().startswith(LABEL_RESPONSE)
        assert len({LABEL_CLIENT_HELLO, LABEL_SERVER_HELLO, LABEL_REQUEST, LABEL_RESPONSE}) == 4

    def test_fuzz_never_crashes(self):
        rng = random.Random(1234)
        raws = [m.encode() for m in SAMPLES]
        for raw, _ in itertools.product(raws, range(300)):
            data = bytearray(raw)
            for _ in range(rng.randint(1, 4)):
                data[rng.randrange(len(data))] = rng.randrange(256)
            data = bytes(data[: rng.randint(0, len(data))]) if rng.random() < 0.3 else bytes(data)
            try:
                decode_message(data)
            except SecurityError as exc:
                assert exc.reason is ReasonCode.MALFORMED_FRAME

    def test_msg_type_values_are_stable(self):
        assert [t.value for t in MsgType] == [1, 2, 3, 4, 5]
