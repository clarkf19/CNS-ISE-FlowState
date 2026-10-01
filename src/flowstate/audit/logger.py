"""Security event logger (proposal section 4.3(f)).

Each accepted or rejected request becomes one JSON line holding the time,
client ID, session ID, operation and reason code. Entries are hash-chained:

    hash_n = SHA-256(hash_{n-1} || canonical_json(entry_n without "hash"))

so editing, deleting or reordering any entry breaks verification from that
point on. Only fields of SecurityEvent are written: key material and request
plaintext never reach the log.
"""

from __future__ import annotations

import json
import threading
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from flowstate.core import crypto
from flowstate.core.events import SecurityEvent

GENESIS_HASH = "0" * 64
MAX_DETAIL_LEN = 200


def _canonical(entry: dict) -> bytes:
    return json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()


def _entry_hash(prev_hash: str, body: dict) -> str:
    return crypto.sha256(prev_hash.encode() + _canonical(body)).hex()


class AuditLogger:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.counters: Counter[str] = Counter()
        self._lock = threading.Lock()
        self._index, self._prev_hash = 0, GENESIS_HASH
        if self.path.exists():  # continue an existing chain
            for entry in read_entries(self.path):
                self._index, self._prev_hash = entry["index"], entry["hash"]

    def record(self, event: SecurityEvent) -> None:
        body = event.to_dict()
        body["detail"] = body["detail"][:MAX_DETAIL_LEN]
        body["time"] = datetime.fromtimestamp(
            event.timestamp_ms / 1000, tz=timezone.utc
        ).isoformat(timespec="milliseconds")
        with self._lock:
            body["index"] = self._index + 1
            body["prev_hash"] = self._prev_hash
            body["hash"] = _entry_hash(self._prev_hash, body)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(body, sort_keys=True) + "\n")
            self._index, self._prev_hash = body["index"], body["hash"]
            self.counters[event.reason.value] += 1


def read_entries(path: str | Path) -> list[dict]:
    with Path(path).open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


@dataclass
class ChainVerification:
    ok: bool
    entries: int
    first_bad_line: int | None = None
    problem: str = ""


def verify_chain(path: str | Path) -> ChainVerification:
    prev, expected_index, count = GENESIS_HASH, 1, 0
    with Path(path).open(encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                stored = entry.pop("hash")
            except (json.JSONDecodeError, KeyError):
                return ChainVerification(False, count, line_no, "unparseable entry")
            if entry.get("prev_hash") != prev:
                return ChainVerification(False, count, line_no, "chain link broken")
            if entry.get("index") != expected_index:
                return ChainVerification(False, count, line_no, "entry missing or reordered")
            if _entry_hash(prev, entry) != stored:
                return ChainVerification(False, count, line_no, "entry contents modified")
            prev, expected_index, count = stored, expected_index + 1, count + 1
    return ChainVerification(True, count)
