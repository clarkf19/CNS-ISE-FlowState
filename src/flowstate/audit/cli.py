"""Audit log tools.

  flowstate-audit verify  [--log logs/audit.jsonl]
  flowstate-audit summary [--log ...]
  flowstate-audit show    [--log ...] [--reason MODIFIED_MESSAGE] [--client alice] [--limit 20]
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter

from flowstate.audit.logger import read_entries, verify_chain


def summarize(entries: list[dict]) -> dict:
    reasons = Counter(e["reason"] for e in entries)
    rejected = sum(n for r, n in reasons.items() if r != "ACCEPTED")
    return {
        "total": len(entries),
        "accepted": reasons.get("ACCEPTED", 0),
        "rejected": rejected,
        "by_reason": dict(sorted(reasons.items())),
        "by_client": dict(sorted(Counter(e.get("client_id") or "-" for e in entries).items())),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="flowstate-audit")
    parser.add_argument("cmd", choices=["verify", "summary", "show"])
    parser.add_argument("--log", default="logs/audit.jsonl")
    parser.add_argument("--reason")
    parser.add_argument("--client")
    parser.add_argument("--limit", type=int, default=20)
    args = parser.parse_args(argv)

    if args.cmd == "verify":
        result = verify_chain(args.log)
        if result.ok:
            print(f"OK: {result.entries} entries, hash chain intact")
            return 0
        print(f"TAMPERED at line {result.first_bad_line}: {result.problem}")
        return 1

    entries = read_entries(args.log)
    if args.cmd == "summary":
        s = summarize(entries)
        print(f"total={s['total']} accepted={s['accepted']} rejected={s['rejected']}")
        for reason, n in s["by_reason"].items():
            print(f"  {reason:<24}{n}")
        return 0

    shown = [
        e for e in entries
        if (not args.reason or e["reason"] == args.reason)
        and (not args.client or e.get("client_id") == args.client)
    ][-args.limit:]
    for e in shown:
        print(
            f"{e['time']}  {e['phase']:<9} {e['reason']:<24} client={e.get('client_id') or '-':<8} "
            f"op={e.get('operation') or '-':<14} {e.get('detail', '')}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
