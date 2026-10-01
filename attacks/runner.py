"""Run every attack scenario against a fresh gateway and print the results.

  python -m attacks.runner [--audit logs/attack_audit.jsonl] [--only replay_request]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from attacks.scenarios import ALL_SCENARIOS, Attack, ScenarioResult
from flowstate.audit import verify_chain
from flowstate.core.clock import OffsetClock
from flowstate.gateway.runtime import start_stack


def run_scenarios(
    names: list[str] | None = None, audit_path: str | Path | None = None
) -> list[ScenarioResult]:
    """Each scenario gets its own stack so clock changes and state cannot leak between them."""
    results = []
    for scenario in ALL_SCENARIOS:
        if names and scenario.__name__ not in names:
            continue
        clock = OffsetClock()
        with start_stack(clock=clock, audit_path=audit_path) as stack:
            results.append(scenario(Attack(stack, clock)))
    return results


def print_table(results: list[ScenarioResult]) -> None:
    print(f"{'scenario':<35}{'expected':<24}{'observed':<24}{'result':<9}legit")
    print("-" * 99)
    for r in results:
        print(
            f"{r.name:<35}{r.expected:<24}{r.observed:<24}"
            f"{'BLOCKED' if r.blocked else 'FAILED':<9}{'ok' if r.legit_ok else 'BROKEN'}"
        )
    blocked = sum(r.blocked for r in results)
    print("-" * 99)
    print(f"{blocked}/{len(results)} attacks blocked; legitimate traffic "
          f"{'unaffected' if all(r.legit_ok for r in results) else 'AFFECTED'}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="attacks.runner")
    parser.add_argument("--audit", help="also write a hash-chained audit log here")
    parser.add_argument("--only", nargs="*", help="scenario names to run")
    args = parser.parse_args(argv)
    if args.audit and Path(args.audit).exists():
        Path(args.audit).unlink()

    results = run_scenarios(args.only, args.audit)
    print_table(results)
    if args.audit:
        chain = verify_chain(args.audit)
        print(f"audit log {args.audit}: {chain.entries} entries, chain {'intact' if chain.ok else 'BROKEN'}")
    return 0 if all(r.blocked and r.legit_ok for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
