"""Architecture rules that keep the design honest as the code grows."""

import ast
from pathlib import Path

from flowstate.gateway.runtime import start_stack

ROOT = Path(__file__).resolve().parents[2]
CRYPTO_FACADE = ROOT / "src" / "flowstate" / "core" / "crypto.py"


def python_files():
    for folder in ("src", "attacks", "eval"):
        yield from (ROOT / folder).rglob("*.py")


def imported_modules(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            yield from (a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            yield node.module


def test_only_the_facade_imports_cryptography():
    offenders = [
        str(p.relative_to(ROOT))
        for p in python_files()
        if p != CRYPTO_FACADE
        and any(m == "cryptography" or m.startswith("cryptography.") for m in imported_modules(p))
    ]
    assert offenders == []


def test_pipeline_order_matches_proposal():
    with start_stack() as stack:
        assert stack.gateway.pipeline.stage_names() == [
            "session", "decrypt", "replay", "freshness", "authorization",
        ]
