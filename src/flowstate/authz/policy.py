"""RBAC policy: roles grant permissions, operations require one permission.

Deny by default: an unknown role, an unknown operation, or an operation whose
permission the role lacks are all refused.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Policy:
    roles: dict[str, frozenset[str]] = field(default_factory=dict)
    operations: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict) -> "Policy":
        roles = {name: frozenset(perms) for name, perms in data.get("roles", {}).items()}
        operations = dict(data.get("operations", {}))
        for op, perm in operations.items():
            if not isinstance(perm, str) or not perm:
                raise ValueError(f"operation {op!r} needs a permission string")
        return cls(roles, operations)

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        with Path(path).open("rb") as fh:
            return cls.from_dict(tomllib.load(fh))

    def required_permission(self, operation: str) -> str | None:
        return self.operations.get(operation)

    def is_allowed(self, role: str, operation: str) -> bool:
        needed = self.operations.get(operation)
        if needed is None:
            return False
        return needed in self.roles.get(role, frozenset())
