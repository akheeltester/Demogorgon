"""Trust Boundary Mapper — automatically discovers role hierarchy and trust levels.

Generates tests crossing every discovered boundary.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TrustLevel:
    name: str
    level: int
    permissions: list[str] = field(default_factory=list)
    description: str = ""
    discovered_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "level": self.level,
            "permissions": self.permissions,
            "description": self.description,
        }


@dataclass
class TrustBoundary:
    from_level: str
    to_level: str
    boundary_type: str
    endpoint: str = ""
    description: str = ""
    test_generated: bool = False

    def to_dict(self) -> dict:
        return {
            "from_level": self.from_level,
            "to_level": self.to_level,
            "boundary_type": self.boundary_type,
            "endpoint": self.endpoint,
            "description": self.description,
            "test_generated": self.test_generated,
        }


class TrustBoundaryMapper:
    """Automatically discovers role hierarchy and trust boundaries.

    When a new role or access pattern is discovered, updates the trust model
    and generates boundary crossing tests.
    """

    def __init__(self):
        self.levels: dict[str, TrustLevel] = {}
        self.boundaries: list[TrustBoundary] = []
        self._test_queue: list[dict[str, Any]] = []
        self._default_hierarchy = [
            ("anonymous", 0, []),
            ("guest", 1, ["view_public"]),
            ("employee", 2, ["view_own", "edit_own", "view同事们"]),
            ("moderator", 3, ["moderate_content", "view_all"]),
            ("manager", 4, ["approve_leave", "view_team", "edit_team"]),
            ("hr", 5, ["view_all_employees", "edit_employees", "manage_benefits"]),
            ("admin", 6, ["full_access", "manage_users", "manage_settings"]),
            ("superadmin", 7, ["system_admin", "manage_admins"]),
            ("internal_api", 8, ["backend_services"]),
            ("cloud", 9, ["infrastructure"]),
        ]
        self._init_defaults()

    def _init_defaults(self):
        for name, level, perms in self._default_hierarchy:
            self.levels[name] = TrustLevel(name=name, level=level, permissions=perms)

    def discover_role(self, role_name: str, level: int | None = None) -> TrustLevel:
        if role_name in self.levels:
            return self.levels[role_name]
        if level is None:
            existing_levels = [t.level for t in self.levels.values()]
            level = max(existing_levels) + 1 if existing_levels else 1
        tl = TrustLevel(name=role_name, level=level)
        self.levels[role_name] = tl
        self._generate_boundary_tests_for(role_name)
        return tl

    def add_boundary(self, boundary: TrustBoundary) -> None:
        self.boundaries.append(boundary)
        self._generate_boundary_test(boundary)

    def _generate_boundary_tests_for(self, role_name: str) -> None:
        for other_name, other_level in self.levels.items():
            if other_name == role_name:
                continue
            if self.levels[role_name].level < other_level.level:
                self._test_queue.append({
                    "type": "privilege_escalation",
                    "from_role": role_name,
                    "to_role": other_name,
                    "description": f"Test if {role_name} can access {other_name} resources",
                })
            elif self.levels[role_name].level > other_level.level:
                self._test_queue.append({
                    "type": "horizontal_access",
                    "from_role": role_name,
                    "to_role": other_name,
                    "description": f"Test if {role_name} can access {other_name} resources",
                })

    def _generate_boundary_test(self, boundary: TrustBoundary) -> None:
        self._test_queue.append({
            "type": f"boundary_{boundary.boundary_type}",
            "from": boundary.from_level,
            "to": boundary.to_level,
            "endpoint": boundary.endpoint,
            "description": boundary.description,
        })

    def get_tests_for_role(self, role: str) -> list[dict[str, Any]]:
        return [t for t in self._test_queue if t.get("from_role") == role or t.get("from") == role]

    def get_all_pending_tests(self) -> list[dict[str, Any]]:
        return [t for t in self._test_queue if not t.get("executed")]

    def mark_test_executed(self, test: dict[str, Any]) -> None:
        test["executed"] = True

    def get_role_hierarchy(self) -> list[dict[str, Any]]:
        sorted_levels = sorted(self.levels.values(), key=lambda t: t.level)
        return [t.to_dict() for t in sorted_levels]

    def get_cross_boundary_tests(self) -> list[dict[str, Any]]:
        tests = []
        roles = sorted(self.levels.keys(), key=lambda r: self.levels[r].level)
        for i, low_role in enumerate(roles):
            for high_role in roles[i+1:]:
                tests.append({
                    "from_role": low_role,
                    "from_level": self.levels[low_role].level,
                    "to_role": high_role,
                    "to_level": self.levels[high_role].level,
                    "test_type": "vertical_privilege_escalation",
                })
        return tests

    def to_dict(self) -> dict:
        return {
            "levels": {k: v.to_dict() for k, v in self.levels.items()},
            "boundaries": [b.to_dict() for b in self.boundaries],
            "pending_tests": len(self.get_all_pending_tests()),
        }
