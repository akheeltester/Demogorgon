"""Attack Surface Builder — classifies endpoints into attack surface categories.

Takes Endpoint objects and classifies them into AttackSurface entries
with risk levels, categories, and state-changing flags.
"""

from __future__ import annotations

import re
from typing import Any

from ..models import Endpoint, AttackSurface


# Category detection patterns
CATEGORY_PATTERNS = {
    "authentication": [
        re.compile(r"/auth", re.IGNORECASE),
        re.compile(r"/login", re.IGNORECASE),
        re.compile(r"/signin", re.IGNORECASE),
        re.compile(r"/signup", re.IGNORECASE),
        re.compile(r"/register", re.IGNORECASE),
        re.compile(r"/oauth", re.IGNORECASE),
        re.compile(r"/sso", re.IGNORECASE),
        re.compile(r"/saml", re.IGNORECASE),
        re.compile(r"/callback", re.IGNORECASE),
    ],
    "api": [
        re.compile(r"/api/", re.IGNORECASE),
        re.compile(r"/v[0-9]+/", re.IGNORECASE),
        re.compile(r"/graphql", re.IGNORECASE),
        re.compile(r"/rest/", re.IGNORECASE),
    ],
    "admin": [
        re.compile(r"/admin", re.IGNORECASE),
        re.compile(r"/dashboard", re.IGNORECASE),
        re.compile(r"/manage", re.IGNORECASE),
        re.compile(r"/console", re.IGNORECASE),
        re.compile(r"/internal", re.IGNORECASE),
    ],
    "user_content": [
        re.compile(r"/upload", re.IGNORECASE),
        re.compile(r"/file", re.IGNORECASE),
        re.compile(r"/image", re.IGNORECASE),
        re.compile(r"/media", re.IGNORECASE),
        re.compile(r"/avatar", re.IGNORECASE),
    ],
    "payment": [
        re.compile(r"/pay", re.IGNORECASE),
        re.compile(r"/billing", re.IGNORECASE),
        re.compile(r"/checkout", re.IGNORECASE),
        re.compile(r"/subscription", re.IGNORECASE),
        re.compile(r"/invoice", re.IGNORECASE),
        re.compile(r"/credit", re.IGNORECASE),
    ],
    "search": [
        re.compile(r"/search", re.IGNORECASE),
        re.compile(r"/query", re.IGNORECASE),
        re.compile(r"/filter", re.IGNORECASE),
    ],
    "user_data": [
        re.compile(r"/user", re.IGNORECASE),
        re.compile(r"/profile", re.IGNORECASE),
        re.compile(r"/account", re.IGNORECASE),
        re.compile(r"/settings", re.IGNORECASE),
        re.compile(r"/preference", re.IGNORECASE),
    ],
    "debug": [
        re.compile(r"/debug", re.IGNORECASE),
        re.compile(r"/trace", re.IGNORECASE),
        re.compile(r"/actuator", re.IGNORECASE),
        re.compile(r"/health", re.IGNORECASE),
        re.compile(r"/metrics", re.IGNORECASE),
        re.compile(r"/env", re.IGNORECASE),
    ],
}

# Risk level calculation weights
RISK_WEIGHTS = {
    "admin": 0.9,
    "authentication": 0.8,
    "payment": 0.85,
    "api": 0.6,
    "user_data": 0.7,
    "user_content": 0.5,
    "search": 0.3,
    "debug": 0.95,
    "other": 0.4,
}

# State-changing methods increase risk
STATE_CHANGING_RISK_BONUS = 0.15

# Authentication requirement increases risk
AUTH_REQUIRED_RISK_BONUS = 0.1


class AttackSurfaceBuilder:
    """Classifies endpoints into an attack surface.

    Usage:
        builder = AttackSurfaceBuilder()
        surfaces = builder.build(endpoints)
        builder.populate_model(app_model, surfaces)
    """

    def build(self, endpoints: list[Endpoint]) -> list[AttackSurface]:
        """Classify a list of Endpoints into AttackSurface entries."""
        surfaces = []
        for endpoint in endpoints:
            surface = self._classify(endpoint)
            surfaces.append(surface)
        return surfaces

    def populate_model(self, surfaces: list[AttackSurface]) -> list[AttackSurface]:
        """Return surfaces for direct addition to ApplicationModel."""
        return surfaces

    def _classify(self, endpoint: Endpoint) -> AttackSurface:
        """Classify a single endpoint."""
        category = self._detect_category(endpoint)
        risk_level = self._calculate_risk(endpoint, category)
        state_changing = endpoint.method.upper() in {"POST", "PUT", "PATCH", "DELETE"}

        return AttackSurface(
            endpoint=endpoint.url,
            method=endpoint.method,
            category=category,
            risk_level=risk_level,
            auth_required=endpoint.auth_required,
            rate_limited=False,
            parameters=endpoint.params,
            state_changing=state_changing,
        )

    def _detect_category(self, endpoint: Endpoint) -> str:
        """Detect the category of an endpoint based on its path."""
        path = endpoint.url

        for category, patterns in CATEGORY_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(path):
                    return category

        return "other"

    def _calculate_risk(self, endpoint: Endpoint, category: str) -> str:
        """Calculate risk level for an endpoint."""
        base_risk = RISK_WEIGHTS.get(category, 0.4)

        # State-changing methods are riskier
        if endpoint.method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
            base_risk += STATE_CHANGING_RISK_BONUS

        # Auth-required endpoints are riskier (more impact if broken)
        if endpoint.auth_required:
            base_risk += AUTH_REQUIRED_RISK_BONUS

        # Cap at 1.0
        base_risk = min(base_risk, 1.0)

        # Map to level string
        if base_risk >= 0.8:
            return "critical"
        elif base_risk >= 0.6:
            return "high"
        elif base_risk >= 0.4:
            return "medium"
        elif base_risk >= 0.2:
            return "low"
        else:
            return "info"
