"""ResearchContextBuilder — constructs bounded context for LLM reasoning.

The LLM must NOT receive the entire engagement database.
This builder selects only the relevant, non-sensitive data needed
for adaptive decision-making.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Maximum items to include in context to stay within token budget
MAX_OBSERVATIONS = 15
MAX_HYPOTHESES = 8
MAX_FINDINGS = 10
MAX_TESTED_ACTIONS = 30
MAX_ASSETS = 20
MAX_ENDPOINTS = 30


class ResearchContextBuilder:
    """Builds a bounded context dict for LLM reasoning.

    The context includes only what the LLM needs to make a decision:
    - Target and scope
    - Discovered assets and endpoints
    - Recent observations
    - Active hypotheses
    - Confirmed findings
    - What has been tested
    - Available tools
    - Current strategy

    The context NEVER includes:
    - API keys, passwords, tokens
    - Raw HTTP responses with sensitive data
    - Internal system state
    - Implementation details
    """

    def __init__(
        self,
        target: str,
        scope_assets: list[dict[str, Any]] | None = None,
        tools: list[str] | None = None,
    ):
        self.target = target
        self.scope_assets = scope_assets or []
        self.tools = tools or []

    def build(
        self,
        case: Any = None,
        iteration: int = 0,
        strategy: str = "explore",
        tested_actions: set[str] | None = None,
        assets: list[dict[str, Any]] | None = None,
        endpoints: list[dict[str, Any]] | None = None,
        tech_stack: dict[str, str] | None = None,
        auth_state: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Build a bounded research context from case state.

        Returns a dict suitable for passing to the LLM reasoner.
        """
        ctx: dict[str, Any] = {
            "target": self.target,
            "iteration": iteration,
            "strategy": strategy,
        }

        # Scope (redacted — no sensitive details)
        ctx["scope"] = self._format_scope()

        # Assets
        all_assets = assets or []
        ctx["assets"] = all_assets[:MAX_ASSETS]
        ctx["asset_count"] = len(all_assets)

        # Endpoints
        all_endpoints = endpoints or []
        ctx["endpoints"] = all_endpoints[:MAX_ENDPOINTS]
        ctx["endpoint_count"] = len(all_endpoints)

        # Tech stack
        ctx["tech_stack"] = tech_stack or {}

        # Auth state (safe subset)
        ctx["auth_state"] = self._redact_auth(auth_state)

        # Case data
        if case:
            ctx["observations"] = self._format_observations(case)
            ctx["hypotheses"] = self._format_hypotheses(case)
            ctx["findings"] = self._format_findings(case)
        else:
            ctx["observations"] = []
            ctx["hypotheses"] = []
            ctx["findings"] = []

        # Tested actions
        ctx["tested_actions"] = sorted(list(tested_actions or []))[-MAX_TESTED_ACTIONS:]
        ctx["tested_count"] = len(tested_actions or set())

        # Available tools
        ctx["available_tools"] = self.tools

        return ctx

    def _format_scope(self) -> dict[str, Any]:
        """Format scope for LLM (non-sensitive)."""
        return {
            "in_scope": [
                {"pattern": a.get("pattern", ""), "type": a.get("asset_type", "")}
                for a in self.scope_assets
            ],
            "description": "Only test targets matching in-scope patterns",
        }

    def _format_observations(self, case: Any) -> list[dict[str, str]]:
        """Format recent observations for LLM context."""
        obs_list = getattr(case, "observations", [])
        recent = obs_list[-MAX_OBSERVATIONS:]
        return [
            {
                "description": getattr(o, "description", str(o)),
                "source": getattr(o, "source", ""),
            }
            for o in recent
        ]

    def _format_hypotheses(self, case: Any) -> list[dict[str, Any]]:
        """Format active hypotheses for LLM context."""
        hypotheses = getattr(case, "hypotheses", [])
        active = [
            h for h in hypotheses
            if getattr(h, "status", "").value in ("proposed", "testing")
        ]
        return [
            {
                "id": getattr(h, "id", ""),
                "description": getattr(h, "description", ""),
                "vuln_class": getattr(h, "vuln_class", ""),
                "endpoint": getattr(h, "endpoint", ""),
                "status": getattr(h, "status", "").value
                if hasattr(getattr(h, "status", ""), "value")
                else str(getattr(h, "status", "")),
                "confidence": getattr(h, "confidence", 0.3),
            }
            for h in active[-MAX_HYPOTHESES:]
        ]

    def _format_findings(self, case: Any) -> list[dict[str, str]]:
        """Format confirmed findings for LLM context."""
        findings = getattr(case, "findings", [])
        confirmed = [f for f in findings if getattr(f, "confirmed", False)]
        return [
            {
                "title": getattr(f, "title", ""),
                "severity": getattr(f, "severity", ""),
                "vuln_class": getattr(f, "vuln_class", ""),
                "endpoint": getattr(f, "endpoint", ""),
            }
            for f in confirmed[-MAX_FINDINGS:]
        ]

    def _redact_auth(self, auth_state: dict[str, Any] | None) -> dict[str, Any]:
        """Return safe subset of auth state (no secrets)."""
        if not auth_state:
            return {"configured": False}
        return {
            "configured": bool(auth_state),
            "auth_type": auth_state.get("auth_type", "unknown"),
            "session_active": auth_state.get("session_active", False),
        }
