"""EngagementContext — single runtime context for autonomous research.

All major subsystems receive this context (or a well-defined subset)
instead of passing dozens of unrelated arguments between modules.

This is the single source of truth for the current engagement state
available to any component that needs it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class EngagementContext:
    """Runtime context for an autonomous engagement.

    Composes all the subsystems a research component might need.
    Components should receive the specific subsystems they need,
    but this context provides a convenient way to pass everything.

    Attributes:
        engagement_id: Unique engagement identifier
        target: Primary target URL/domain
        program: Program name (if from bug bounty)
        workspace_dir: Persistent workspace directory
        config: Research configuration
        engagement: Engagement data object
        policy: Program policy (scope, restrictions)
        auth_manager: Authentication manager
        hitl_gate: Human-in-the-loop gate
        safety_gate: Safety/scope enforcement gate
        action_gateway: Action validation gateway
        tool_registry: Available tools registry
        state_manager: State persistence manager
        asset_database: Discovered assets
        application_model: Understanding of the target app
        llm_generate: LLM generate function
    """
    engagement_id: str = ""
    target: str = ""
    program: str = ""
    workspace_dir: str = ""

    # Subsystems (None = not initialized)
    config: Any = None
    engagement: Any = None
    policy: Any = None
    auth_manager: Any = None
    hitl_gate: Any = None
    safety_gate: Any = None
    action_gateway: Any = None
    tool_registry: Any = None
    state_manager: Any = None
    asset_database: Any = None
    application_model: Any = None
    llm_generate: Any = None

    # Runtime state
    auth_headers: dict[str, str] = field(default_factory=dict)
    available_tools: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def get_auth_headers(self) -> dict[str, str]:
        """Get current authentication headers."""
        if self.auth_manager:
            injection = self.auth_manager.get_auth_injection()
            return injection.get("headers", {})
        return self.auth_headers

    def get_auth_cookies(self) -> dict[str, str]:
        """Get current authentication cookies."""
        if self.auth_manager:
            injection = self.auth_manager.get_auth_injection()
            return injection.get("cookies", {})
        return {}

    def is_in_scope(self, target: str) -> bool:
        """Check if a target is in scope."""
        if self.safety_gate:
            check = self.safety_gate.check_url(target)
            return check.allowed
        return True

    def to_summary(self) -> dict[str, Any]:
        """Get a summary of the context."""
        return {
            "engagement_id": self.engagement_id,
            "target": self.target,
            "program": self.program,
            "workspace_dir": self.workspace_dir,
            "has_auth": self.auth_manager is not None,
            "has_safety": self.safety_gate is not None,
            "has_gateway": self.action_gateway is not None,
            "has_tools": self.tool_registry is not None,
            "has_state": self.state_manager is not None,
            "has_llm": self.llm_generate is not None,
            "available_tools": len(self.available_tools),
        }
