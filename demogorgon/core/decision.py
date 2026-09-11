"""ResearchDecision — typed decision schema for the research brain.

LLM outputs are validated against this schema before reaching the executor.
Malformed output is rejected; never passes unsafe decisions to PlanExecutor.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class ActionType(str, Enum):
    """Types of actions the research brain can propose."""
    RECON = "recon"
    CRAWL = "crawl"
    FUZZ = "fuzz"
    TEST_ENDPOINT = "test_endpoint"
    ANALYZE_JS = "analyze_js"
    ANALYZE_API = "analyze_api"
    TEST_AUTH = "test_auth"
    TEST_IDOR = "test_idor"
    TEST_XSS = "test_xss"
    TEST_SQLI = "test_sqli"
    TEST_SSRF = "test_ssrf"
    TEST_CSRF = "test_csrf"
    TEST_REDIRECT = "test_redirect"
    TEST_UPLOAD = "test_upload"
    INVESTIGATE = "investigate"
    OBSERVE = "observe"
    WAIT = "wait"
    STOP = "stop"
    CUSTOM = "custom"


class ResearchDecision(BaseModel):
    """A validated decision from the LLM reasoning engine.

    The LLM generates JSON; this model validates it.
    Invalid fields fall back to safe defaults.
    """
    action: ActionType = Field(
        default=ActionType.OBSERVE,
        description="Type of action to execute",
    )
    target: str = Field(
        default="",
        description="Specific target URL or endpoint",
        max_length=2048,
    )
    reason: str = Field(
        default="",
        description="Why this is the best next action",
        max_length=2000,
    )
    confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Confidence in this decision (0.0-1.0)",
    )
    priority: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Priority of this action (0.0-1.0)",
    )
    params: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional parameters for the action",
    )
    tool_hint: str = Field(
        default="",
        description="Suggested tool or empty",
    )
    expected_information_gain: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Expected information gain from this action",
    )

    @field_validator("target")
    @classmethod
    def sanitize_target(cls, v: str) -> str:
        """Strip whitespace and limit length."""
        return v.strip()[:2048] if v else ""

    @field_validator("reason")
    @classmethod
    def sanitize_reason(cls, v: str) -> str:
        """Strip and limit length."""
        return v.strip()[:2000] if v else ""

    def to_legacy_decision(self) -> Any:
        """Convert to the existing Decision dataclass for backward compatibility."""
        from .interfaces import Decision as LegacyDecision
        return LegacyDecision(
            action=self.action,
            target=self.target,
            reason=self.reason,
            confidence=self.confidence,
            priority=self.priority,
            params=self.params,
            tool_hint=self.tool_hint,
        )

    @classmethod
    def from_llm_output(cls, raw: dict[str, Any]) -> ResearchDecision:
        """Parse LLM JSON output into a validated ResearchDecision.

        Handles common LLM mistakes:
        - Unknown action types → OBSERVE
        - Missing fields → safe defaults
        - Invalid confidence values → 0.5
        """
        if not isinstance(raw, dict):
            return cls()

        # Normalize action string
        action_str = str(raw.get("action", "observe")).lower().strip()
        try:
            action = ActionType(action_str)
        except ValueError:
            action = ActionType.OBSERVE

        # Safely parse floats
        def safe_float(val: Any, default: float = 0.5) -> float:
            try:
                f = float(val)
                return max(0.0, min(1.0, f))
            except (TypeError, ValueError):
                return default

        return cls(
            action=action,
            target=str(raw.get("target", "")),
            reason=str(raw.get("reason", "")),
            confidence=safe_float(raw.get("confidence"), 0.5),
            priority=safe_float(raw.get("priority"), 0.5),
            params=raw.get("params", {}) if isinstance(raw.get("params"), dict) else {},
            tool_hint=str(raw.get("tool_hint", "")),
            expected_information_gain=safe_float(
                raw.get("expected_information_gain"), 0.5
            ),
        )
