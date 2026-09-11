"""Core Interfaces — contracts for the research brain components.

These interfaces define how the research brain operates:
- Reasoner: LLM-powered reasoning about what to do next
- ExperimentPlanner: Plans controlled experiments
- ExperimentExecutor: Executes experiments safely
- Validator: Validates findings with evidence
- ResearchCase: Persistent reasoning trail

The key principle: deterministic code handles execution and safety,
the LLM provides adaptive reasoning.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from datetime import datetime, timezone


# ─── Decision Types ───────────────────────────────────────────────

class ActionType(Enum):
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
    TEST_Sqli = "test_sqli"
    TEST_SSRF = "test_ssrf"
    TEST_CSRF = "test_csrf"
    TEST_REDIRECT = "test_redirect"
    TEST_UPLOAD = "test_upload"
    INVESTIGATE = "investigate"
    OBSERVE = "observe"
    WAIT = "wait"
    STOP = "stop"
    CUSTOM = "custom"


class Confidence(Enum):
    """Confidence levels for decisions."""
    VERY_LOW = 0.1
    LOW = 0.3
    MEDIUM = 0.5
    HIGH = 0.7
    VERY_HIGH = 0.9


@dataclass
class Decision:
    """A decision from the reasoning engine."""
    action: ActionType
    target: str
    reason: str
    confidence: float = 0.5
    priority: float = 0.5
    params: dict[str, Any] = field(default_factory=dict)
    tool_hint: str = ""  # optional hint for which tool to use
    scope_status: str = "unknown"  # "in_scope", "out_of_scope", "unknown"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "action": self.action.value,
            "target": self.target,
            "reason": self.reason,
            "confidence": self.confidence,
            "priority": self.priority,
            "params": self.params,
            "tool_hint": self.tool_hint,
            "scope_status": self.scope_status,
            "timestamp": self.timestamp,
        }


@dataclass
class Observation:
    """An observation from executing an action."""
    description: str
    source: str  # tool or module that produced this
    data: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.5
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "description": self.description,
            "source": self.source,
            "data": self.data,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
        }


# ─── Research Brain Interfaces ────────────────────────────────────

class Reasoner(ABC):
    """Reasoning engine — decides what to do next.

    The reasoner observes the current state and proposes the next action.
    It does NOT execute anything — it only proposes.
    """

    @abstractmethod
    async def reason(self, context: dict[str, Any]) -> Decision:
        """Analyze context and propose next action.

        Args:
            context: Current state including:
                - engagement: engagement info
                - assets: discovered assets
                - endpoints: discovered endpoints
                - observations: list of Observation
                - hypotheses: list of hypotheses
                - findings: list of findings
                - available_tools: list of available tools
                - scope_status: current scope status

        Returns:
            Decision with the proposed next action
        """
        pass

    @abstractmethod
    async def explain(self, decision: Decision) -> str:
        """Explain why this decision was made."""
        pass


class ExperimentPlanner(ABC):
    """Plans controlled experiments for testing hypotheses."""

    @abstractmethod
    async def plan(self, hypothesis: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        """Create an experiment plan for a hypothesis.

        Args:
            hypothesis: The hypothesis to test
            context: Current state

        Returns:
            Experiment plan with:
                - steps: list of steps to execute
                - preconditions: what must be true
                - expected_outcomes: what we expect to see
                - safety_checks: what to verify before/during
                - evidence_to_collect: what to capture
        """
        pass


class ExperimentExecutor(ABC):
    """Executes experiments safely."""

    @abstractmethod
    async def execute(self, plan: dict[str, Any]) -> dict[str, Any]:
        """Execute an experiment plan.

        Args:
            plan: The experiment plan from ExperimentPlanner

        Returns:
            Execution results with:
                - observations: what was observed
                - evidence: captured evidence
                - success: whether execution completed
                - error: any errors encountered
        """
        pass


class Validator(ABC):
    """Validates findings with evidence."""

    @abstractmethod
    async def validate(self, evidence: dict[str, Any]) -> dict[str, Any]:
        """Validate evidence and determine if it's a finding.

        Args:
            evidence: Collected evidence

        Returns:
            Validation result with:
                - is_finding: bool
                - confidence: float
                - severity: str
                - title: str
                - description: str
                - impact: str
                - remediation: str
                - false_positive_reason: str (if not a finding)
        """
        pass


# ─── Tool Registry Interface ─────────────────────────────────────

class ToolRegistry(ABC):
    """Registry of available tools."""

    @abstractmethod
    async def discover_all(self) -> dict[str, bool]:
        """Discover all available tools.

        Returns:
            Dict mapping tool name to availability status
        """
        pass

    @abstractmethod
    def get_available_tools(self) -> list[str]:
        """Get list of available tool names."""
        pass

    @abstractmethod
    def get_tool(self, name: str) -> Any:
        """Get a tool by name."""
        pass

    @abstractmethod
    def is_allowed(self, tool_name: str, action: str) -> bool:
        """Check if a tool action is allowed by policy."""
        pass
