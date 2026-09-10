"""Base Executor — interface for all deterministic executors.

Every executor:
1. Owns its payload library (LLM never creates payloads)
2. Implements test() -> dict with findings, evidence, metadata
3. Is deterministic — same input produces same output
4. Returns structured findings, not raw text
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ExecutorFinding:
    """A finding from an executor."""
    title: str
    severity: str  # critical, high, medium, low, info
    vuln_class: str
    endpoint: str
    evidence: str
    steps: list[str] = field(default_factory=list)
    impact: str = ""
    confidence: float = 0.5
    request: dict[str, Any] | None = None
    response: dict[str, Any] | None = None

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity,
            "vuln_class": self.vuln_class,
            "endpoint": self.endpoint,
            "evidence": self.evidence,
            "steps": self.steps,
            "impact": self.impact,
            "confidence": self.confidence,
        }


@dataclass
class ExecutorResult:
    """Result of an executor test."""
    findings: list[ExecutorFinding]
    evidence: list[dict[str, Any]]
    tested_count: int = 0
    vulnerable: bool = False
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "evidence": self.evidence,
            "tested_count": self.tested_count,
            "vulnerable": self.vulnerable,
            "error": self.error,
        }


class BaseExecutor(ABC):
    """Base class for all deterministic executors.

    Each executor owns its payload library and mutation logic.
    The LLM never creates payloads — it only decides what to test.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Executor name (e.g., 'cors_detector', 'idor_tester')."""
        pass

    @property
    @abstractmethod
    def vuln_class(self) -> str:
        """Vulnerability class (e.g., 'cors', 'idor')."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """What this executor tests."""
        pass

    @abstractmethod
    async def test(self, endpoint: str, **kwargs) -> dict[str, Any]:
        """Execute the test and return results.

        Args:
            endpoint: The URL to test
            **kwargs: Additional parameters (auth_token, id_range, etc.)

        Returns:
            Dict with 'findings', 'evidence', 'vulnerable', 'error'
        """
        pass

    def _create_finding(
        self,
        title: str,
        severity: str,
        endpoint: str,
        evidence: str,
        steps: list[str] | None = None,
        impact: str = "",
        confidence: float = 0.5,
    ) -> ExecutorFinding:
        """Helper to create a finding."""
        return ExecutorFinding(
            title=title,
            severity=severity,
            vuln_class=self.vuln_class,
            endpoint=endpoint,
            evidence=evidence,
            steps=steps or [],
            impact=impact,
            confidence=confidence,
        )
