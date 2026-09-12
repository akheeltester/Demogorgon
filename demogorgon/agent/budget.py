"""Budget Controller — user-defined limits on cycles, cost, and requests.

Respects budget_limits before each action. No auto-increase.
Exceeding a limit triggers pause+notify, not auto-stop.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class BudgetLimits:
    """User-defined budget limits."""
    max_cycles: int = 100
    max_cost_usd: float = 5.00
    max_requests: int = 500
    max_tokens: int = 500_000
    max_findings: int = 50
    max_duration_seconds: float = 3600.0  # 1 hour
    warning_threshold: float = 0.8  # 80% = warn

    def to_dict(self) -> dict:
        return {
            "max_cycles": self.max_cycles,
            "max_cost_usd": self.max_cost_usd,
            "max_requests": self.max_requests,
            "max_tokens": self.max_tokens,
            "max_findings": self.max_findings,
            "max_duration_seconds": self.max_duration_seconds,
            "warning_threshold": self.warning_threshold,
        }


@dataclass
class BudgetStatus:
    """Current budget consumption status."""
    cycles_used: int = 0
    cost_usd: float = 0.0
    requests_used: int = 0
    tokens_used: int = 0
    findings_count: int = 0
    duration_seconds: float = 0.0

    # Warnings
    warnings: list[str] | None = None

    # Exceeded
    exceeded: list[str] | None = None

    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []
        if self.exceeded is None:
            self.exceeded = []


class BudgetController:
    """Enforces budget limits across the agent lifecycle.

    Usage:
        budget = BudgetController(BudgetLimits(max_cycles=50, max_cost_usd=2.00))
        budget.record_cycle()
        budget.record_cost(0.001)
        status = budget.check()
        if status.exceeded:
            # Pause agent
    """

    def __init__(self, limits: BudgetLimits | None = None):
        self.limits = limits or BudgetLimits()
        self._cycles = 0
        self._cost = 0.0
        self._requests = 0
        self._tokens = 0
        self._findings = 0
        self._start_time = 0.0

    def start(self, start_time: float) -> None:
        """Mark the start time for duration tracking."""
        self._start_time = start_time

    def record_cycle(self) -> None:
        """Record one research cycle completed."""
        self._cycles += 1

    def record_cost(self, cost_usd: float) -> None:
        """Record LLM cost."""
        self._cost += cost_usd

    def record_request(self) -> None:
        """Record one HTTP request."""
        self._requests += 1

    def record_tokens(self, tokens: int) -> None:
        """Record tokens consumed."""
        self._tokens += tokens

    def record_finding(self) -> None:
        """Record one finding discovered."""
        self._findings += 1

    @property
    def duration(self) -> float:
        """Current session duration in seconds."""
        if self._start_time <= 0:
            return 0.0
        import time
        return time.time() - self._start_time

    def check(self) -> BudgetStatus:
        """Check budget status against limits. Returns warnings and exceeded."""
        status = BudgetStatus(
            cycles_used=self._cycles,
            cost_usd=self._cost,
            requests_used=self._requests,
            tokens_used=self._tokens,
            findings_count=self._findings,
            duration_seconds=self.duration,
        )

        warn_pct = self.limits.warning_threshold

        # Cycles
        if self._cycles >= self.limits.max_cycles:
            status.exceeded.append(
                f"Cycles: {self._cycles}/{self.limits.max_cycles} (exceeded)"
            )
        elif self._cycles >= self.limits.max_cycles * warn_pct:
            status.warnings.append(
                f"Cycles: {self._cycles}/{self.limits.max_cycles} ({self._cycles/self.limits.max_cycles*100:.0f}%)"
            )

        # Cost
        if self._cost >= self.limits.max_cost_usd:
            status.exceeded.append(
                f"Cost: ${self._cost:.4f}/${self.limits.max_cost_usd:.2f} (exceeded)"
            )
        elif self._cost >= self.limits.max_cost_usd * warn_pct:
            status.warnings.append(
                f"Cost: ${self._cost:.4f}/${self.limits.max_cost_usd:.2f} ({self._cost/self.limits.max_cost_usd*100:.0f}%)"
            )

        # Requests
        if self._requests >= self.limits.max_requests:
            status.exceeded.append(
                f"Requests: {self._requests}/{self.limits.max_requests} (exceeded)"
            )
        elif self._requests >= self.limits.max_requests * warn_pct:
            status.warnings.append(
                f"Requests: {self._requests}/{self.limits.max_requests} ({self._requests/self.limits.max_requests*100:.0f}%)"
            )

        # Tokens
        if self._tokens >= self.limits.max_tokens:
            status.exceeded.append(
                f"Tokens: {self._tokens:,}/{self.limits.max_tokens:,} (exceeded)"
            )
        elif self._tokens >= self.limits.max_tokens * warn_pct:
            status.warnings.append(
                f"Tokens: {self._tokens:,}/{self.limits.max_tokens:,} ({self._tokens/self.limits.max_tokens*100:.0f}%)"
            )

        # Findings
        if self._findings >= self.limits.max_findings:
            status.exceeded.append(
                f"Findings: {self._findings}/{self.limits.max_findings} (exceeded)"
            )

        # Duration
        dur = self.duration
        if dur >= self.limits.max_duration_seconds:
            status.exceeded.append(
                f"Duration: {dur:.0f}s/{self.limits.max_duration_seconds:.0f}s (exceeded)"
            )
        elif dur >= self.limits.max_duration_seconds * warn_pct:
            status.warnings.append(
                f"Duration: {dur:.0f}s/{self.limits.max_duration_seconds:.0f}s ({dur/self.limits.max_duration_seconds*100:.0f}%)"
            )

        return status

    def should_stop(self) -> tuple[bool, str]:
        """Check if budget exceeded (agent should pause)."""
        status = self.check()
        if status.exceeded:
            return True, "; ".join(status.exceeded)
        return False, ""

    def get_usage_display(self) -> str:
        """Single-line budget usage display."""
        status = self.check()
        parts = []

        if self.limits.max_cycles < 10000:
            parts.append(f"Cycles: {self._cycles}/{self.limits.max_cycles}")
        else:
            parts.append(f"Cycles: {self._cycles}")

        parts.append(f"Cost: ${self._cost:.4f}/${self.limits.max_cost_usd:.2f}")
        parts.append(f"Req: {self._requests}/{self.limits.max_requests}")
        parts.append(f"Tokens: {self._tokens:,}")

        return " | ".join(parts)

    def to_dict(self) -> dict:
        """Serialize for state persistence."""
        return {
            "limits": self.limits.to_dict(),
            "usage": {
                "cycles": self._cycles,
                "cost_usd": self._cost,
                "requests": self._requests,
                "tokens": self._tokens,
                "findings": self._findings,
                "duration": self.duration,
            },
        }
