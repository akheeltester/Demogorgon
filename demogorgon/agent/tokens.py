"""Token Tracker — live token usage and cost tracking.

Every LLM call goes through the TokenTracker, which records tokens
and cost in real time for the live UI display.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TokenUsage:
    """A single LLM call's token usage."""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    cost_usd: float = 0.0
    provider: str = ""
    model: str = ""
    timestamp: float = field(default_factory=time.time)
    latency_ms: float = 0.0
    cached: bool = False
    error: bool = False

    @property
    def cost_display(self) -> str:
        if self.cost_usd < 0.001:
            return "<$0.001"
        return f"${self.cost_usd:.4f}"

    def to_dict(self) -> dict:
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "cost_usd": self.cost_usd,
            "provider": self.provider,
            "model": self.model,
            "timestamp": self.timestamp,
            "latency_ms": self.latency_ms,
            "cached": self.cached,
            "error": self.error,
        }


# Approximate costs per 1M tokens (USD)
DEFAULT_COST_TABLE: dict[str, dict[str, float]] = {
    "openai": {
        "gpt-4o": {"input": 2.50, "output": 10.00},
        "gpt-4o-mini": {"input": 0.15, "output": 0.60},
        "gpt-4-turbo": {"input": 10.00, "output": 30.00},
        "gpt-3.5-turbo": {"input": 0.50, "output": 1.50},
    },
    "anthropic": {
        "claude-sonnet-4-20250514": {"input": 3.00, "output": 15.00},
        "claude-3-5-sonnet-20241022": {"input": 3.00, "output": 15.00},
        "claude-3-5-haiku-20241022": {"input": 0.80, "output": 4.00},
        "claude-3-haiku-20240307": {"input": 0.25, "output": 1.25},
    },
    "openrouter": {
        "nvidia/nemotron-3-super-120b-a12b:free": {"input": 0.0, "output": 0.0},
        "default": {"input": 1.00, "output": 3.00},
    },
    "deepseek": {
        "deepseek-chat": {"input": 0.14, "output": 0.28},
        "default": {"input": 0.14, "output": 0.28},
    },
    "gemini": {
        "gemini-2.0-flash": {"input": 0.075, "output": 0.30},
        "gemini-1.5-pro": {"input": 1.25, "output": 5.00},
        "default": {"input": 0.075, "output": 0.30},
    },
    "ollama": {
        "default": {"input": 0.0, "output": 0.0},
    },
}


class TokenTracker:
    """Tracks token usage and cost across all LLM calls.

    Usage:
        tracker = TokenTracker()
        tracker.record(TokenUsage(prompt_tokens=100, completion_tokens=50, cost_usd=0.001))
        print(tracker.totals_display)
    """

    def __init__(self, cost_table: dict | None = None):
        self._usages: list[TokenUsage] = []
        self._cost_table = cost_table or DEFAULT_COST_TABLE

    def record(self, usage: TokenUsage) -> None:
        """Record a single LLM call's token usage."""
        self._usages.append(usage)

    def record_call(
        self,
        provider: str,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        latency_ms: float = 0.0,
        cached: bool = False,
        error: bool = False,
    ) -> TokenUsage:
        """Record a call and compute cost automatically."""
        cost = self._compute_cost(provider, model, prompt_tokens, completion_tokens, cached)
        usage = TokenUsage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
            cost_usd=cost,
            provider=provider,
            model=model,
            latency_ms=latency_ms,
            cached=cached,
            error=error,
        )
        self.record(usage)
        return usage

    def _compute_cost(
        self,
        provider: str,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        cached: bool = False,
    ) -> float:
        """Compute cost in USD for a single call."""
        provider_costs = self._cost_table.get(provider, {})
        model_costs = provider_costs.get(model, provider_costs.get("default", {}))

        if not model_costs:
            return 0.0

        input_cost_per_token = model_costs.get("input", 0.0) / 1_000_000
        output_cost_per_token = model_costs.get("output", 0.0) / 1_000_000

        # Cache discount (most providers charge 50% less for cached input)
        if cached:
            input_cost_per_token *= 0.5

        return (prompt_tokens * input_cost_per_token) + (completion_tokens * output_cost_per_token)

    @property
    def total_tokens(self) -> int:
        return sum(u.total_tokens for u in self._usages)

    @property
    def total_prompt_tokens(self) -> int:
        return sum(u.prompt_tokens for u in self._usages)

    @property
    def total_completion_tokens(self) -> int:
        return sum(u.completion_tokens for u in self._usages)

    @property
    def total_cost(self) -> float:
        return sum(u.cost_usd for u in self._usages)

    @property
    def total_calls(self) -> int:
        return len(self._usages)

    @property
    def avg_latency(self) -> float:
        if not self._usages:
            return 0.0
        return sum(u.latency_ms for u in self._usages) / len(self._usages)

    @property
    def totals_display(self) -> str:
        return (
            f"Tokens: {self.total_tokens:,} "
            f"({self.total_prompt_tokens:,} in / {self.total_completion_tokens:,} out) "
            f"| Cost: ${self.total_cost:.4f} "
            f"| Calls: {self.total_calls}"
        )

    @property
    def live_display(self) -> str:
        """Single-line live display for the terminal."""
        cost = self.total_cost
        if cost < 0.01:
            cost_str = f"${cost:.4f}"
        elif cost < 1.0:
            cost_str = f"${cost:.3f}"
        else:
            cost_str = f"${cost:.2f}"
        return (
            f"Tokens: {self.total_tokens:,} | "
            f"Cost: {cost_str} | "
            f"Calls: {self.total_calls}"
        )

    def get_by_provider(self) -> dict[str, dict[str, Any]]:
        """Get totals broken down by provider."""
        by_provider: dict[str, dict[str, Any]] = {}
        for usage in self._usages:
            if usage.provider not in by_provider:
                by_provider[usage.provider] = {
                    "calls": 0, "tokens": 0, "cost": 0.0,
                }
            by_provider[usage.provider]["calls"] += 1
            by_provider[usage.provider]["tokens"] += usage.total_tokens
            by_provider[usage.provider]["cost"] += usage.cost_usd
        return by_provider

    def reset(self) -> None:
        """Reset all tracking data."""
        self._usages.clear()

    def to_dict(self) -> dict:
        """Serialize for state persistence."""
        return {
            "total_tokens": self.total_tokens,
            "total_cost": self.total_cost,
            "total_calls": self.total_calls,
            "by_provider": self.get_by_provider(),
            "recent": [u.to_dict() for u in self._usages[-20:]],
        }
