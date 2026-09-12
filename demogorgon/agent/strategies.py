"""Strategy Engine — dynamic research strategies for the agent.

Replaces the fixed explore→validate→exploit cycle with dynamic,
state-aware strategy selection driven by observations and findings.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class AgentStrategy(Enum):
    """Agent research strategies."""
    RECON = "recon"                        # Discover assets, endpoints, tech stack
    EXPLORE = "explore"                    # Map attack surface, test common vulns
    FOCUSED = "focused"                    # Deep-dive on a specific vuln class
    VALIDATE = "validate"                  # Confirm/TP/FP on existing findings
    EXPLOIT = "exploit"                    # Prove impact, extract data, ATO
    CHAIN = "chain"                        # Look for multi-step attack chains
    RECOVERY = "recovery"                  # Recover from errors/failures
    ADAPT = "adapt"                        # Pivot strategy based on new intel


@dataclass
class StrategyState:
    """Current strategy state."""
    strategy: AgentStrategy = AgentStrategy.RECON
    confidence: float = 0.5
    reason: str = "Starting recon"
    cycles_in_strategy: int = 0
    stagnation_count: int = 0
    total_cycles: int = 0

    # Per-strategy stats
    findings_per_strategy: dict[str, int] = field(default_factory=dict)
    evidence_per_strategy: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "strategy": self.strategy.value,
            "confidence": self.confidence,
            "reason": self.reason,
            "cycles_in_strategy": self.cycles_in_strategy,
            "stagnation_count": self.stagnation_count,
            "total_cycles": self.total_cycles,
            "findings_per_strategy": self.findings_per_strategy,
            "evidence_per_strategy": self.evidence_per_strategy,
        }


@dataclass
class StrategyTransition:
    """A recommended strategy transition."""
    from_strategy: AgentStrategy
    to_strategy: AgentStrategy
    reason: str
    confidence: float


# Transition rules: when to move between strategies
TRANSITION_RULES: dict[AgentStrategy, list[dict[str, Any]]] = {
    AgentStrategy.RECON: [
        {"condition": "endpoints_discovered >= 5", "next": AgentStrategy.EXPLORE, "reason": "Enough endpoints mapped"},
        {"condition": "cycles >= 10", "next": AgentStrategy.EXPLORE, "reason": "Recon phase complete"},
    ],
    AgentStrategy.EXPLORE: [
        {"condition": "findings >= 3", "next": AgentStrategy.VALIDATE, "reason": "Findings to validate"},
        {"condition": "stagnation >= 5", "next": AgentStrategy.FOCUSED, "reason": "Exploration stagnant"},
        {"condition": "evidence_count >= 10", "next": AgentStrategy.EXPLOIT, "reason": "Evidence to exploit"},
    ],
    AgentStrategy.FOCUSED: [
        {"condition": "findings >= 2", "next": AgentStrategy.VALIDATE, "reason": "Findings to validate"},
        {"condition": "stagnation >= 3", "next": AgentStrategy.EXPLORE, "reason": "Focus stagnant, explore more"},
    ],
    AgentStrategy.VALIDATE: [
        {"condition": "validated_findings >= 2", "next": AgentStrategy.EXPLOIT, "reason": "Validated findings to exploit"},
        {"condition": "false_positives >= 3", "next": AgentStrategy.EXPLORE, "reason": "Too many FPs, explore different areas"},
        {"condition": "stagnation >= 3", "next": AgentStrategy.EXPLORE, "reason": "Validation stagnant"},
    ],
    AgentStrategy.EXPLOIT: [
        {"condition": "chains >= 1", "next": AgentStrategy.CHAIN, "reason": "Attack chains found"},
        {"condition": "stagnation >= 3", "next": AgentStrategy.EXPLORE, "reason": "Exploitation stagnant"},
        {"condition": "max_impact_proven", "next": AgentStrategy.CHAIN, "reason": "Impact proven, look for chains"},
    ],
    AgentStrategy.CHAIN: [
        {"condition": "stagnation >= 3", "next": AgentStrategy.EXPLORE, "reason": "Chain analysis stagnant"},
        {"condition": "all_chains_exhausted", "next": AgentStrategy.EXPLORE, "reason": "All chains explored"},
    ],
}


class StrategyEngine:
    """Dynamic strategy selection engine.

    Usage:
        engine = StrategyEngine()
        state = engine.evaluate(context)
        if state.strategy != current_strategy:
            # Strategy changed — emit event
    """

    def __init__(self):
        self.state = StrategyState()
        self._history: list[StrategyState] = []

    def evaluate(self, context: dict[str, Any]) -> StrategyState:
        """Evaluate current state and recommend strategy.

        Context should contain:
            - endpoints_discovered: int
            - findings: int
            - validated_findings: int
            - false_positives: int
            - evidence_count: int
            - chains: int
            - consecutive_failures: int
            - tested_vuln_classes: list[str]
            - target_type: str (optional)
        """
        self.state.total_cycles += 1
        self.state.cycles_in_strategy += 1

        # Check stagnation
        if context.get("consecutive_failures", 0) >= 3:
            self.state.stagnation_count += 1
        else:
            self.state.stagnation_count = 0

        # Check transition rules
        transition = self._check_transitions(context)
        if transition:
            old_strategy = self.state.strategy
            self.state.strategy = transition.to_strategy
            self.state.reason = transition.reason
            self.state.confidence = transition.confidence
            self.state.cycles_in_strategy = 0
            self.state.stagnation_count = 0

            logger.info(
                f"Strategy change: {old_strategy.value} -> {transition.to_strategy.value} "
                f"(reason: {transition.reason})"
            )

        return self.state

    def _check_transitions(self, context: dict[str, Any]) -> StrategyTransition | None:
        """Check if any transition rules are satisfied."""
        rules = TRANSITION_RULES.get(self.state.strategy, [])

        for rule in rules:
            if self._evaluate_condition(rule["condition"], context):
                return StrategyTransition(
                    from_strategy=self.state.strategy,
                    to_strategy=rule["next"],
                    reason=rule["reason"],
                    confidence=0.7,
                )

        return None

    def _evaluate_condition(self, condition: str, context: dict[str, Any]) -> bool:
        """Evaluate a transition condition string."""
        try:
            # Simple condition evaluation
            # Format: "variable >= value" or "variable >= value" or "variable"
            parts = condition.split()
            if len(parts) == 3:
                var_name = parts[0]
                op = parts[1]
                value = float(parts[2])

                current = self._get_condition_value(var_name, context)

                if op == ">=":
                    return current >= value
                elif op == ">":
                    return current > value
                elif op == "<=":
                    return current <= value
                elif op == "<":
                    return current < value
                elif op == "==":
                    return current == value
                elif op == "!=":
                    return current != value
            elif len(parts) == 1:
                # Boolean condition
                var_name = parts[0]
                return bool(self._get_condition_value(var_name, context))

        except Exception as e:
            logger.debug(f"Condition evaluation failed for '{condition}': {e}")

        return False

    def _get_condition_value(self, var_name: str, context: dict[str, Any]) -> float:
        """Get the value of a condition variable from context."""
        # Direct context lookup
        if var_name in context:
            val = context[var_name]
            if isinstance(val, (int, float)):
                return float(val)
            if isinstance(val, bool):
                return 1.0 if val else 0.0
            if isinstance(val, list):
                return float(len(val))

        # Special variables
        if var_name == "validated_findings":
            return float(context.get("validated_findings", 0))
        if var_name == "false_positives":
            return float(context.get("false_positives", 0))
        if var_name == "evidence_count":
            return float(context.get("evidence_count", 0))
        if var_name == "chains":
            return float(context.get("chains", 0))
        if var_name == "cycles":
            return float(self.state.total_cycles)
        if var_name == "stagnation":
            return float(self.state.stagnation_count)
        if var_name == "endpoints_discovered":
            return float(context.get("endpoints_discovered", 0))
        if var_name == "findings":
            return float(context.get("findings", 0))
        if var_name == "max_impact_proven":
            return 1.0 if context.get("max_impact_proven", False) else 0.0
        if var_name == "all_chains_exhausted":
            return 1.0 if context.get("all_chains_exhausted", False) else 0.0

        return 0.0

    def get_strategy_context(self) -> dict[str, Any]:
        """Get current strategy state as context for the LLM."""
        return {
            "current_strategy": self.state.strategy.value,
            "strategy_confidence": self.state.confidence,
            "strategy_reason": self.state.reason,
            "cycles_in_strategy": self.state.cycles_in_strategy,
            "stagnation_count": self.state.stagnation_count,
            "total_cycles": self.state.total_cycles,
        }

    def record_finding(self) -> None:
        """Record a finding in the current strategy."""
        key = self.state.strategy.value
        self.state.findings_per_strategy[key] = self.state.findings_per_strategy.get(key, 0) + 1

    def record_evidence(self) -> None:
        """Record evidence in the current strategy."""
        key = self.state.strategy.value
        self.state.evidence_per_strategy[key] = self.state.evidence_per_strategy.get(key, 0) + 1

    def force_strategy(self, strategy: AgentStrategy, reason: str = "Manual override") -> None:
        """Force a strategy change (user override)."""
        old = self.state.strategy
        self.state.strategy = strategy
        self.state.reason = reason
        self.state.cycles_in_strategy = 0
        self.state.stagnation_count = 0
        logger.info(f"Strategy forced: {old.value} -> {strategy.value} (reason: {reason})")

    def to_dict(self) -> dict:
        """Serialize for state persistence."""
        return self.state.to_dict()

    def load_state(self, data: dict) -> None:
        """Load from serialized state."""
        self.state.strategy = AgentStrategy(data.get("strategy", "recon"))
        self.state.confidence = data.get("confidence", 0.5)
        self.state.reason = data.get("reason", "")
        self.state.cycles_in_strategy = data.get("cycles_in_strategy", 0)
        self.state.stagnation_count = data.get("stagnation_count", 0)
        self.state.total_cycles = data.get("total_cycles", 0)
        self.state.findings_per_strategy = data.get("findings_per_strategy", {})
        self.state.evidence_per_strategy = data.get("evidence_per_strategy", {})
