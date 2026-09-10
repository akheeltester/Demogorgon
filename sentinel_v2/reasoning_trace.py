"""Real Reasoning Traces

Every action must include reasoning, hypothesis, confidence, evidence.
This is what separates intelligent testing from random fuzzing.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ReasoningStep:
    """A single step in a reasoning trace."""
    action: str
    reasoning: str
    hypothesis: str
    confidence: float  # 0.0 - 1.0
    evidence_for: list[str] = field(default_factory=list)
    evidence_against: list[str] = field(default_factory=list)
    what_would_confirm: str = ""
    what_would_falsify: str = ""
    result: str = ""
    observation: str = ""
    timestamp: float = field(default_factory=time.time)


class ReasoningTrace:
    """Tracks reasoning for every action taken.

    Forces the researcher to think before acting and evaluate after.
    """

    def __init__(self):
        self._traces: list[ReasoningStep] = []
        self._current: ReasoningStep | None = None

    def begin(self, action: str, reasoning: str, hypothesis: str, confidence: float = 0.5):
        """Start a new reasoning step."""
        self._current = ReasoningStep(
            action=action,
            reasoning=reasoning,
            hypothesis=hypothesis,
            confidence=confidence,
        )

    def add_evidence(self, evidence_for: str | None = None, evidence_against: str | None = None):
        """Add evidence to the current step."""
        if self._current:
            if evidence_for:
                self._current.evidence_for.append(evidence_for)
            if evidence_against:
                self._current.evidence_against.append(evidence_against)

    def set_expectations(self, confirm: str, falsify: str):
        """Set what would confirm or falsify the hypothesis."""
        if self._current:
            self._current.what_would_confirm = confirm
            self._current.what_would_falsify = falsify

    def complete(self, result: str, observation: str):
        """Complete the current reasoning step."""
        if self._current:
            self._current.result = result
            self._current.observation = observation

            # Auto-adjust confidence based on evidence
            if self._current.evidence_for:
                self._current.confidence = min(1.0, self._current.confidence + 0.1 * len(self._current.evidence_for))
            if self._current.evidence_against:
                self._current.confidence = max(0.0, self._current.confidence - 0.15 * len(self._current.evidence_against))

            self._traces.append(self._current)
            self._current = None

    def get_trace(self) -> list[dict]:
        """Get the full reasoning trace."""
        return [{
            "action": s.action,
            "reasoning": s.reasoning,
            "hypothesis": s.hypothesis,
            "confidence": round(s.confidence, 2),
            "evidence_for": s.evidence_for,
            "evidence_against": s.evidence_against,
            "confirm": s.what_would_confirm,
            "falsify": s.what_would_falsify,
            "result": s.result,
            "observation": s.observation,
        } for s in self._traces]

    def get_summary(self) -> str:
        """Get human-readable reasoning summary."""
        if not self._traces:
            return "No reasoning traces yet"

        lines = [f"REASONING TRACE ({len(self._traces)} steps):"]
        for i, s in enumerate(self._traces[-5:], 1):  # Last 5
            lines.append(f"\n{i}. {s.action}")
            lines.append(f"   Hypothesis: {s.hypothesis}")
            lines.append(f"   Confidence: {s.confidence:.0%}")
            if s.evidence_for:
                lines.append(f"   Evidence+: {', '.join(s.evidence_for[:3])}")
            if s.evidence_against:
                lines.append(f"   Evidence-: {', '.join(s.evidence_against[:3])}")
            lines.append(f"   Result: {s.result}")

        return "\n".join(lines)

    def get_high_confidence_traces(self, threshold: float = 0.7) -> list[dict]:
        """Get traces with high confidence findings."""
        return [vars(s) for s in self._traces if s.confidence >= threshold]
