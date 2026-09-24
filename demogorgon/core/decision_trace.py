"""Decision Trace — structured logs for all autonomous decisions.

Every decision (strategy selection, target prioritization, routing) must be
observable and logged. Decisions can come from Laya, LLM, Deterministic Policy,
or Human.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Decision:
    """A single decision made by the system."""
    decision_type: str  # e.g., 'strategy', 'target_priority', 'reasoning_route'
    source: str         # 'laya', 'llm', 'deterministic', 'human'
    question: str
    options: list[str]
    selected: str
    confidence: float
    reason_code: str
    fallback: bool = False
    
    # Metadata
    decision_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    state_version: int = 0
    
    # Results (populated later)
    tool_executed: str = ""
    result: str = ""
    outcome: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "timestamp": self.timestamp,
            "state_version": self.state_version,
            "decision_type": self.decision_type,
            "source": self.source,
            "question": self.question,
            "options": self.options,
            "selected": self.selected,
            "confidence": self.confidence,
            "reason_code": self.reason_code,
            "fallback": self.fallback,
            "tool_executed": self.tool_executed,
            "result": self.result,
            "outcome": self.outcome,
        }


class DecisionTrace:
    """Tracks all structured decisions made during an engagement."""

    def __init__(self):
        self._decisions: list[Decision] = []

    def record(
        self,
        decision_type: str,
        source: str,
        question: str,
        options: list[str],
        selected: str,
        confidence: float,
        reason_code: str = "",
        fallback: bool = False,
        state_version: int = 0,
    ) -> Decision:
        """Record a new decision."""
        decision = Decision(
            decision_type=decision_type,
            source=source,
            question=question,
            options=options,
            selected=selected,
            confidence=confidence,
            reason_code=reason_code,
            fallback=fallback,
            state_version=state_version,
        )
        self._decisions.append(decision)
        return decision

    def update_result(self, decision_id: str, tool_executed: str = "", result: str = "", outcome: str = ""):
        """Update a decision with its execution results."""
        for d in self._decisions:
            if d.decision_id == decision_id:
                if tool_executed:
                    d.tool_executed = tool_executed
                if result:
                    d.result = result
                if outcome:
                    d.outcome = outcome
                break

    def get_traces(self) -> list[dict[str, Any]]:
        """Get all decisions as a list of dictionaries."""
        return [d.to_dict() for d in self._decisions]

    def get_summary(self) -> str:
        """Get a human-readable summary of recent decisions."""
        if not self._decisions:
            return "No decisions recorded."
            
        lines = [f"DECISION TRACE ({len(self._decisions)} decisions):"]
        for i, d in enumerate(self._decisions[-5:], 1):
            lines.append(f"\nDecision #{i} ({d.decision_type}) by {d.source.upper()}")
            lines.append(f"  Question: {d.question}")
            lines.append(f"  Selected: {d.selected} (Confidence: {d.confidence:.0%})")
            if d.reason_code:
                lines.append(f"  Reason: {d.reason_code}")
            if d.result:
                lines.append(f"  Result: {d.result}")
                
        return "\n".join(lines)
