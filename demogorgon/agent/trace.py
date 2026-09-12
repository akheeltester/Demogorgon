"""Research Trace — structured decision history for the agent.

Provides a chronological, queryable log of all agent decisions,
actions, evidence, and findings. Enables the LLM to review recent
history and prevents loops.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from pathlib import Path


class TraceEntryType(Enum):
    """Types of trace entries."""
    OBSERVATION = "observation"
    DECISION = "decision"
    ACTION = "action"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    EVIDENCE = "evidence"
    FINDING = "finding"
    FALSE_POSITIVE = "false_positive"
    STRATEGY_CHANGE = "strategy_change"
    ERROR = "error"
    USER_INSTRUCTION = "user_instruction"
    LLM_CALL = "llm_call"
    SAFETY_BLOCK = "safety_block"
    HITL_REQUEST = "hitl_request"
    BUDGET_CHECK = "budget_check"


@dataclass
class TraceEntry:
    """A single entry in the research trace."""
    type: TraceEntryType
    content: str
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    iteration: int = 0
    cycle_id: str = ""

    def to_dict(self) -> dict:
        return {
            "type": self.type.value,
            "content": self.content,
            "data": self.data,
            "timestamp": self.timestamp,
            "iteration": self.iteration,
            "cycle_id": self.cycle_id,
        }

    @classmethod
    def from_dict(cls, d: dict) -> TraceEntry:
        return cls(
            type=TraceEntryType(d["type"]),
            content=d["content"],
            data=d.get("data", {}),
            timestamp=d.get("timestamp", 0.0),
            iteration=d.get("iteration", 0),
            cycle_id=d.get("cycle_id", ""),
        )


class ResearchTrace:
    """Structured, queryable decision history.

    Usage:
        trace = ResearchTrace(max_entries=200)
        trace.add(TraceEntryType.OBSERVATION, "Found /api/users endpoint")
        trace.add(TraceEntryType.DECISION, "Testing IDOR on /api/users", iteration=3)
        recent = trace.get_recent(10)
        summary = trace.get_llm_summary()
    """

    def __init__(self, max_entries: int = 200, workspace_dir: str = ""):
        self._entries: list[TraceEntry] = []
        self._max_entries = max_entries
        self._workspace_dir = workspace_dir

    def add(
        self,
        entry_type: TraceEntryType,
        content: str,
        data: dict[str, Any] | None = None,
        iteration: int = 0,
        cycle_id: str = "",
    ) -> TraceEntry:
        """Add an entry to the trace."""
        entry = TraceEntry(
            type=entry_type,
            content=content,
            data=data or {},
            iteration=iteration,
            cycle_id=cycle_id,
        )
        self._entries.append(entry)

        # Trim to max
        if len(self._entries) > self._max_entries:
            self._entries = self._entries[-self._max_entries:]

        return entry

    def get_recent(self, n: int = 20) -> list[TraceEntry]:
        """Get the N most recent entries."""
        return self._entries[-n:]

    def get_by_type(self, entry_type: TraceEntryType, limit: int = 50) -> list[TraceEntry]:
        """Get entries of a specific type."""
        return [e for e in self._entries if e.type == entry_type][-limit:]

    def get_last_n_actions(self, n: int = 10) -> list[str]:
        """Get the last N action strings for loop detection."""
        actions = []
        for e in reversed(self._entries):
            if e.type in (TraceEntryType.ACTION, TraceEntryType.TOOL_CALL):
                actions.append(e.content)
                if len(actions) >= n:
                    break
        return list(reversed(actions))

    def get_last_n_findings(self, n: int = 10) -> list[TraceEntry]:
        """Get the last N findings."""
        return self.get_by_type(TraceEntryType.FINDING, limit=n)

    def check_for_loops(self, window: int = 5) -> tuple[bool, str]:
        """Detect if the agent is repeating the same actions.

        Returns (is_loop, pattern_description).
        """
        if len(self._entries) < window * 2:
            return False, ""

        recent = self._entries[-window * 2:]
        first_half = [e.content for e in recent[:window]]
        second_half = [e.content for e in recent[window:]]

        if first_half == second_half:
            return True, f"Repeating pattern: {first_half[0][:50]}..."

        # Check for single-action loop
        last_actions = [e.content for e in self._entries[-window:]]
        if len(set(last_actions)) == 1 and window >= 3:
            return True, f"Stuck on single action: {last_actions[0][:50]}..."

        return False, ""

    def get_llm_summary(self, max_entries: int = 15) -> str:
        """Generate a summary suitable for LLM context.

        Returns the last N entries as a compact string.
        """
        recent = self._entries[-max_entries:]
        if not recent:
            return "No trace history yet."

        lines = []
        for entry in recent:
            ts = time.strftime("%H:%M:%S", time.localtime(entry.timestamp))
            marker = {
                TraceEntryType.OBSERVATION: "[OBS]",
                TraceEntryType.DECISION: "[DEC]",
                TraceEntryType.ACTION: "[ACT]",
                TraceEntryType.TOOL_CALL: "[TL]",
                TraceEntryType.TOOL_RESULT: "[RES]",
                TraceEntryType.EVIDENCE: "[EVD]",
                TraceEntryType.FINDING: "[FND]",
                TraceEntryType.FALSE_POSITIVE: "[FP]",
                TraceEntryType.STRATEGY_CHANGE: "[STR]",
                TraceEntryType.ERROR: "[ERR]",
                TraceEntryType.USER_INSTRUCTION: "[USR]",
                TraceEntryType.SAFETY_BLOCK: "[SAF]",
                TraceEntryType.LLM_CALL: "[LLM]",
            }.get(entry.type, "[???]")

            content = entry.content[:200]
            lines.append(f"  {ts} {marker} {content}")

        return "\n".join(lines)

    def save(self, path: str | Path) -> None:
        """Save trace to JSON file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = [e.to_dict() for e in self._entries]
        path.write_text(json.dumps(data, indent=2))

    @classmethod
    def load(cls, path: str | Path, max_entries: int = 200) -> ResearchTrace:
        """Load trace from JSON file."""
        path = Path(path)
        trace = cls(max_entries=max_entries)
        if path.exists():
            data = json.loads(path.read_text())
            trace._entries = [TraceEntry.from_dict(d) for d in data]
        return trace

    def __len__(self) -> int:
        return len(self._entries)

    def __repr__(self) -> str:
        return f"ResearchTrace(entries={len(self._entries)}, max={self._max_entries})"
