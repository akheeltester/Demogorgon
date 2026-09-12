"""Event Bus — decoupled event system for agent UI and monitoring.

The agent emits typed events for every significant state change.
UI components subscribe as decoupled consumers — the brain never knows
about the terminal. This enables headless mode, logging, dashboards,
and multi-UI support.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Awaitable

logger = logging.getLogger(__name__)


class EventType(Enum):
    """All agent event types."""
    # Session lifecycle
    SESSION_START = "session.start"
    SESSION_END = "session.end"
    SESSION_RESUME = "session.resume"
    SESSION_ERROR = "session.error"

    # Strategy
    STRATEGY_CHANGE = "strategy.change"
    STRATEGY_EVAL = "strategy.eval"

    # Decision cycle
    DECISION_START = "decision.start"
    DECISION_COMPLETE = "decision.complete"
    DECISION_ERROR = "decision.error"

    # Tool execution
    TOOL_EXECUTE = "tool.execute"
    TOOL_RESULT = "tool.result"
    TOOL_ERROR = "tool.error"

    # Findings
    FINDING = "finding.new"
    FINDING_VALIDATED = "finding.validated"
    FINDING_FALSE_POSITIVE = "finding.false_positive"

    # Evidence
    EVIDENCE_COLLECTED = "evidence.collected"

    # Safety / HITL
    SAFETY_BLOCK = "safety.block"
    HITL_REQUEST = "hitl.request"
    HITL_APPROVED = "hitl.approved"
    HITL_DENIED = "hitl.denied"
    HITL_TIMEOUT = "hitl.timeout"
    USER_INSTRUCTION = "user.instruction"

    # LLM
    LLM_REQUEST = "llm.request"
    LLM_RESPONSE = "llm.response"
    LLM_ERROR = "llm.error"
    LLM_ROUTING = "llm.routing"

    # Budget
    BUDGET_WARNING = "budget.warning"
    BUDGET_EXCEEDED = "budget.exceeded"

    # Progress
    PROGRESS_UPDATE = "progress.update"
    STATUS_CHANGE = "status.change"
    AGENT_THINKING = "agent.thinking"

    # Error
    ERROR = "error"
    WARNING = "warning"

    # Log
    LOG = "log"
    FINDINGS_REPORT = "findings.report"


@dataclass
class AgentEvent:
    """A typed event emitted by the agent."""
    type: EventType
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    source: str = ""  # which component emitted this

    def to_dict(self) -> dict:
        return {
            "type": self.type.value,
            "data": self.data,
            "timestamp": self.timestamp,
            "source": self.source,
        }


# Handler type: async callable that receives an AgentEvent
EventHandler = Callable[[AgentEvent], Awaitable[None]]


class EventBus:
    """Decoupled event system for agent UI and monitoring.

    Components emit events via emit(). UI subscribers receive them
    via on() or once(). The brain never knows about the terminal.

    Usage:
        bus = EventBus()
        bus.on(EventType.FINDING, my_handler)
        await bus.emit(EventType.FINDING, {"title": "XSS", "severity": "high"})
    """

    def __init__(self):
        self._handlers: dict[EventType, list[EventHandler]] = {}
        self._global_handlers: list[EventHandler] = []
        self._history: list[AgentEvent] = []
        self._max_history: int = 500

    def on(self, event_type: EventType, handler: EventHandler) -> None:
        """Subscribe to an event type."""
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        self._handlers[event_type].append(handler)

    def once(self, event_type: EventType, handler: EventHandler) -> None:
        """Subscribe to an event type (auto-unsubscribe after first call)."""
        async def _wrapper(event: AgentEvent):
            self.off(event_type, _wrapper)
            await handler(event)
        self.on(event_type, _wrapper)

    def off(self, event_type: EventType, handler: EventHandler) -> None:
        """Unsubscribe from an event type."""
        if event_type in self._handlers:
            self._handlers[event_type] = [
                h for h in self._handlers[event_type] if h != handler
            ]

    def on_all(self, handler: EventHandler) -> None:
        """Subscribe to all events."""
        self._global_handlers.append(handler)

    async def emit(
        self,
        event_type: EventType,
        data: dict[str, Any] | None = None,
        source: str = "",
    ) -> None:
        """Emit an event to all subscribers."""
        event = AgentEvent(
            type=event_type,
            data=data or {},
            source=source,
        )

        # Record in history
        self._history.append(event)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]

        # Dispatch to type-specific handlers
        handlers = self._handlers.get(event_type, [])
        for handler in handlers:
            try:
                await handler(event)
            except Exception as e:
                logger.error(f"Event handler error for {event_type.value}: {e}")

        # Dispatch to global handlers
        for handler in self._global_handlers:
            try:
                await handler(event)
            except Exception as e:
                logger.error(f"Global event handler error: {e}")

    def get_history(self, event_type: EventType | None = None, limit: int = 50) -> list[AgentEvent]:
        """Get recent events, optionally filtered by type."""
        events = self._history
        if event_type:
            events = [e for e in events if e.type == event_type]
        return events[-limit:]

    def clear_history(self) -> None:
        """Clear event history."""
        self._history.clear()
