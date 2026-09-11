"""PauseController — manages pause/resume state of the research loop."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PauseReason(Enum):
    """Why the loop was paused."""
    HUMAN_REQUEST = "human_request"
    APPROVAL_PENDING = "approval_pending"
    RATE_LIMIT = "rate_limit"
    SAFETY_GATE = "safety_gate"
    STAGNATION = "stagnation"
    CHECKPOINT = "checkpoint"
    ERROR = "error"
    MANUAL = "manual"


@dataclass
class PauseEvent:
    """Record of a pause event."""
    reason: PauseReason
    message: str = ""
    timestamp: float = field(default_factory=time.time)
    context: dict[str, Any] = field(default_factory=dict)


@dataclass
class PauseController:
    """Manages pause/resume state of the research loop.

    The loop checks `is_paused` before each iteration.
    If paused, it waits until resumed.

    Usage:
        controller = PauseController()

        # In the loop:
        if controller.is_paused:
            await controller.wait_for_resume()

        # From CLI or signal handler:
        controller.pause(PauseReason.HUMAN_REQUEST)
        controller.resume()
    """
    is_paused: bool = False
    pause_reason: PauseReason | None = None
    pause_message: str = ""
    pause_timestamp: float | None = None
    pause_history: list[PauseEvent] = field(default_factory=list)
    _resume_events: dict[int, Any] = field(default_factory=dict)

    def pause(
        self,
        reason: PauseReason = PauseReason.HUMAN_REQUEST,
        message: str = "",
        context: dict[str, Any] | None = None,
    ) -> None:
        """Pause the research loop."""
        self.is_paused = True
        self.pause_reason = reason
        self.pause_message = message
        self.pause_timestamp = time.time()

        event = PauseEvent(reason=reason, message=message, context=context or {})
        self.pause_history.append(event)

    def resume(self, message: str = "") -> None:
        """Resume the research loop."""
        self.is_paused = False
        self.pause_reason = None
        self.pause_message = ""
        self.pause_timestamp = None

    async def wait_for_resume(self, check_interval: float = 1.0) -> None:
        """Wait until the loop is resumed.

        This should be called when `is_paused` is True.
        It polls at `check_interval` seconds until resumed.
        """
        import asyncio

        while self.is_paused:
            await asyncio.sleep(check_interval)

    def get_pause_duration(self) -> float | None:
        """Get how long the loop has been paused (in seconds)."""
        if not self.is_paused or self.pause_timestamp is None:
            return None
        return time.time() - self.pause_timestamp

    def get_resume_event(self, event_id: int) -> Any:
        """Get a resume event by ID (for asyncio.Event usage)."""
        return self._resume_events.get(event_id)

    def get_history(self) -> list[dict[str, Any]]:
        """Get pause history as list of dicts."""
        return [
            {
                "reason": e.reason.value,
                "message": e.message,
                "timestamp": e.timestamp,
            }
            for e in self.pause_history
        ]

    def get_summary(self) -> dict[str, Any]:
        """Get pause state summary."""
        return {
            "is_paused": self.is_paused,
            "reason": self.pause_reason.value if self.pause_reason else None,
            "message": self.pause_message,
            "duration": self.get_pause_duration(),
            "history_count": len(self.pause_history),
        }
