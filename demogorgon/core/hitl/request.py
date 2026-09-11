"""ApprovalRequest — a request for human approval."""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RequestStatus(Enum):
    """Status of an approval request."""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class RequestPriority(Enum):
    """Priority level for approval requests."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ApprovalRequest:
    """A request for human approval before executing an action.

    Attributes:
        id: Unique identifier
        action: The action being requested
        target: Target of the action
        description: Human-readable description
        priority: Priority level
        status: Current status
        context: Additional context (params, headers, etc.)
        created_at: When request was created
        responded_at: When human responded
        notes: Human notes/approval conditions
        deny_reason: Why the request was denied
    """
    id: str = field(default_factory=lambda: secrets.token_hex(8))
    action: str = ""
    target: str = ""
    description: str = ""
    priority: RequestPriority = RequestPriority.MEDIUM
    status: RequestStatus = RequestStatus.PENDING
    context: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    responded_at: float | None = None
    notes: str = ""
    deny_reason: str = ""

    def approve(self, notes: str = "") -> None:
        """Approve this request."""
        self.status = RequestStatus.APPROVED
        self.responded_at = time.time()
        self.notes = notes

    def deny(self, reason: str = "") -> None:
        """Deny this request."""
        self.status = RequestStatus.DENIED
        self.responded_at = time.time()
        self.deny_reason = reason

    def cancel(self) -> None:
        """Cancel this request."""
        self.status = RequestStatus.CANCELLED
        self.responded_at = time.time()

    def is_approved(self) -> bool:
        """Check if this request was approved."""
        return self.status == RequestStatus.APPROVED

    def is_pending(self) -> bool:
        """Check if this request is still pending."""
        return self.status == RequestStatus.PENDING

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "id": self.id,
            "action": self.action,
            "target": self.target,
            "description": self.description,
            "priority": self.priority.value,
            "status": self.status.value,
            "context": self.context,
            "created_at": self.created_at,
            "responded_at": self.responded_at,
            "notes": self.notes,
            "deny_reason": self.deny_reason,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ApprovalRequest:
        """Deserialize from dictionary."""
        return cls(
            id=data.get("id", ""),
            action=data.get("action", ""),
            target=data.get("target", ""),
            description=data.get("description", ""),
            priority=RequestPriority(data.get("priority", "medium")),
            status=RequestStatus(data.get("status", "pending")),
            context=data.get("context", {}),
            created_at=data.get("created_at", 0),
            responded_at=data.get("responded_at"),
            notes=data.get("notes", ""),
            deny_reason=data.get("deny_reason", ""),
        )
