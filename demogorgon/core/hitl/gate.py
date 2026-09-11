"""HITLGate — decision gate that can require human approval.

In autonomous mode, decisions are made by the LLM and executed.
In HITL mode, certain actions (especially active exploitation)
require human approval before execution.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Awaitable

from .request import ApprovalRequest, RequestPriority, RequestStatus

logger = logging.getLogger(__name__)


class ApprovalLevel(Enum):
    """How much human oversight is required."""
    NONE = "none"             # Fully autonomous, no approval needed
    ADVISORY = "advisory"     # Log for review but don't block
    REQUIRED = "required"     # Block until human approves
    EXCLUSIVE = "exclusive"   # Human must approve everything


# Actions that are safe to run autonomously
SAFE_ACTIONS = {
    "observe",
    "scan",
    "fingerprint",
    "enumerate",
    "recon",
    "crawl",
    "directory_bruteforce",
    "tech_detect",
    "subdomain_enum",
    "waybackurls",
    "gau",
    "katana",
}

# Actions that require human approval
REQUIRES_APPROVAL = {
    "exploit",
    "injection",
    "ssrf",
    "sql_injection",
    "xss_injection",
    "command_injection",
    "csrf",
    "file_upload",
    "privilege_escalation",
    "account_takeover",
    "rce",
    "data_exfiltration",
    "write_request",
    "delete_request",
    "modify_request",
    "mass_assignment",
    "idor_modify",
    "idor_delete",
}


@dataclass
class HITLGate:
    """Decision gate for human-in-the-loop control.

    Determines whether an action can proceed autonomously,
    requires human approval, or should be blocked entirely.

    Attributes:
        approval_level: Global approval level
        safe_actions: Actions allowed without approval
        blocked_actions: Actions that are always blocked
        custom_callbacks: Async callbacks for approval requests
        pending_requests: Requests waiting for human response
        max_pending: Maximum pending requests before pausing
    """
    approval_level: ApprovalLevel = ApprovalLevel.REQUIRED
    safe_actions: set[str] = field(default_factory=lambda: set(SAFE_ACTIONS))
    blocked_actions: set[str] = field(default_factory=set)
    custom_callbacks: dict[str, Callable[..., Awaitable[ApprovalRequest]]] = field(
        default_factory=dict
    )
    pending_requests: list[ApprovalRequest] = field(default_factory=list)
    max_pending: int = 10
    _approval_callback: Callable[[ApprovalRequest], Awaitable[ApprovalRequest]] | None = None

    def set_approval_callback(
        self, callback: Callable[[ApprovalRequest], Awaitable[ApprovalRequest]]
    ) -> None:
        """Set the callback function for approval requests."""
        self._approval_callback = callback

    def should_allow(self, action: str, context: dict[str, Any] | None = None) -> bool:
        """Quick check: should this action be allowed?

        Returns True if safe, False if needs approval or is blocked.
        Use requires_approval() for more detailed routing.
        """
        action_lower = action.lower()

        if action_lower in self.blocked_actions:
            return False

        if self.approval_level == ApprovalLevel.NONE:
            return True

        if action_lower in self.safe_actions:
            return True

        return False

    def requires_approval(self, action: str) -> tuple[bool, str]:
        """Check if action needs human approval.

        Returns (needs_approval, reason).
        """
        action_lower = action.lower()

        if action_lower in self.blocked_actions:
            return True, f"Action '{action}' is explicitly blocked"

        if self.approval_level == ApprovalLevel.NONE:
            return False, "Approval not required (autonomous mode)"

        if self.approval_level == ApprovalLevel.EXCLUSIVE:
            return True, "All actions require human approval (exclusive mode)"

        if action_lower in self.safe_actions:
            return False, "Action is in safe_actions list"

        if action_lower in REQUIRES_APPROVAL:
            return True, f"Action '{action}' requires approval (high-risk action)"

        if self.approval_level == ApprovalLevel.REQUIRED:
            return True, f"Action '{action}' requires approval (default: required)"

        return False, "Approval not required (advisory mode)"

    async def request_approval(
        self,
        action: str,
        target: str,
        description: str,
        context: dict[str, Any] | None = None,
        priority: RequestPriority = RequestPriority.MEDIUM,
    ) -> ApprovalRequest:
        """Create and submit an approval request.

        If a callback is set, it will be called.
        Otherwise, the request is queued for manual review.
        """
        needs_approval, reason = self.requires_approval(action)

        if not needs_approval:
            return ApprovalRequest(
                action=action,
                target=target,
                description=description,
                status=RequestStatus.APPROVED,
                context=context or {},
            )

        if action.lower() in self.blocked_actions:
            request = ApprovalRequest(
                action=action,
                target=target,
                description=description,
                context=context or {},
            )
            request.deny(f"Action '{action}' is explicitly blocked")
            return request

        if len(self.pending_requests) >= self.max_pending:
            logger.warning(
                f"Max pending requests ({self.max_pending}) reached. "
                f"Action '{action}' queued but may delay."
            )

        request = ApprovalRequest(
            action=action,
            target=target,
            description=description,
            priority=priority,
            context=context or {},
        )

        if self._approval_callback:
            try:
                result = await self._approval_callback(request)
                return result
            except Exception as e:
                logger.error(f"Approval callback failed: {e}")
                request.status = RequestStatus.DENIED
                request.deny_reason = f"Callback error: {e}"
                return request

        # No callback — queue for manual review
        self.pending_requests.append(request)
        logger.info(
            f"Approval request queued: {action} on {target} "
            f"(reason: {reason}). Status: {request.status.value}"
        )
        return request

    def approve_request(self, request_id: str, notes: str = "") -> bool:
        """Approve a pending request."""
        for req in self.pending_requests:
            if req.id == request_id:
                req.approve(notes)
                self.pending_requests.remove(req)
                return True
        return False

    def deny_request(self, request_id: str, reason: str = "") -> bool:
        """Deny a pending request."""
        for req in self.pending_requests:
            if req.id == request_id:
                req.deny(reason)
                self.pending_requests.remove(req)
                return True
        return False

    def get_pending(self) -> list[ApprovalRequest]:
        """Get all pending approval requests."""
        return list(self.pending_requests)

    def clear_pending(self) -> int:
        """Clear all pending requests. Returns count cleared."""
        count = len(self.pending_requests)
        self.pending_requests.clear()
        return count

    def get_stats(self) -> dict[str, Any]:
        """Get gate statistics."""
        return {
            "approval_level": self.approval_level.value,
            "pending_count": len(self.pending_requests),
            "max_pending": self.max_pending,
            "safe_actions": len(self.safe_actions),
            "blocked_actions": len(self.blocked_actions),
        }
