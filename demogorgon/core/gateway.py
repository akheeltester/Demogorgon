"""ActionGateway — validates every autonomous action before execution.

Every action proposed by the ResearchBrain MUST pass through this gateway.
The gateway enforces: scope, safety, HITL approval, rate limits, tool capability.

The LLM must never directly bypass this gateway.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class GateResult(Enum):
    """Result of gateway validation."""
    ALLOW = "allow"
    DENY = "deny"
    HITL_REQUIRED = "hitl_required"
    RATE_LIMITED = "rate_limited"


@dataclass
class GateCheck:
    """Result of a gateway check on an action."""
    result: GateResult
    reason: str
    action: str = ""
    target: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    @property
    def allowed(self) -> bool:
        return self.result == GateResult.ALLOW

    def __bool__(self) -> bool:
        return self.allowed


class ActionGateway:
    """The single point of control for all autonomous actions.

    Every action from the ResearchBrain must pass through:
    1. Scope validation (is the target in scope?)
    2. Safety policy (is the action allowed by policy?)
    3. HITL approval (does this require human approval?)
    4. Rate limiting (are we within limits?)
    5. Tool capability (do we have the right tool?)

    Usage:
        gateway = ActionGateway(safety_gate=safety, hitl_gate=hitl)
        check = gateway.validate(action="test_idor", target="https://api.example.com/users/1")
        if check:
            # Proceed with execution
        else:
            # Action blocked
            print(check.reason)
    """

    def __init__(
        self,
        safety_gate: Any = None,
        hitl_gate: Any = None,
        rate_limit_delay: float = 0.0,
        max_actions_per_minute: int = 60,
    ):
        self._safety = safety_gate
        self._hitl = hitl_gate
        self._rate_limit_delay = rate_limit_delay
        self._max_actions_per_minute = max_actions_per_minute

        # Tracking
        self._action_count = 0
        self._action_times: list[float] = []
        self._blocked_actions: list[dict[str, Any]] = []
        self._allowed_actions: list[dict[str, Any]] = []

    async def validate(
        self,
        action: str,
        target: str,
        description: str = "",
        context: dict[str, Any] | None = None,
        auth_headers: dict[str, str] | None = None,
    ) -> GateCheck:
        """Validate an action through all gateway checks.

        Returns GateCheck with result=ALLOW if all checks pass.
        """
        ctx = context or {}

        # 1. Scope check
        if self._safety:
            scope_check = self._safety.check_url(target) if hasattr(self._safety, 'check_url') else None
            if scope_check is not None and not scope_check.allowed:
                self._record_blocked(action, target, "scope", scope_check.reason)
                return GateCheck(
                    result=GateResult.DENY,
                    reason=f"Out of scope: {scope_check.reason}",
                    action=action,
                    target=target,
                )

            # Action-level check
            action_check = self._safety.check_action(action, target) if hasattr(self._safety, 'check_action') else None
            if action_check is not None and not action_check.allowed:
                self._record_blocked(action, target, "policy", action_check.reason)
                return GateCheck(
                    result=GateResult.DENY,
                    reason=f"Policy violation: {action_check.reason}",
                    action=action,
                    target=target,
                )

        # 2. HITL check
        if self._hitl:
            needs_approval, reason = self._hitl.requires_approval(action)
            if needs_approval:
                request = await self._hitl.request_approval(
                    action=action,
                    target=target,
                    description=description or f"Execute {action} on {target}",
                    context=ctx,
                )
                if not request.is_approved():
                    self._record_blocked(action, target, "hitl", reason)
                    return GateCheck(
                        result=GateResult.DENY,
                        reason=f"HITL denied: {request.deny_reason or reason}",
                        action=action,
                        target=target,
                        details={"request_id": request.id},
                    )

        # 3. Rate limit check
        rate_check = self._check_rate_limit()
        if not rate_check.allowed:
            self._record_blocked(action, target, "rate_limit", rate_check.reason)
            return rate_check

        # 4. Record and allow
        self._record_allowed(action, target)
        self._action_count += 1
        self._action_times.append(time.time())

        return GateCheck(
            result=GateResult.ALLOW,
            reason="All gateway checks passed",
            action=action,
            target=target,
        )

    def _check_rate_limit(self) -> GateCheck:
        """Check if we're within rate limits."""
        if self._max_actions_per_minute <= 0:
            return GateCheck(result=GateResult.ALLOW, reason="No rate limit")

        now = time.time()
        self._action_times = [t for t in self._action_times if now - t < 60.0]

        if len(self._action_times) >= self._max_actions_per_minute:
            return GateCheck(
                result=GateResult.RATE_LIMITED,
                reason=f"Rate limit: {len(self._action_times)}/{self._max_actions_per_minute} actions/min",
            )

        return GateCheck(result=GateResult.ALLOW, reason="Within rate limit")

    def _record_blocked(self, action: str, target: str, reason: str, details: str):
        """Record a blocked action for audit."""
        self._blocked_actions.append({
            "action": action,
            "target": target,
            "reason": reason,
            "details": details,
            "timestamp": time.time(),
        })

    def _record_allowed(self, action: str, target: str):
        """Record an allowed action for audit."""
        self._allowed_actions.append({
            "action": action,
            "target": target,
            "timestamp": time.time(),
        })

    def get_stats(self) -> dict[str, Any]:
        """Get gateway statistics."""
        return {
            "total_actions": self._action_count,
            "allowed": len(self._allowed_actions),
            "blocked": len(self._blocked_actions),
            "recent_actions": len(self._action_times),
            "blocked_details": self._blocked_actions[-10:] if self._blocked_actions else [],
        }
