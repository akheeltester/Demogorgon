"""Safety Gate — ensures all actions are within scope and policy.

Every active request must pass through the safety gate.
The gate checks:
1. Is the target in scope?
2. Is the action allowed by policy?
3. Are we within rate limits?
4. Are we within request budget?

The gate NEVER assumes authorization.
It always checks before allowing actions.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any
from .matcher import ScopeMatcher, MatchResult
from ..engagement import ScopeAsset, TestingRestriction


@dataclass
class SafetyCheck:
    """Result of a safety check."""
    allowed: bool
    reason: str
    scope_result: MatchResult | None = None
    restriction: TestingRestriction | None = None

    def __bool__(self) -> bool:
        return self.allowed

    def __repr__(self) -> str:
        return f"SafetyCheck(allowed={self.allowed}, reason={self.reason!r})"


class SafetyGate:
    """The single point of control for all active actions.

    Every module that wants to make a request MUST check with the safety gate first.

    Usage:
        gate = SafetyGate(
            in_scope_assets=[...],
            out_of_scope_assets=[...],
            restrictions=[...],
            rate_limit=5.0,
            max_requests=1000,
        )

        check = gate.check_url("https://api.example.com/v1/users")
        if check:
            # Proceed with the request
            ...
        else:
            # Request blocked
            print(check.reason)
    """

    def __init__(
        self,
        in_scope_assets: list[ScopeAsset],
        out_of_scope_assets: list[ScopeAsset] | None = None,
        restrictions: list[TestingRestriction] | None = None,
        rate_limit: float = 5.0,  # requests per second
        max_requests: int = 10000,  # absolute limit
    ):
        self._matcher = ScopeMatcher(in_scope_assets, out_of_scope_assets)
        self._restrictions = restrictions or []
        self._rate_limit = rate_limit
        self._max_requests = max_requests
        
        # Request tracking
        self._request_count = 0
        self._request_times: list[float] = []
        self._blocked_requests: list[dict[str, Any]] = []

    def check_url(self, url: str) -> SafetyCheck:
        """Check if a URL request is allowed."""
        # Scope check
        scope_result = self._matcher.match(url)
        if not scope_result:
            self._log_blocked(url, "out_of_scope", scope_result.reason)
            return SafetyCheck(
                allowed=False,
                reason=f"Out of scope: {scope_result.reason}",
                scope_result=scope_result,
            )
        
        # Rate limit check
        rate_check = self._check_rate_limit()
        if not rate_check:
            self._log_blocked(url, "rate_limited", rate_check.reason)
            return rate_check
        
        # Request budget check
        budget_check = self._check_budget()
        if not budget_check:
            self._log_blocked(url, "budget_exceeded", budget_check.reason)
            return budget_check
        
        # Restriction checks
        restriction_check = self._check_restrictions("request")
        if not restriction_check:
            self._log_blocked(url, "restriction", restriction_check.reason)
            return restriction_check
        
        # Record the request
        self._record_request()
        
        return SafetyCheck(
            allowed=True,
            reason="All safety checks passed",
            scope_result=scope_result,
        )

    def check_action(self, action: str, target: str) -> SafetyCheck:
        """Check if an action is allowed."""
        # Scope check on target
        scope_result = self._matcher.match(target)
        if not scope_result:
            return SafetyCheck(
                allowed=False,
                reason=f"Target out of scope: {scope_result.reason}",
                scope_result=scope_result,
            )
        
        # Action-specific restriction checks
        restriction_check = self._check_restrictions(action)
        if not restriction_check:
            return restriction_check
        
        return SafetyCheck(
            allowed=True,
            reason="Action allowed",
            scope_result=scope_result,
        )

    def _check_rate_limit(self) -> SafetyCheck:
        """Check if we're within rate limits."""
        if self._rate_limit <= 0:
            return SafetyCheck(allowed=True, reason="No rate limit")
        
        now = time.time()
        # Remove requests older than 1 second
        self._request_times = [t for t in self._request_times if now - t < 1.0]
        
        if len(self._request_times) >= self._rate_limit:
            return SafetyCheck(
                allowed=False,
                reason=f"Rate limit exceeded: {len(self._request_times)}/{self._rate_limit} req/s",
            )
        
        return SafetyCheck(allowed=True, reason="Within rate limit")

    def _check_budget(self) -> SafetyCheck:
        """Check if we're within request budget."""
        if self._max_requests <= 0:
            return SafetyCheck(allowed=True, reason="No request budget")
        
        if self._request_count >= self._max_requests:
            return SafetyCheck(
                allowed=False,
                reason=f"Request budget exceeded: {self._request_count}/{self._max_requests}",
            )
        
        return SafetyCheck(allowed=True, reason="Within budget")

    def _check_restrictions(self, action: str) -> SafetyCheck:
        """Check if an action is allowed by policy restrictions."""
        for restriction in self._restrictions:
            if restriction.allowed:
                continue
            
            # Check if this restriction applies to this action
            if self._restriction_applies(restriction, action):
                return SafetyCheck(
                    allowed=False,
                    reason=f"Restricted by policy: {restriction.category} - {restriction.description}",
                    restriction=restriction,
                )
        
        return SafetyCheck(allowed=True, reason="No restrictions apply")

    def _restriction_applies(self, restriction: TestingRestriction, action: str) -> bool:
        """Check if a restriction applies to a given action."""
        category = restriction.category.lower()
        action_lower = action.lower()
        
        # Map actions to restriction categories
        action_category_map = {
            "dos": ["dos", "denial_of_service", "flood", "stress"],
            "social_engineering": ["social_engineering", "phishing", "pretexting"],
            "automated_scanning": ["scan", "automated", "bulk"],
            "physical": ["physical", "lockpicking", "tailgating"],
            "spam": ["spam", "bulk_email", "mass_email"],
        }
        
        categories = action_category_map.get(category, [category])
        return any(cat in action_lower for cat in categories)

    def _record_request(self):
        """Record a request for rate limiting and budgeting."""
        self._request_count += 1
        self._request_times.append(time.time())

    def _log_blocked(self, target: str, reason: str, details: str):
        """Log a blocked request for audit purposes."""
        self._blocked_requests.append({
            "target": target,
            "reason": reason,
            "details": details,
            "timestamp": time.time(),
        })

    def get_stats(self) -> dict[str, Any]:
        """Get safety gate statistics."""
        return {
            "request_count": self._request_count,
            "max_requests": self._max_requests,
            "rate_limit": self._rate_limit,
            "recent_requests": len(self._request_times),
            "blocked_count": len(self._blocked_requests),
        }

    def get_blocked_requests(self) -> list[dict[str, Any]]:
        """Get list of blocked requests for audit."""
        return list(self._blocked_requests)
