"""Scope Matcher — checks whether assets are in scope.

Supports:
- Exact domain matching
- Wildcard domain matching
- URL matching
- IP range matching
- Subdomain matching
"""

from __future__ import annotations

import ipaddress
import fnmatch
from urllib.parse import urlparse
from ..engagement import ScopeAsset


class ScopeMatcher:
    """Matches assets against scope rules.

    Usage:
        matcher = ScopeMatcher(in_scope_assets, out_of_scope_assets)
        result = matcher.match("api.example.com")
        # result.in_scope = True
        # result.reason = "Matches wildcard: *.example.com"
    """

    def __init__(
        self,
        in_scope: list[ScopeAsset],
        out_of_scope: list[ScopeAsset] | None = None,
    ):
        self._in_scope = in_scope
        self._out_of_scope = out_of_scope or []

    def match(self, target: str) -> MatchResult:
        """Check if a target is in scope.

        Args:
            target: A URL, domain, IP, or other asset identifier

        Returns:
            MatchResult with in_scope status and reason
        """
        normalized = self._normalize_target(target)
        
        # Check out-of-scope first (explicit exclusions win)
        for asset in self._out_of_scope:
            if self._matches_asset(normalized, asset):
                return MatchResult(
                    in_scope=False,
                    reason=f"Explicitly out of scope: {asset.pattern}",
                    matched_asset=asset,
                )
        
        # Check in-scope
        for asset in self._in_scope:
            if self._matches_asset(normalized, asset):
                return MatchResult(
                    in_scope=True,
                    reason=f"Matches scope: {asset.pattern}",
                    matched_asset=asset,
                )
        
        return MatchResult(
            in_scope=False,
            reason="No matching scope rule found",
            matched_asset=None,
        )

    def _normalize_target(self, target: str) -> str:
        """Normalize a target for matching."""
        # Extract hostname from URL
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            return parsed.hostname.lower().rstrip('.') if parsed.hostname else target
        
        return target.lower().strip().rstrip('.')

    def _matches_asset(self, target: str, asset: ScopeAsset) -> bool:
        """Check if a target matches a scope asset."""
        pattern = asset.pattern.lower()
        
        if asset.asset_type == "url":
            return self._matches_url(target, pattern)
        elif asset.asset_type == "ip_range":
            return self._matches_ip_range(target, pattern)
        elif asset.asset_type == "subdomain":
            return self._matches_wildcard(target, pattern)
        elif asset.asset_type == "domain":
            return self._matches_domain(target, pattern)
        elif asset.asset_type == "mobile_app":
            return target == pattern
        
        return False

    def _matches_url(self, target: str, pattern: str) -> bool:
        """Match against a URL pattern."""
        # Simple prefix match
        return target.startswith(pattern.replace('https://', '').replace('http://', ''))

    def _matches_ip_range(self, target: str, pattern: str) -> bool:
        """Match against an IP range/CIDR."""
        try:
            target_ip = ipaddress.ip_address(target)
            network = ipaddress.ip_network(pattern, strict=False)
            return target_ip in network
        except ValueError:
            return False

    def _matches_wildcard(self, target: str, pattern: str) -> bool:
        """Match against a wildcard pattern like *.example.com."""
        # pattern is "*.example.com"
        # target should end with ".example.com" or be "example.com"
        base_domain = pattern[2:]  # Remove "*."
        
        if target == base_domain:
            return True
        if target.endswith("." + base_domain):
            return True
        
        # Use fnmatch for more complex patterns
        return fnmatch.fnmatch(target, pattern)

    def _matches_domain(self, target: str, pattern: str) -> bool:
        """Match against an exact domain."""
        return target == pattern


class MatchResult:
    """Result of a scope match."""

    def __init__(self, in_scope: bool, reason: str, matched_asset: ScopeAsset | None):
        self.in_scope = in_scope
        self.reason = reason
        self.matched_asset = matched_asset

    def __repr__(self) -> str:
        return f"MatchResult(in_scope={self.in_scope}, reason={self.reason!r})"

    def __bool__(self) -> bool:
        return self.in_scope
