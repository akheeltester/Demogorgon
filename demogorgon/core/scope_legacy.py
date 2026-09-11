"""ScopeValidator — the single source of truth for scope checks.

Every module that checks whether a URL or hostname is in scope MUST use this
class. No more ad-hoc substring matching.

NOTE: This is the legacy ScopeValidator. For new code, use:
    - demogorgon.core.scope.matcher.ScopeMatcher (for matching)
    - demogorgon.core.scope.safety.SafetyGate (for safety checks)
    - demogorgon.core.scope.parser.parse_program_policy (for parsing)

This class is preserved for backward compatibility with existing researchers.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse


class ScopeValidator:
    """Hostname-aware scope validator.

    Usage:
        sv = ScopeValidator("https://example.com", extra_scopes=["api.example.com"])
        sv.in_scope("https://api.example.com/v1")  # True
        sv.in_scope("https://evil-example.com")     # False

    Rules:
        - Exact hostname match
        - Subdomain match (api.example.com matches example.com)
        - Extra scopes (explicit additional hostnames)
        - IP addresses matched when target is an IP
        - Ports are ignored for matching
        - Trailing dots stripped
        - Case-insensitive
    """

    def __init__(
        self,
        target_url: str,
        extra_scopes: list[str] | None = None,
        excluded_hosts: list[str] | None = None,
    ):
        self._target_url = target_url
        self._target_host = self._extract_host(target_url)
        self._extra_hosts: set[str] = set()
        self._excluded_hosts: set[str] = set()

        for extra in extra_scopes or []:
            host = self._extract_host(extra)
            if host:
                self._extra_hosts.add(host)

        for excl in excluded_hosts or []:
            host = self._extract_host(excl)
            if host:
                self._excluded_hosts.add(host)

    @property
    def target_host(self) -> str:
        return self._target_host

    @property
    def all_hosts(self) -> set[str]:
        """All in-scope hostnames (target + extras)."""
        return {self._target_host} | self._extra_hosts

    def in_scope(self, url_or_host: str) -> bool:
        """Check if a URL or bare hostname is in scope.

        Returns False for excluded hosts even if they match scope rules.
        """
        host = self._extract_host(url_or_host)
        if not host:
            return False

        # Excluded hosts always fail
        if host in self._excluded_hosts:
            return False

        # Exact match on target
        if host == self._target_host:
            return True

        # Subdomain match: host ends with .target_host
        if self._target_host and host.endswith("." + self._target_host):
            return True

        # Match against extra scopes
        for extra_host in self._extra_hosts:
            if host == extra_host:
                return True
            if extra_host and host.endswith("." + extra_host):
                return True

        # IP address matching: if target is an IP, match IPs directly
        try:
            target_ip = ipaddress.ip_address(self._target_host)
            url_ip = ipaddress.ip_address(host)
            return target_ip == url_ip
        except ValueError:
            pass  # Not IP addresses, that's fine

        return False

    @staticmethod
    def _extract_host(url_or_host: str) -> str:
        """Extract normalized hostname from a URL or bare hostname string."""
        if not url_or_host:
            return ""

        # Try parsing as URL first
        try:
            parsed = urlparse(url_or_host)
            if parsed.hostname:
                return parsed.hostname.lower().rstrip(".")
        except Exception:
            pass

        # Treat as bare hostname
        return url_or_host.lower().strip().rstrip(".")
