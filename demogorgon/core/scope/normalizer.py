"""Scope Normalizer — normalizes asset patterns to a consistent format.

Handles:
- Wildcard domains (*.example.com)
- Exact domains (api.example.com)
- URLs (https://app.example.com)
- IP ranges (192.168.1.0/24)
- Mobile apps (com.example.app)
"""

from __future__ import annotations

import re
from urllib.parse import urlparse
from ..engagement import ScopeAsset


def normalize_asset(pattern: str) -> ScopeAsset:
    """Normalize an asset pattern into a ScopeAsset."""
    pattern = pattern.strip()
    
    # URL
    if pattern.startswith(('http://', 'https://')):
        return _normalize_url(pattern)
    
    # IP range/CIDR
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?$', pattern):
        return _normalize_ip_range(pattern)
    
    # Wildcard domain
    if pattern.startswith('*.'):
        return _normalize_wildcard(pattern)
    
    # Mobile app (com.example.app)
    if re.match(r'^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*){2,}$', pattern.lower()):
        return _normalize_mobile_app(pattern)
    
    # Plain domain
    return _normalize_domain(pattern)


def _normalize_url(pattern: str) -> ScopeAsset:
    """Normalize a URL pattern."""
    parsed = urlparse(pattern)
    return ScopeAsset(
        pattern=pattern.rstrip('/'),
        asset_type="url",
        description=f"URL: {parsed.hostname}",
    )


def _normalize_ip_range(pattern: str) -> ScopeAsset:
    """Normalize an IP range/CIDR pattern."""
    return ScopeAsset(
        pattern=pattern,
        asset_type="ip_range",
        description=f"IP range: {pattern}",
    )


def _normalize_wildcard(pattern: str) -> ScopeAsset:
    """Normalize a wildcard domain pattern."""
    # Extract the base domain
    base_domain = pattern[2:]  # Remove *.
    return ScopeAsset(
        pattern=f"*.{base_domain}",
        asset_type="subdomain",
        description=f"Wildcard: all subdomains of {base_domain}",
    )


def _normalize_domain(pattern: str) -> ScopeAsset:
    """Normalize a plain domain."""
    domain = pattern.lower().rstrip('.')
    return ScopeAsset(
        pattern=domain,
        asset_type="domain",
        description=f"Domain: {domain}",
    )


def _normalize_mobile_app(pattern: str) -> ScopeAsset:
    """Normalize a mobile app identifier."""
    return ScopeAsset(
        pattern=pattern.lower(),
        asset_type="mobile_app",
        description=f"Mobile app: {pattern}",
    )


def normalize_assets(assets: list[ScopeAsset]) -> list[ScopeAsset]:
    """Normalize a list of assets, deduplicating by pattern."""
    seen = set()
    normalized = []
    
    for asset in assets:
        norm = normalize_asset(asset.pattern)
        if norm.pattern not in seen:
            seen.add(norm.pattern)
            normalized.append(norm)
    
    return normalized
