"""Endpoint Builder — converts raw crawl data into Endpoint objects.

Raw crawl output (from katana, BFS crawler, browser, etc.) arrives as
simple dicts with url/method/tag/source. This module enriches them into
canonical Endpoint objects with parameters, content type, and metadata.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import urlparse, parse_qs

from ..models import Endpoint


# Common API path patterns
API_PATH_PATTERN = re.compile(
    r"/(?:api|v[0-9]+|graphql|rest|internal|admin|auth|oauth|callback)/",
    re.IGNORECASE,
)

# State-changing methods
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Sensitive path indicators
SENSITIVE_PATTERNS = [
    re.compile(r"/admin", re.IGNORECASE),
    re.compile(r"/internal", re.IGNORECASE),
    re.compile(r"/debug", re.IGNORECASE),
    re.compile(r"/test", re.IGNORECASE),
    re.compile(r"/staging", re.IGNORECASE),
    re.compile(r"/env", re.IGNORECASE),
    re.compile(r"/config", re.IGNORECASE),
    re.compile(r"/backup", re.IGNORECASE),
    re.compile(r"/\.env", re.IGNORECASE),
    re.compile(r"/graphql", re.IGNORECASE),
]


class EndpointBuilder:
    """Builds canonical Endpoint objects from raw crawl data.

    Handles deduplication, parameter extraction, and metadata enrichment.

    Usage:
        builder = EndpointBuilder()
        endpoints = builder.build_from_katana(katana_output)
        endpoints = builder.build_from_crawler(crawler_output)
    """

    def build_from_katana(self, data: dict[str, Any]) -> list[Endpoint]:
        """Convert katana JSON output to Endpoint objects.

        Katana returns: {url, method, tag, source}
        """
        endpoints = []
        raw_list = data.get("endpoints", [])

        for raw in raw_list:
            url = raw.get("url", "")
            if not url:
                continue

            method = raw.get("method", "GET").upper()
            tag = raw.get("tag", "")
            source = raw.get("source", "katana")

            endpoint = self._build_endpoint(
                url=url,
                method=method,
                source=source,
                tag=tag,
            )
            endpoints.append(endpoint)

        return self._deduplicate(endpoints)

    def build_from_crawler(self, data: dict[str, Any]) -> list[Endpoint]:
        """Convert BFS crawler output to Endpoint objects.

        Crawler returns: {endpoints: [...], forms: [...]}
        Each endpoint: {url, method?}
        Each form: {action, method, inputs: [...]}
        """
        endpoints = []

        # Process raw endpoints
        for raw in data.get("endpoints", []):
            url = raw.get("url", "")
            if not url:
                continue
            method = raw.get("method", "GET").upper()
            endpoint = self._build_endpoint(url=url, method=method, source="crawler")
            endpoints.append(endpoint)

        # Process forms
        for form in data.get("forms", []):
            action = form.get("action", "")
            if not action:
                continue
            method = form.get("method", "POST").upper()
            inputs = form.get("inputs", [])
            param_names = [inp.get("name", "") for inp in inputs if inp.get("name")]

            endpoint = self._build_endpoint(
                url=action,
                method=method,
                source="crawler_form",
                params=param_names,
            )
            endpoints.append(endpoint)

        return self._deduplicate(endpoints)

    def build_from_urls(self, urls: list[str], source: str = "manual") -> list[Endpoint]:
        """Convert a plain URL list to Endpoint objects."""
        endpoints = []
        for url in urls:
            if not url:
                continue
            endpoint = self._build_endpoint(url=url, method="GET", source=source)
            endpoints.append(endpoint)
        return self._deduplicate(endpoints)

    def build_from_httpx(self, data: dict[str, Any]) -> list[Endpoint]:
        """Convert httpx probe output to Endpoint objects.

        httpx returns: {url, status_code, title, tech, content_type, ...}
        """
        endpoints = []
        hosts = data.get("live_hosts", [])

        for host in hosts:
            url = host.get("url", "")
            if not url:
                continue

            endpoint = self._build_endpoint(
                url=url,
                method="GET",
                source="httpx",
                status_code=host.get("status_code", 0),
                title=host.get("title", ""),
                tech_stack=host.get("tech", []),
                content_type=host.get("content_type", ""),
            )
            endpoints.append(endpoint)

        return self._deduplicate(endpoints)

    def merge(self, *endpoint_lists: list[Endpoint]) -> list[Endpoint]:
        """Merge multiple endpoint lists with deduplication."""
        combined = []
        for lst in endpoint_lists:
            combined.extend(lst)
        return self._deduplicate(combined)

    def _build_endpoint(
        self,
        url: str,
        method: str = "GET",
        source: str = "",
        tag: str = "",
        params: list[str] | None = None,
        status_code: int = 0,
        title: str = "",
        tech_stack: list[str] | None = None,
        content_type: str = "",
    ) -> Endpoint:
        """Build a single Endpoint object."""
        # Normalize URL
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        parsed = urlparse(url)

        # Extract parameters from query string
        query_params = list(parse_qs(parsed.query).keys())

        # Merge explicit params with query params
        all_params = list(set(query_params + (params or [])))

        # Determine auth requirement from path
        auth_required = self._guess_auth_required(parsed.path)

        # Detect if state-changing
        state_changing = method in STATE_CHANGING_METHODS

        # Detect API endpoint
        is_api = bool(API_PATH_PATTERN.search(parsed.path))

        # Build endpoint ID
        endpoint_id = self._make_id(url, method)

        return Endpoint(
            url=url,
            method=method,
            params=all_params,
            content_type=content_type,
            status_code=status_code,
            auth_required=auth_required,
            tested=False,
        )

    def _guess_auth_required(self, path: str) -> bool:
        """Heuristic: paths with auth/admin/internal likely require auth."""
        for pattern in SENSITIVE_PATTERNS:
            if pattern.search(path):
                return True
        return False

    def _make_id(self, url: str, method: str) -> str:
        """Create a stable deduplication ID."""
        raw = f"{method.upper()}:{url}"
        return hashlib.md5(raw.encode()).hexdigest()[:12]

    def _deduplicate(self, endpoints: list[Endpoint]) -> list[Endpoint]:
        """Remove duplicate endpoints (same URL + method)."""
        seen: set[str] = set()
        deduped: list[Endpoint] = []

        for ep in endpoints:
            key = f"{ep.method.upper()}:{ep.url}"
            if key not in seen:
                seen.add(key)
                deduped.append(ep)

        return deduped
