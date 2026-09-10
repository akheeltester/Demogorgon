"""JavaScript Intelligence Engine

Deep analysis of JavaScript to extract security-relevant intelligence:
- API endpoints, parameters, data models
- Authentication flows, token handling
- Business logic, validation, authorization checks
- Hidden endpoints, debug modes, feature flags
- Source maps for reconstructed code flow

This is what a manual JS auditor does with DevTools.
"""

from __future__ import annotations

import re
import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class JSEndpoint:
    """An endpoint discovered from JS analysis."""
    method: str
    path: str
    parameters: list[str] = field(default_factory=list)
    auth_required: bool | None = None
    source_file: str = ""


@dataclass
class JSModel:
    """A data model discovered from JS."""
    name: str
    fields: list[str] = field(default_factory=list)
    relationships: list[str] = field(default_factory=list)


@dataclass
class JSFlow:
    """A business logic flow discovered from JS."""
    name: str
    steps: list[str] = field(default_factory=list)
    endpoints_used: list[str] = field(default_factory=list)


class JSIntelligence:
    """Extracts security intelligence from JavaScript code.

    Analyzes source code, bundles, and runtime behavior to find:
    - Hidden API endpoints and parameters
    - Data models and relationships
    - Business logic and validation rules
    - Authentication and authorization patterns
    - Debug modes and feature flags
    """

    def __init__(self, browser_tool):
        self.browser = browser_tool
        self._endpoints: list[JSEndpoint] = []
        self._models: list[JSModel] = []
        self._flows: list[JSFlow] = []
        self._patterns: dict[str, list[str]] = {}

    async def analyze_page(self) -> dict[str, Any]:
        """Analyze all JavaScript on the current page."""
        if not self.browser._page:
            return {}

        # Get all script contents
        scripts = await self._get_all_scripts()

        # Analyze each script
        for script in scripts:
            self._analyze_script(script)

        # Extract from runtime
        runtime = await self._analyze_runtime()

        # Extract from network patterns
        network = self._analyze_network_patterns()

        return {
            "endpoints": [vars(e) for e in self._endpoints],
            "models": [vars(m) for m in self._models],
            "flows": [vars(f) for f in self._flows],
            "patterns": self._patterns,
            "runtime": runtime,
            "network": network,
        }

    async def _get_all_scripts(self) -> list[str]:
        """Get contents of all scripts on the page."""
        if not self.browser._page:
            return []

        return await self.browser._page.evaluate("""
            () => {
                const scripts = [];
                document.querySelectorAll('script').forEach(s => {
                    if (s.textContent && s.textContent.length > 50) {
                        scripts.push(s.textContent);
                    }
                });
                return scripts;
            }
        """)

    def _analyze_script(self, code: str):
        """Analyze a script for security-relevant patterns."""
        # API endpoints
        endpoint_patterns = [
            (r'["\'](/api/[^\s"\']+)["\']', 'GET'),
            (r'["\'](/[a-z]+/[a-z]+[^\s"\']*)["\']', 'GET'),
            (r'method:\s*["\']([A-Z]+)["\'].*?url:\s*["\']([^\s"\']+)["\']', None),
            (r'fetch\(["\']([^\s"\']+)["\']', 'GET'),
            (r'\.get\(["\']([^\s"\']+)["\']', 'GET'),
            (r'\.post\(["\']([^\s"\']+)["\']', 'POST'),
            (r'\.put\(["\']([^\s"\']+)["\']', 'PUT'),
            (r'\.delete\(["\']([^\s"\']+)["\']', 'DELETE'),
        ]

        for pattern, method in endpoint_patterns:
            matches = re.findall(pattern, code)
            for match in matches:
                if isinstance(match, tuple):
                    self._endpoints.append(JSEndpoint(
                        method=match[0] if len(match) > 1 else method or 'GET',
                        path=match[1] if len(match) > 1 else match[0],
                        source_file='inline_script'
                    ))
                else:
                    self._endpoints.append(JSEndpoint(
                        method=method or 'GET',
                        path=match,
                        source_file='inline_script'
                    ))

        # Data models (class definitions)
        class_pattern = r'class\s+(\w+)(?:\s+extends\s+\w+)?\s*\{([^}]+)\}'
        for name, body in re.findall(class_pattern, code):
            fields = re.findall(r'this\.(\w+)', body)
            if fields:
                self._models.append(JSModel(
                    name=name,
                    fields=fields[:20]
                ))

        # Authentication patterns
        auth_patterns = [
            r'Authorization["\']?\s*:\s*["\']Bearer\s+([^\s"\']+)',
            r'token["\']?\s*[=:]\s*["\']([^\s"\']+)',
            r'localStorage\.setItem\(["\'](\w*[Tt]oken\w*)["\']',
            r'cookie["\']?\s*[=:]\s*["\'](\w*session\w*)',
        ]
        for pattern in auth_patterns:
            matches = re.findall(pattern, code)
            if matches:
                self._patterns.setdefault('auth', []).extend(matches)

        # Validation/authorization patterns
        validation_patterns = [
            r'if\s*\([^)]*role[^)]*\)',
            r'if\s*\([^)]*admin[^)]*\)',
            r'if\s*\([^)]*permission[^)]*\)',
            r'if\s*\([^)]*auth[^)]*\)',
            r'\.isAdmin\b',
            r'\.role\s*[=!]=',
        ]
        for pattern in validation_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                self._patterns.setdefault('authorization', []).append(pattern)

        # Feature flags
        flag_patterns = [
            r'feature[s]?\[["\'](\w+)["\']\]',
            r'flags?\[["\'](\w+)["\']\]',
            r'isEnabled\(["\'](\w+)["\']\)',
            r'["\'](\w*[Ff]eature\w*)["\']',
        ]
        for pattern in flag_patterns:
            matches = re.findall(pattern, code)
            if matches:
                self._patterns.setdefault('feature_flags', []).extend(matches)

        # API base URLs
        base_url_patterns = [
            r'baseURL["\']?\s*[=:]\s*["\']([^\s"\']+)["\']',
            r'apiUrl["\']?\s*[=:]\s*["\']([^\s"\']+)["\']',
            r'API_BASE["\']?\s*[=:]\s*["\']([^\s"\']+)["\']',
            r'NEXT_PUBLIC_API["\']?\s*[=:]\s*["\']([^\s"\']+)["\']',
        ]
        for pattern in base_url_patterns:
            matches = re.findall(pattern, code)
            if matches:
                self._patterns.setdefault('base_urls', []).extend(matches)

        # Internal IDs and object references
        id_patterns = [
            r'["\']([a-f0-9]{24})["\']',
            r'["\']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']',
        ]
        for pattern in id_patterns:
            matches = re.findall(pattern, code)
            if matches:
                self._patterns.setdefault('internal_ids', []).extend(matches[:10])

    async def _analyze_runtime(self) -> dict[str, Any]:
        """Analyze JavaScript runtime for dynamic patterns."""
        if not self.browser._page:
            return {}

        return await self.browser._page.evaluate("""
            () => {
                const result = {
                    global_functions: [],
                    global_objects: [],
                    react_components: [],
                    vue_instances: [],
                };

                // Look for global functions (potential API clients)
                for (const key of Object.keys(window)) {
                    const val = window[key];
                    if (typeof val === 'function' && key.length > 2) {
                        result.global_functions.push(key);
                    } else if (typeof val === 'object' && val !== null && key.length > 2) {
                        result.global_objects.push(key);
                    }
                }

                // React fiber tree
                const root = document.getElementById('root') || document.getElementById('app');
                if (root && root._reactRootContainer) {
                    result.react_components.push('detected');
                }

                // Vue instances
                if (window.__VUE_DEVTOOLS_GLOBAL_HOOK__) {
                    result.vue_instances.push('detected');
                }

                return result;
            }
        """)

    def _analyze_network_patterns(self) -> dict[str, Any]:
        """Analyze network request patterns from browser capture."""
        if not self.browser:
            return {}

        requests = self.browser.get_captured_requests(limit=200)

        patterns = {
            "endpoints_by_method": {},
            "auth_patterns": [],
            "rate_limited": [],
            "error_patterns": [],
        }

        for req in requests:
            method = req.get("method", "GET")
            url = req.get("url", "")
            status = req.get("status")

            # Group by method
            if method not in patterns["endpoints_by_method"]:
                patterns["endpoints_by_method"][method] = []
            patterns["endpoints_by_method"][method].append(url)

            # Auth patterns
            headers = req.get("headers", {})
            if "authorization" in headers:
                patterns["auth_patterns"].append({
                    "url": url,
                    "header": headers["authorization"][:50]
                })

            # Rate limiting
            if status == 429:
                patterns["rate_limited"].append(url)

            # Error patterns
            if status and status >= 400:
                patterns["error_patterns"].append({
                    "url": url,
                    "status": status
                })

        return patterns

    def get_summary(self) -> str:
        """Get summary of JS intelligence."""
        lines = []
        if self._endpoints:
            lines.append(f"ENDPOINTS: {len(self._endpoints)}")
        if self._models:
            lines.append(f"MODELS: {', '.join(m.name for m in self._models[:10])}")
        if self._patterns:
            lines.append(f"PATTERNS: {', '.join(self._patterns.keys())}")
        return "\n".join(lines) if lines else "No JS intelligence yet"
