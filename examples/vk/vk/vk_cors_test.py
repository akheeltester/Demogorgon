#!/usr/bin/env python3
"""
VK CORS Misconfiguration Tester
================================
Tests for Cross-Origin Resource Sharing misconfigurations on VK's API endpoints.

Usage:
    python3 vk_cors_test.py

Tests:
    - Arbitrary origin reflection
    - Credential handling
    - Preflight response analysis
    - Subdomain trust analysis
"""

import asyncio
import json
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

import httpx


# ─── Configuration ─────────────────────────────────────────────────────────────
RATE_LIMIT_DELAY = 0.15
VK_API_BASE = "https://api.vk.com"
VK_OAUTH_BASE = "https://oauth.vk.com"
VK_ID_BASE = "https://id.vk.com"


# ─── Test Origins ──────────────────────────────────────────────────────────────
TEST_ORIGINS = [
    # ─── Basic Origin Tests ────────────────────────────────────────────────────
    "https://evil.com",
    "https://attacker.com",
    "https://malicious-site.com",
    "null",  # null origin (sandboxed iframes)

    # ─── Subdomain Tests ───────────────────────────────────────────────────────
    "https://evil.vk.com",
    "https://test.vk.com",
    "https://api.vk.com.evil.com",  # Subdomain abuse
    "https://vk.com.evil.com",

    # ─── Protocol Tricks ───────────────────────────────────────────────────────
    "http://evil.com",  # HTTP vs HTTPS
    "https://evil.com:443",  # Port specification

    # ─── Special Cases ─────────────────────────────────────────────────────────
    "https://EVIL.COM",  # Case sensitivity
    "https://evil.com%00",  # Null byte
    "https://evil.com%0d%0a",  # CRLF injection
    "https://evil.com%60",  # Backtick encoding
]


@dataclass
class CORSTestResult:
    """Result of a CORS test."""
    endpoint: str
    origin_sent: str
    acao_reflected: bool
    acac_enabled: bool
    credentials_supported: bool
    vulnerability: str
    severity: str
    evidence: str
    response_headers: dict = field(default_factory=dict)


class VKCORSTester:
    """VK CORS misconfiguration tester."""

    def __init__(self):
        self.results: list[CORSTestResult] = []
        self.request_count = 0
        self.last_request_time = 0.0

    async def _rate_limit_wait(self):
        """Enforce rate limit."""
        elapsed = time.time() - self.last_request_time
        if elapsed < RATE_LIMIT_DELAY:
            await asyncio.sleep(RATE_LIMIT_DELAY - elapsed)
        self.last_request_time = time.time()
        self.request_count += 1

    async def _test_cors(self, endpoint: str, origin: str) -> CORSTestResult:
        """Test CORS configuration for a specific endpoint and origin."""
        await self._rate_limit_wait()

        headers = {
            "Origin": origin,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
        }

        async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
            try:
                resp = await client.get(endpoint, headers=headers)
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}

                acao = resp_headers.get("access-control-allow-origin", "")
                acac = resp_headers.get("access-control-allow-credentials", "")

                # Determine vulnerability
                acao_reflected = acao == origin
                acac_enabled = acac.lower() == "true"
                credentials_supported = acao_reflected and acac_enabled

                if credentials_supported:
                    vulnerability = "CRITICAL: Origin reflected with credentials"
                    severity = "CRITICAL"
                elif acao_reflected:
                    vulnerability = "MEDIUM: Origin reflected (no credentials)"
                    severity = "MEDIUM"
                elif acao == "*":
                    vulnerability = "LOW: Wildcard ACAO"
                    severity = "LOW"
                else:
                    vulnerability = "None"
                    severity = "info"

                return CORSTestResult(
                    endpoint=endpoint,
                    origin_sent=origin,
                    acao_reflected=acao_reflected,
                    acac_enabled=acac_enabled,
                    credentials_supported=credentials_supported,
                    vulnerability=vulnerability,
                    severity=severity,
                    evidence=f"ACAO: '{acao}', ACAC: '{acac}'",
                    response_headers=resp_headers,
                )

            except httpx.RequestError as e:
                return CORSTestResult(
                    endpoint=endpoint,
                    origin_sent=origin,
                    acao_reflected=False,
                    acac_enabled=False,
                    credentials_supported=False,
                    vulnerability="Error",
                    severity="info",
                    evidence=f"Request error: {str(e)[:100]}",
                )

    async def _test_preflight(self, endpoint: str, origin: str) -> CORSTestResult:
        """Test CORS preflight (OPTIONS) response."""
        await self._rate_limit_wait()

        headers = {
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type,Authorization",
        }

        async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
            try:
                resp = await client.options(endpoint, headers=headers)
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}

                acao = resp_headers.get("access-control-allow-origin", "")
                acac = resp_headers.get("access-control-allow-credentials", "")
                acam = resp_headers.get("access-control-allow-methods", "")
                acah = resp_headers.get("access-control-allow-headers", "")

                acao_reflected = acao == origin
                acac_enabled = acac.lower() == "true"

                vulnerability = "None"
                severity = "info"

                if acao_reflected and acac_enabled:
                    vulnerability = "CRITICAL: Preflight accepts origin with credentials"
                    severity = "CRITICAL"
                elif acao_reflected:
                    vulnerability = "MEDIUM: Preflight reflects origin"
                    severity = "MEDIUM"

                return CORSTestResult(
                    endpoint=endpoint,
                    origin_sent=origin,
                    acao_reflected=acao_reflected,
                    acac_enabled=acac_enabled,
                    credentials_supported=acao_reflected and acac_enabled,
                    vulnerability=vulnerability,
                    severity=severity,
                    evidence=f"ACAO: '{acao}', ACAC: '{acac}', Methods: '{acam}'",
                    response_headers=resp_headers,
                )

            except httpx.RequestError as e:
                return CORSTestResult(
                    endpoint=endpoint,
                    origin_sent=origin,
                    acao_reflected=False,
                    acac_enabled=False,
                    credentials_supported=False,
                    vulnerability="Error",
                    severity="info",
                    evidence=f"Request error: {str(e)[:100]}",
                )

    async def run_all_tests(self) -> list[CORSTestResult]:
        """Run CORS tests on all VK endpoints with all test origins."""
        # Endpoints to test
        endpoints = [
            f"{VK_API_BASE}/method/users.get",
            f"{VK_API_BASE}/method/messages.getConversations",
            f"{VK_API_BASE}/method/friends.get",
            f"{VK_API_BASE}/method/wall.get",
            f"{VK_OAUTH_BASE}/authorize",
            f"{VK_ID_BASE}/",
        ]

        print(f"\n{'='*70}")
        print(f"VK CORS MISCONFIGURATION TESTER")
        print(f"{'='*70}")
        print(f"Endpoints: {len(endpoints)}")
        print(f"Test Origins: {len(TEST_ORIGINS)}")
        print(f"Total Tests: {len(endpoints) * len(TEST_ORIGINS)}")
        print(f"Rate Limit: {RATE_LIMIT_DELAY}s between requests")
        print(f"{'='*70}\n")

        self.results = []

        for endpoint in endpoints:
            print(f"\n🔍 Testing: {endpoint}")
            print(f"{'-'*70}")

            for origin in TEST_ORIGINS:
                # Test GET request
                result = await self._test_cors(endpoint, origin)
                self.results.append(result)

                # Test OPTIONS preflight
                preflight_result = await self._test_preflight(endpoint, origin)
                self.results.append(preflight_result)

                # Print critical findings
                if result.credentials_supported or preflight_result.credentials_supported:
                    print(f"  🔴 CRITICAL: Origin '{origin}' accepted with credentials!")
                elif result.acao_reflected or preflight_result.acao_reflected:
                    print(f"  🟡 MEDIUM: Origin '{origin}' reflected")

            print(f"  ✅ All origins tested for this endpoint")

        return self.results

    def print_summary(self):
        """Print summary of CORS test results."""
        critical = [r for r in self.results if r.severity == "CRITICAL"]
        medium = [r for r in self.results if r.severity == "MEDIUM"]
        low = [r for r in self.results if r.severity == "LOW"]

        print(f"\n{'='*70}")
        print(f"CORS TEST RESULTS SUMMARY")
        print(f"{'='*70}")
        print(f"Total Tests:   {len(self.results)}")
        print(f"CRITICAL:      {len(critical)} 🔴")
        print(f"MEDIUM:        {len(medium)} 🟡")
        print(f"LOW:           {len(low)} 🟢")
        print(f"{'='*70}")

        if critical:
            print(f"\n🔴 CRITICAL FINDINGS:")
            print(f"{'-'*70}")
            for r in critical:
                print(f"\n  Endpoint: {r.endpoint}")
                print(f"  Origin:   {r.origin_sent}")
                print(f"  Evidence: {r.evidence}")
                print(f"  Impact:   Attacker can read credentialed responses from this endpoint")

        if medium:
            print(f"\n🟡 MEDIUM FINDINGS:")
            print(f"{'-'*70}")
            for r in medium[:10]:  # Show first 10
                print(f"\n  Endpoint: {r.endpoint}")
                print(f"  Origin:   {r.origin_sent}")
                print(f"  Evidence: {r.evidence}")

        print(f"\n{'='*70}")

    def export_results(self, path: str):
        """Export results to JSON."""
        data = {
            "summary": {
                "total_tests": len(self.results),
                "critical": len([r for r in self.results if r.severity == "CRITICAL"]),
                "medium": len([r for r in self.results if r.severity == "MEDIUM"]),
                "low": len([r for r in self.results if r.severity == "LOW"]),
            },
            "results": [
                {
                    "endpoint": r.endpoint,
                    "origin_sent": r.origin_sent,
                    "acao_reflected": r.acao_reflected,
                    "acac_enabled": r.acac_enabled,
                    "credentials_supported": r.credentials_supported,
                    "vulnerability": r.vulnerability,
                    "severity": r.severity,
                    "evidence": r.evidence,
                }
                for r in self.results
            ],
        }

        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"\nResults exported to: {path}")


async def main():
    """Main entry point."""
    tester = VKCORSTester()
    await tester.run_all_tests()
    tester.print_summary()
    tester.export_results("vk_cors_results.json")


if __name__ == "__main__":
    asyncio.run(main())
