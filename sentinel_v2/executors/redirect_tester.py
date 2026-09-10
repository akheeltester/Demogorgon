"""Redirect Tester — tests for open redirect vulnerabilities."""

from __future__ import annotations

from typing import Any

from urllib.parse import urlparse, parse_qs

from sentinel_v2.executors.base import BaseExecutor


class RedirectTester(BaseExecutor):
    """Tests for open redirect using various redirect parameter patterns."""

    # Common redirect parameter names
    REDIRECT_PARAMS = [
        "redirect", "url", "next", "return", "goto", "continue",
        "dest", "redir", "redirect_uri", "return_to", "checkout_url",
        "return_url", "ref", "referer", "from", "returnUrl",
        "nextUrl", "redirectUrl", "target", "rurl", "dest_url",
    ]

    # Evil URLs to test
    EVIL_URLS = [
        "https://evil.com",
        "https://evil.com/",
        "https://evil.com/path",
        "https://evil.com%00.example.com",
        "//evil.com",
        "///evil.com",
        "https://evil.com%23.example.com",
        "https://evil.com%40.example.com",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
    ]

    @property
    def name(self) -> str:
        return "redirect_tester"

    @property
    def vuln_class(self) -> str:
        return "open_redirect"

    @property
    def description(self) -> str:
        return "Tests for open redirect using various redirect parameter patterns"

    async def test(self, endpoint: str, **kwargs) -> dict[str, Any]:
        findings = []
        evidence = []
        http = kwargs.get("http_client")
        headers = kwargs.get("headers", {})

        if not http:
            return {"findings": [], "evidence": [], "error": "No HTTP client"}

        # Extract existing redirect parameters from URL
        parsed = urlparse(endpoint)
        existing_params = parse_qs(parsed.query, keep_blank_values=True)

        # Test existing redirect parameters
        for param_name in existing_params:
            if param_name.lower() in [p.lower() for p in self.REDIRECT_PARAMS]:
                for evil_url in self.EVIL_URLS[:5]:
                    result = await self._test_redirect(
                        http, endpoint, param_name, evil_url, headers
                    )
                    evidence.append(result["evidence"])

                    if result["vulnerable"]:
                        findings.append(self._create_finding(
                            title=f"Open Redirect — parameter '{param_name}' redirects to external URL",
                            severity="medium",
                            endpoint=endpoint,
                            evidence=f"Setting {param_name} to {evil_url} caused redirect to {result['evidence']['location']}",
                            steps=[
                                f"Set {param_name} to {evil_url}",
                                "Follow redirect",
                                "Verify redirect to external URL",
                                "Use for phishing or OAuth token theft",
                            ],
                            impact="Phishing, OAuth token theft, malware delivery",
                            confidence=0.85,
                        ))
                        break

        # Test adding redirect parameters
        for param_name in self.REDIRECT_PARAMS[:10]:
            if param_name not in existing_params:
                for evil_url in self.EVIL_URLS[:3]:
                    result = await self._test_redirect(
                        http, endpoint, param_name, evil_url, headers
                    )
                    evidence.append(result["evidence"])

                    if result["vulnerable"]:
                        findings.append(self._create_finding(
                            title=f"Open Redirect — hidden parameter '{param_name}' accepts external URLs",
                            severity="medium",
                            endpoint=endpoint,
                            evidence=f"Adding {param_name}={evil_url} caused redirect",
                            steps=[
                                f"Add {param_name}={evil_url} to URL",
                                "Follow redirect",
                                "Verify redirect to external URL",
                            ],
                            impact="Phishing, OAuth token theft",
                            confidence=0.75,
                        ))
                        break

        # Test POST-based redirects
        for param_name in self.REDIRECT_PARAMS[:5]:
            body = f"{param_name}=https://evil.com"
            result = await http.request("POST", endpoint, headers=headers, body=body)

            if "evil.com" in result["headers"].get("location", ""):
                findings.append(self._create_finding(
                    title=f"Open Redirect — POST to {endpoint} with {param_name}",
                    severity="medium",
                    endpoint=endpoint,
                    evidence=f"POST with {param_name}=evil.com caused redirect",
                    steps=[
                        f"POST to {endpoint} with {param_name}=evil.com",
                        "Follow redirect to evil.com",
                    ],
                    impact="Phishing via POST redirect",
                    confidence=0.7,
                ))

        return {
            "findings": [f.to_dict() for f in findings],
            "evidence": evidence,
            "tested_count": len(self.REDIRECT_PARAMS) * 3,
            "vulnerable": len(findings) > 0,
        }

    async def _test_redirect(self, http, endpoint: str, param_name: str,
                             evil_url: str, headers: dict) -> dict:
        """Test a single redirect parameter."""
        parsed = urlparse(endpoint)
        params = parse_qs(parsed.query, keep_blank_values=True)

        # Add/replace parameter
        params[param_name] = [evil_url]

        # Reconstruct URL
        query = "&".join(f"{k}={v[0]}" for k, v in params.items())
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"

        result = await http.request("GET", test_url, headers=headers)

        # Check for redirect
        location = result["headers"].get("location", "")
        vulnerable = False

        if 300 <= result["status_code"] < 400:
            if "evil.com" in location:
                vulnerable = True
        elif "evil.com" in result["body"]:
            vulnerable = True

        return {
            "vulnerable": vulnerable,
            "evidence": {
                "param": param_name,
                "payload": evil_url,
                "status": result["status_code"],
                "location": location,
            },
        }
