"""Info Disclosure Detector — tests for information disclosure via errors and headers."""

from __future__ import annotations

from typing import Any


class InfoDisclosureDetector:
    """Tests for information disclosure via error messages, headers, and verbose responses."""

    ERROR_TRIGGERS = [
        "/api/nonexistent",
        "/api/v999/users",
        "/api/users/-1",
        "/api/admin/config",
        "/api/debug",
        "/api/health",
        "/api/config",
        "/.env",
        "/.git/config",
        "/robots.txt",
        "/sitemap.xml",
    ]

    def __init__(self, http_client: Any):
        self.http = http_client

    async def test(self, base_url: str) -> dict[str, Any]:
        findings = []
        evidence = []

        for path in self.ERROR_TRIGGERS:
            url = f"{base_url.rstrip('/')}{path}"
            result = await self.http.request(method="GET", url=url)

            resp_body = result["body"]
            resp_headers = result["headers"]

            evidence.append({
                "path": path,
                "status": result["status_code"],
                "length": len(resp_body),
                "body_preview": resp_body[:200],
            })

            interesting_patterns = [
                "stack trace", "traceback", "error", "exception",
                "debug", "internal", "server", "version",
                "database", "sql", "mysql", "postgres", "sqlite",
                "password", "secret", "key", "token",
            ]
            body_lower = resp_body.lower()
            for pattern in interesting_patterns:
                if pattern in body_lower and result["status_code"] >= 400:
                    findings.append({
                        "title": f"Information disclosure via error at {path}",
                    "severity": "medium",
                    "vuln_class": "info_disclosure",
                    "endpoint": url,
                    "evidence": f"Error response contains '{pattern}' at {path}",
                })
                    break

            if result["status_code"] == 200 and path in ["/.env", "/.git/config", "/robots.txt"]:
                findings.append({
                    "title": f"Sensitive file exposed: {path}",
                    "severity": "high" if path == "/.env" else "medium",
                    "vuln_class": "info_disclosure",
                    "endpoint": url,
                    "evidence": f"File {path} accessible, body length: {len(resp_body)}",
                })

            server = resp_headers.get("server", "")
            if server and "nginx" in server.lower() or "apache" in server.lower():
                findings.append({
                    "title": f"Server version disclosed: {server}",
                    "severity": "low",
                    "vuln_class": "info_disclosure",
                    "endpoint": url,
                    "evidence": f"Server header: {server}",
                })

        return {
            "findings": findings,
            "evidence": evidence,
            "endpoints_tested": len(self.ERROR_TRIGGERS),
            "vulnerable": len(findings) > 0,
        }
