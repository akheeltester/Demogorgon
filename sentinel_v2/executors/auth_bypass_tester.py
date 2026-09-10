"""Auth Bypass Tester — tests endpoints for authentication bypass."""

from __future__ import annotations

from typing import Any


class AuthBypassTester:
    """Tests endpoints for authentication bypass."""

    def __init__(self, http_client: Any):
        self.http = http_client

    async def test(self, endpoint: str, method: str = "GET") -> dict[str, Any]:
        findings = []
        evidence = []

        result_no_auth = await self.http.request(method=method, url=endpoint)
        evidence.append({
            "test": "no_auth",
            "status": result_no_auth["status_code"],
            "length": len(result_no_auth["body"]),
        })

        if 200 <= result_no_auth["status_code"] < 400:
            findings.append({
                "title": f"Authentication bypass — {method} {endpoint} accessible without auth",
                "severity": "critical",
                "vuln_class": "auth_bypass",
                "endpoint": endpoint,
                "evidence": f"Request without authentication returned {result_no_auth['status_code']}",
            })

        result_empty_token = await self.http.request(
            method=method,
            url=endpoint,
            headers={"Authorization": "Bearer "},
        )
        evidence.append({
            "test": "empty_token",
            "status": result_empty_token["status_code"],
            "length": len(result_empty_token["body"]),
        })

        if 200 <= result_empty_token["status_code"] < 400:
            findings.append({
                "title": f"Authentication bypass — empty token accepted at {endpoint}",
                "severity": "high",
                "vuln_class": "auth_bypass",
                "endpoint": endpoint,
                "evidence": f"Empty Bearer token returned {result_empty_token['status_code']}",
            })

        result_invalid = await self.http.request(
            method=method,
            url=endpoint,
            headers={"Authorization": "Bearer invalid_token_12345"},
        )
        evidence.append({
            "test": "invalid_token",
            "status": result_invalid["status_code"],
            "length": len(result_invalid["body"]),
        })

        if 200 <= result_invalid["status_code"] < 400:
            findings.append({
                "title": f"Authentication bypass — invalid token accepted at {endpoint}",
                "severity": "critical",
                "vuln_class": "auth_bypass",
                "endpoint": endpoint,
                "evidence": f"Invalid token returned {result_invalid['status_code']}",
            })

        result_admin_header = await self.http.request(
            method=method,
            url=endpoint,
            headers={"X-Admin": "true", "X-Forwarded-For": "127.0.0.1"},
        )
        evidence.append({
            "test": "admin_header",
            "status": result_admin_header["status_code"],
            "length": len(result_admin_header["body"]),
        })

        if 200 <= result_admin_header["status_code"] < 400:
            no_auth_status = result_no_auth["status_code"]
            if result_admin_header["status_code"] != no_auth_status:
                findings.append({
                    "title": f"Authentication bypass via admin header at {endpoint}",
                    "severity": "high",
                    "vuln_class": "auth_bypass",
                    "endpoint": endpoint,
                    "evidence": f"X-Admin header changed response from {no_auth_status} to {result_admin_header['status_code']}",
                })

        return {
            "findings": findings,
            "evidence": evidence,
            "tests_performed": len(evidence),
            "vulnerable": len(findings) > 0,
        }
