"""CSRF Tester — tests for Cross-Site Request Forgery."""

from __future__ import annotations

from typing import Any

from demogorgon.executors.base import BaseExecutor


class CSRFTester(BaseExecutor):
    """Tests for CSRF by sending state-changing requests without tokens."""

    # CSRF-sensitive methods
    SENSITIVE_METHODS = ["POST", "PUT", "DELETE", "PATCH"]

    # Common CSRF token field names
    CSRF_TOKEN_FIELDS = [
        "csrf_token", "csrfmiddlewaretoken", "_token", "token",
        "authenticity_token", "xsrf-token", "x-csrf-token",
        "__RequestVerificationToken", "csrf", "_csrf",
    ]

    @property
    def name(self) -> str:
        return "csrf_tester"

    @property
    def vuln_class(self) -> str:
        return "csrf"

    @property
    def description(self) -> str:
        return "Tests for CSRF by sending state-changing requests without tokens"

    async def test(self, endpoint: str, **kwargs) -> dict[str, Any]:
        findings = []
        evidence = []
        http = kwargs.get("http_client")
        headers = kwargs.get("headers", {})
        method = kwargs.get("method", "POST")
        body = kwargs.get("body")

        if not http:
            return {"findings": [], "evidence": [], "error": "No HTTP client"}

        # Only test state-changing methods
        if method.upper() not in self.SENSITIVE_METHODS:
            return {
                "findings": [],
                "evidence": [],
                "tested_count": 0,
                "vulnerable": False,
                "error": f"Method {method} is not state-changing",
            }

        # Test 1: Send without CSRF token
        clean_headers = {k: v for k, v in headers.items()
                        if not any(token in k.lower() for token in self.CSRF_TOKEN_FIELDS)}

        result = await http.request(method, endpoint, headers=clean_headers, body=body)
        evidence.append({
            "test": "no_csrf_token",
            "status": result["status_code"],
            "length": len(result["body"]),
            "snippet": result["body"][:200],
        })

        # If request succeeded without CSRF token, it's vulnerable
        if 200 <= result["status_code"] < 300:
            # Check if it's actually a state-changing operation
            body_lower = result["body"].lower()
            success_indicators = ["success", "created", "updated", "deleted", "saved", "confirmed"]
            if any(indicator in body_lower for indicator in success_indicators):
                findings.append(self._create_finding(
                    title=f"CSRF — state-changing endpoint accessible without CSRF token",
                    severity="high",
                    endpoint=endpoint,
                    evidence=f"{method} {endpoint} returned {result['status_code']} without CSRF token. Response: {result['body'][:200]}",
                    steps=[
                        f"Send {method} request to {endpoint} without CSRF token",
                        "Observe successful response",
                        "Craft malicious page that sends this request",
                        "Victim visits malicious page and action is performed",
                    ],
                    impact="Unauthorized state changes, account takeover, data modification",
                    confidence=0.8,
                ))

        # Test 2: Send with empty CSRF token
        empty_token_headers = dict(clean_headers)
        empty_token_headers["X-CSRF-Token"] = ""
        empty_token_headers["X-XSRF-TOKEN"] = ""

        result2 = await http.request(method, endpoint, headers=empty_token_headers, body=body)
        evidence.append({
            "test": "empty_csrf_token",
            "status": result2["status_code"],
            "length": len(result2["body"]),
        })

        if 200 <= result2["status_code"] < 300:
            body_lower = result2["body"].lower()
            success_indicators = ["success", "created", "updated", "deleted", "saved", "confirmed"]
            if any(indicator in body_lower for indicator in success_indicators):
                findings.append(self._create_finding(
                    title=f"CSRF — state-changing endpoint accepts empty CSRF token",
                    severity="high",
                    endpoint=endpoint,
                    evidence=f"{method} {endpoint} returned {result2['status_code']} with empty CSRF token",
                    steps=[
                        f"Send {method} request to {endpoint} with empty CSRF token",
                        "Observe successful response",
                        "Server is not validating CSRF tokens",
                    ],
                    impact="CSRF token validation bypassed entirely",
                    confidence=0.9,
                ))

        # Test 3: Check for SameSite cookie attribute
        cookies = result.get("headers", {}).get("set-cookie", "")
        if cookies and "samesite" not in cookies.lower():
            evidence.append({
                "test": "missing_samesite",
                "cookies": cookies[:200],
            })

        return {
            "findings": [f.to_dict() for f in findings],
            "evidence": evidence,
            "tested_count": 3,
            "vulnerable": len(findings) > 0,
        }
