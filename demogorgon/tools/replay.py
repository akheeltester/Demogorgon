"""HTTP Replay — take browser-captured requests and replay with mutations.

Every browser action automatically generates a captured request.
The replay tool takes that request and:
1. Replays it as-is (verify it works outside browser)
2. Mutates it systematically (IDOR, auth bypass, etc.)
3. Compares responses (diff)
4. Stores results as evidence

This is how humans test: observe → replay → mutate → compare.
"""

from __future__ import annotations

import copy
import json
import time
from dataclasses import dataclass, field
from typing import Any

from demogorgon.tools.http_client import HTTPClient


@dataclass
class ReplayResult:
    """Result of replaying a request with mutations."""
    mutation: str
    method: str
    url: str
    status_code: int
    response_length: int
    response_snippet: str
    elapsed: float
    diff_from_baseline: dict[str, Any] | None = None
    is_different: bool = False
    timestamp: float = field(default_factory=time.time)


class HTTPReplay:
    """Replay browser-captured requests with systematic mutations.

    For every request the browser makes, this tool can:
    1. Replay it as-is (baseline)
    2. Remove auth headers (auth bypass test)
    3. Change IDs (IDOR test)
    4. Modify body fields (mass assignment test)
    5. Add special characters (injection test)
    6. Change HTTP method (method override test)
    7. Race condition (concurrent replays)
    """

    def __init__(self, http_client: HTTPClient):
        self.http = http_client
        self.results: list[ReplayResult] = []

    async def replay(self, request: dict, label: str = "baseline") -> ReplayResult:
        """Replay a request as-is."""
        result = await self.http.request(
            method=request.get("method", "GET"),
            url=request.get("url", ""),
            headers=request.get("headers", {}),
            body=request.get("body"),
        )
        return ReplayResult(
            mutation=label,
            method=request.get("method", "GET"),
            url=request.get("url", ""),
            status_code=result["status_code"],
            response_length=len(result["body"]),
            response_snippet=result["body"][:500],
            elapsed=result["elapsed"],
        )

    async def replay_without_auth(self, request: dict) -> ReplayResult:
        """Replay without authentication headers."""
        mutated = copy.deepcopy(request)
        headers = mutated.get("headers", {})
        # Remove auth-related headers
        auth_headers = [k for k in headers if k.lower() in (
            "authorization", "x-api-key", "cookie", "x-csrf-token",
            "x-xsrf-token", "csrfmiddlewaretoken",
        )]
        for h in auth_headers:
            del headers[h]
        mutated["headers"] = headers
        # Remove cookies from URL if present
        return await self.replay(mutated, label="no_auth")

    async def replay_with_idor(self, request: dict, id_field: str,
                                original_id: str, new_id: str) -> ReplayResult:
        """Replace an ID in the URL or body to test IDOR."""
        mutated = copy.deepcopy(request)
        # Replace in URL
        mutated["url"] = mutated["url"].replace(original_id, new_id)
        # Replace in body
        if mutated.get("body"):
            mutated["body"] = mutated["body"].replace(original_id, new_id)
        return await self.replay(mutated, label=f"idor_{new_id}")

    async def replay_with_method_override(self, request: dict,
                                           override_method: str) -> ReplayResult:
        """Replay with HTTP method override headers."""
        mutated = copy.deepcopy(request)
        headers = mutated.get("headers", {})
        headers["X-HTTP-Method-Override"] = override_method
        headers["X-Method-Override"] = override_method
        headers["X-HTTP-Method"] = override_method
        mutated["headers"] = headers
        return await self.replay(mutated, label=f"method_override_{override_method}")

    async def replay_without_csrf(self, request: dict) -> ReplayResult:
        """Replay without CSRF token."""
        mutated = copy.deepcopy(request)
        headers = mutated.get("headers", {})
        csrf_headers = [k for k in headers if "csrf" in k.lower()]
        for h in csrf_headers:
            del headers[h]
        mutated["headers"] = headers
        # Remove from body
        if mutated.get("body"):
            try:
                body = json.loads(mutated["body"])
                csrf_fields = [k for k in body if "csrf" in k.lower()]
                for f in csrf_fields:
                    del body[f]
                mutated["body"] = json.dumps(body)
            except (json.JSONDecodeError, TypeError):
                pass
        return await self.replay(mutated, label="no_csrf")

    def diff_responses(self, baseline: ReplayResult, comparison: ReplayResult) -> dict[str, Any]:
        """Compare two responses and identify differences including content, timing, and errors."""
        diff = {
            "status_changed": baseline.status_code != comparison.status_code,
            "baseline_status": baseline.status_code,
            "comparison_status": comparison.status_code,
            "length_changed": baseline.response_length != comparison.response_length,
            "baseline_length": baseline.response_length,
            "comparison_length": comparison.response_length,
            "content_changed": False,
            "error_message_changed": False,
            "significant": False,
            "reasons": [],
        }

        # Status code difference
        if diff["status_changed"]:
            diff["significant"] = True
            diff["reasons"].append(f"Status changed: {baseline.status_code} -> {comparison.status_code}")

        # Length difference
        if diff["length_changed"]:
            length_diff = abs(baseline.response_length - comparison.response_length)
            if length_diff > 50:
                diff["reasons"].append(f"Length changed by {length_diff} bytes")
                if length_diff > 200:
                    diff["significant"] = True

        # Content comparison (error messages, sensitive data leaks)
        baseline_body = baseline.response_snippet.lower()
        comparison_body = comparison.response_snippet.lower()

        # Detect error message changes
        error_patterns = ["error", "exception", "stack trace", "debug", "sql", "mysql", "postgres", "undefined", "null pointer", "traceback", "internal server"]
        baseline_errors = [p for p in error_patterns if p in baseline_body]
        comparison_errors = [p for p in error_patterns if p in comparison_body]
        if baseline_errors != comparison_errors:
            diff["error_message_changed"] = True
            diff["reasons"].append(f"Error messages changed: {baseline_errors} -> {comparison_errors}")
            diff["significant"] = True

        # Detect different JSON structure
        try:
            import json
            b_json = json.loads(baseline.response_snippet)
            c_json = json.loads(comparison.response_snippet)
            b_keys = set(b_json.keys()) if isinstance(b_json, dict) else set()
            c_keys = set(c_json.keys()) if isinstance(c_json, dict) else set()
            if b_keys != c_keys:
                diff["content_changed"] = True
                diff["reasons"].append(f"JSON keys changed: {b_keys.symmetric_difference(c_keys)}")
                diff["significant"] = True
        except (json.JSONDecodeError, TypeError, AttributeError):
            pass

        # Detect privilege escalation indicators
        escalation_patterns = ["admin", "role", "permission", "unauthorized", "forbidden", "access denied"]
        for pattern in escalation_patterns:
            if pattern in comparison_body and pattern not in baseline_body:
                diff["reasons"].append(f"New privilege-related content: '{pattern}'")
                diff["significant"] = True

        # Timing difference (if available)
        if hasattr(baseline, 'elapsed') and hasattr(comparison, 'elapsed'):
            time_diff = abs(baseline.elapsed - comparison.elapsed)
            if time_diff > 2.0:  # More than 2 seconds different
                diff["reasons"].append(f"Timing difference: {time_diff:.1f}s (possible blind injection)")

        # Final significance
        if diff["reasons"]:
            diff["significant"] = True
            diff["reason"] = "; ".join(diff["reasons"])

        return diff

    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
        __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
                name
                kind
                fields {
                    name
                    args { name type { name kind ofType { name kind } } }
                    type { name kind ofType { name kind } }
                }
            }
            directives { name locations args { name type { name } } }
        }
    }
    """

    async def graphql_introspect(self, url: str, headers: dict | None = None) -> dict[str, Any]:
        """Run a GraphQL introspection query and return the schema."""
        result = await self.http.request(
            method="POST",
            url=url,
            headers={**(headers or {}), "Content-Type": "application/json"},
            body=json.dumps({"query": self.INTROSPECTION_QUERY}),
        )
        if result.get("error"):
            return {"error": result["error"], "status_code": result.get("status_code", 0)}

        try:
            data = json.loads(result["body"])
            schema = data.get("data", {}).get("__schema", {})
            types = schema.get("types", [])
            # Filter out built-in types
            user_types = [t for t in types if not t["name"].startswith("__")]
            return {
                "query_type": schema.get("queryType", {}).get("name"),
                "mutation_type": schema.get("mutationType", {}).get("name"),
                "types": user_types,
                "type_count": len(user_types),
                "raw": result["body"][:10000],
            }
        except (json.JSONDecodeError, TypeError, KeyError):
            return {"error": "Invalid introspection response", "body": result["body"][:2000]}

    async def graphql_test_batching(self, url: str, queries: list[str], headers: dict | None = None) -> dict[str, Any]:
        """Test query batching (multiple queries in one request)."""
        result = await self.http.request(
            method="POST",
            url=url,
            headers={**(headers or {}), "Content-Type": "application/json"},
            body=json.dumps({"query": queries}),
        )
        return {
            "status_code": result.get("status_code", 0),
            "body": result.get("body", "")[:5000],
            "error": result.get("error"),
        }

    async def graphql_test_field_suggestion(self, url: str, type_name: str, headers: dict | None = None) -> dict[str, Any]:
        """Test if GraphQL returns field suggestions (information disclosure)."""
        # Send a query with a typo to trigger suggestions
        query = '{ __type(name: "' + type_name + '") { fields { name } } }'
        result = await self.http.request(
            method="POST",
            url=url,
            headers={**(headers or {}), "Content-Type": "application/json"},
            body=json.dumps({"query": query}),
        )
        body = result.get("body", "")
        has_suggestion = "did you mean" in body.lower() or "suggestion" in body.lower()
        return {
            "status_code": result.get("status_code", 0),
            "has_field_suggestion": has_suggestion,
            "body": body[:3000],
        }

    async def full_replay_analysis(self, request: dict) -> dict[str, Any]:
        """Perform a complete replay analysis of a request.

        Returns:
            - baseline: The original replay result
            - mutations: List of all mutation results
            - findings: Any significant differences found
            - summary: Overall analysis summary
        """
        baseline = await self.replay(request, label="baseline")
        mutations = []
        findings = []

        # Auth bypass test
        no_auth = await self.replay_without_auth(request)
        diff = self.diff_responses(baseline, no_auth)
        mutations.append(no_auth)
        if diff["significant"]:
            findings.append({
                "type": "auth_bypass",
                "description": f"Response changed without auth: {diff.get('reason', 'unknown')}",
                "baseline_status": diff["baseline_status"],
                "comparison_status": diff["comparison_status"],
            })

        # CSRF test
        no_csrf = await self.replay_without_csrf(request)
        diff = self.diff_responses(baseline, no_csrf)
        mutations.append(no_csrf)
        if diff["significant"]:
            findings.append({
                "type": "csrf",
                "description": f"Response changed without CSRF: {diff.get('reason', 'unknown')}",
                "baseline_status": diff["baseline_status"],
                "comparison_status": diff["comparison_status"],
            })

        # Method override test
        for method in ["PUT", "PATCH", "DELETE"]:
            override = await self.replay_with_method_override(request, method)
            diff = self.diff_responses(baseline, override)
            mutations.append(override)
            if diff["significant"]:
                findings.append({
                    "type": "method_override",
                    "description": f"Method override to {method} changed response: {diff.get('reason', 'unknown')}",
                })

        return {
            "baseline": baseline,
            "mutations": mutations,
            "findings": findings,
            "summary": {
                "total_mutations": len(mutations),
                "significant_findings": len(findings),
                "baseline_status": baseline.status_code,
            },
        }


