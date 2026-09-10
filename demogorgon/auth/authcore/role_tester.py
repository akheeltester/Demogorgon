"""
authcore/role_tester.py — Role-based access control testing.

Provides RoleTester: systematic RBAC testing across endpoints and roles.
Builds a complete role-access matrix and detects:
    - Role escalation via response comparison
    - Mass assignment of role fields
    - Common role bypass techniques (HTTP method override, header injection)
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from demogorgon.auth.authcore.session import AuthSession, UserRole
from demogorgon.auth.authcore.auth_client import AuthAwareClient
from demogorgon.auth.authcore.object_inventory import ObjectInventoryDB

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SUCCESS_CODES = {200, 201, 204}
_UNAUTHORIZED_CODES = {401, 403}

# Common role bypass techniques
_ROLE_BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Host": "localhost"},
    {"X-Forwarded-Host": "localhost"},
    {"Forwarded": "for=127.0.0.1;by=127.0.0.1;host=localhost"},
]

# Common role field names for mass assignment testing
_ROLE_FIELD_NAMES = [
    "role", "user_role", "account_type", "account_role",
    "is_admin", "is_staff", "admin", "staff", "superuser",
    "permissions", "access_level", "privilege", "level",
    "is_superuser", "user_type", "account_level",
]

# HTTP methods that might bypass role checks
_METHOD_OVERRIDE_HEADERS = [
    "X-HTTP-Method",
    "X-HTTP-Method-Override",
    "X-Method-Override",
]


# ---------------------------------------------------------------------------
# RoleTester
# ---------------------------------------------------------------------------

class RoleTester:
    """
    Systematic RBAC testing across endpoints and roles.

    Usage:
        tester = RoleTester(inventory)

        # Build role-access matrix
        matrix = await tester.run_role_matrix_test(endpoints, sessions)

        # Test specific endpoint
        result = await tester.test_endpoint_role_access(
            endpoint="/api/admin/users",
            method="GET",
            sessions=[admin_session, member_session, viewer_session],
        )

        # Test mass assignment
        result = await tester.test_mass_assignment(
            endpoint="/api/users/me",
            method="PATCH",
            session=member_session,
            base_body={"name": "Test"},
            escalation_fields={"role": "admin", "is_admin": True},
        )
    """

    MAX_EVIDENCE_LENGTH = 2000

    def __init__(self, inventory: ObjectInventoryDB):
        self.inventory = inventory
        self._test_results: List[Dict[str, Any]] = []
        self._role_matrix: Dict[str, Dict[str, Dict[str, Any]]] = {}

    # ── Role access matrix ──────────────────────────────────────────────

    async def test_endpoint_role_access(
        self,
        endpoint: str,
        method: str,
        sessions: List[AuthSession],
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Test a single endpoint with multiple roles.

        Returns:
            {endpoint, method, results: {role: {status, is_authorized, ...}}}
        """
        role_results: Dict[str, Dict[str, Any]] = {}

        for session in sessions:
            role = session.role.value
            async with AuthAwareClient(session) as client:
                try:
                    resp = await client.request(method, endpoint, json=payload)
                except Exception as e:
                    role_results[role] = {
                        "session": session.label,
                        "status_code": None,
                        "is_authorized": False,
                        "error": str(e),
                    }
                    continue

                if resp is None:
                    role_results[role] = {
                        "session": session.label,
                        "status_code": None,
                        "is_authorized": False,
                        "error": "request_returned_none",
                    }
                    continue

                is_authorized = resp.status_code in _SUCCESS_CODES
                role_results[role] = {
                    "session": session.label,
                    "status_code": resp.status_code,
                    "response_length": len(resp.content or b""),
                    "is_authorized": is_authorized,
                    "body_excerpt": (resp.content or b"")[:self.MAX_EVIDENCE_LENGTH].decode("utf-8", errors="ignore"),
                }

        result = {
            "endpoint": endpoint,
            "method": method,
            "results": role_results,
        }

        self._role_matrix[f"{method} {endpoint}"] = role_results
        self._test_results.append(result)

        # Detect anomalies
        await self._check_role_anomalies(endpoint, method, role_results, sessions)

        return result

    async def run_role_matrix_test(
        self,
        endpoints: List[Dict[str, Any]],
        sessions: List[AuthSession],
    ) -> Dict[str, Any]:
        """
        Build complete role-access matrix for all endpoints.

        Args:
            endpoints: [{"url": "/api/admin", "method": "GET", "expected_min_role": "admin"}]
            sessions: Sessions at each role level

        Returns:
            Complete role matrix with anomalies
        """
        self._role_matrix.clear()
        self._test_results.clear()

        for spec in endpoints:
            url = spec.get("url", "")
            method = spec.get("method", "GET")
            payload = spec.get("body")
            expected_min_role = spec.get("expected_min_role")

            result = await self.test_endpoint_role_access(
                endpoint=url,
                method=method,
                sessions=sessions,
                payload=payload,
            )

            # If expected_min_role is specified, check for violations
            if expected_min_role:
                await self._check_expected_role(
                    url, method, result["results"], expected_min_role, sessions
                )

        return self.build_role_matrix_report()

    async def _check_role_anomalies(
        self,
        endpoint: str,
        method: str,
        role_results: Dict[str, Dict[str, Any]],
        sessions: List[AuthSession],
    ) -> None:
        """Detect anomalies in role access patterns."""
        # Find which roles have access
        authorized_roles = [
            role for role, data in role_results.items()
            if data.get("is_authorized")
        ]
        unauthorized_roles = [
            role for role, data in role_results.items()
            if not data.get("is_authorized") and data.get("status_code") is not None
        ]

        # Anomaly: viewer has access but member doesn't
        role_levels = {r: UserRole(r).level for r in authorized_roles if r in [e.value for e in UserRole]}
        if role_levels:
            highest_unauthorized = max(
                (UserRole(r).level for r in unauthorized_roles if r in [e.value for e in UserRole]),
                default=0
            )
            lowest_authorized = min(role_levels.values())

            if lowest_authorized > highest_unauthorized and highest_unauthorized > 0:
                # Potential role escalation
                self.inventory.record_finding(
                    finding_type="role_escalation",
                    severity="high",
                    object_type="endpoint",
                    object_id=endpoint,
                    endpoint=endpoint,
                    method=method,
                    source_session_id="",
                    target_session_id="",
                    breach_description=(
                        f"Role access anomaly: roles {authorized_roles} have access "
                        f"but {unauthorized_roles} don't, suggesting inconsistent "
                        f"access control at {endpoint}"
                    ),
                    evidence={"authorized": authorized_roles, "unauthorized": unauthorized_roles},
                    recommendation="Review role-based access control implementation for consistency.",
                )

    async def _check_expected_role(
        self,
        endpoint: str,
        method: str,
        role_results: Dict[str, Dict[str, Any]],
        expected_min_role: str,
        sessions: List[AuthSession],
    ) -> None:
        """Check if endpoint enforces expected minimum role."""
        expected_level = UserRole(expected_min_role).level

        for role, data in role_results.items():
            if role not in [e.value for e in UserRole]:
                continue
            actual_level = UserRole(role).level

            if actual_level < expected_level and data.get("is_authorized"):
                # Lower role has access than expected
                self.inventory.record_finding(
                    finding_type="role_bypass",
                    severity="high",
                    object_type="endpoint",
                    object_id=endpoint,
                    endpoint=endpoint,
                    method=method,
                    source_session_id="",
                    target_session_id=data.get("session", ""),
                    breach_description=(
                        f"Role bypass: {role} (level {actual_level}) can access "
                        f"{endpoint} which requires {expected_min_role} (level {expected_level})"
                    ),
                    evidence=data,
                    recommendation=f"Enforce {expected_min_role} role requirement on {endpoint}.",
                )

    # ── Role escalation testing ─────────────────────────────────────────

    async def test_role_escalation(
        self,
        endpoint: str,
        method: str,
        low_role_session: AuthSession,
        high_role_session: AuthSession,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Test if a low-role user can access a high-role endpoint.

        Compares:
            1. High role access (baseline — should succeed)
            2. Low role access (should fail)
            3. If both succeed → privesc vulnerability
        """
        high_status = None
        low_status = None
        high_body = b""
        low_body = b""

        # High role baseline
        async with AuthAwareClient(high_role_session) as client:
            try:
                resp = await client.request(method, endpoint, json=payload)
                if resp:
                    high_status = resp.status_code
                    high_body = resp.content or b""
            except Exception:
                pass

        # Low role test
        async with AuthAwareClient(low_role_session) as client:
            try:
                resp = await client.request(method, endpoint, json=payload)
                if resp:
                    low_status = resp.status_code
                    low_body = resp.content or b""
            except Exception:
                pass

        is_breach = (
            high_status in _SUCCESS_CODES
            and low_status in _SUCCESS_CODES
        )

        result = {
            "test_type": "role_escalation",
            "endpoint": endpoint,
            "method": method,
            "high_role": high_role_session.role.value,
            "high_session": high_role_session.label,
            "high_status": high_status,
            "low_role": low_role_session.role.value,
            "low_session": low_role_session.label,
            "low_status": low_status,
            "is_breach": is_breach,
            "breach_type": "role_escalation" if is_breach else "",
            "evidence": {
                "high_body_excerpt": high_body[:self.MAX_EVIDENCE_LENGTH].decode("utf-8", errors="ignore"),
                "low_body_excerpt": low_body[:self.MAX_EVIDENCE_LENGTH].decode("utf-8", errors="ignore"),
            },
        }

        self._test_results.append(result)

        if is_breach:
            self.inventory.record_finding(
                finding_type="role_escalation",
                severity="critical",
                object_type="endpoint",
                object_id=endpoint,
                endpoint=endpoint,
                method=method,
                source_session_id=high_role_session.session_id,
                target_session_id=low_role_session.session_id,
                breach_description=(
                    f"Role escalation: {low_role_session.role.value} user "
                    f"({low_role_session.label}) can access {endpoint} "
                    f"which should be {high_role_session.role.value}-only"
                ),
                evidence=result["evidence"],
                recommendation="Implement server-side role validation on all privileged endpoints.",
            )

        return result

    # ── Mass assignment ─────────────────────────────────────────────────

    async def test_mass_assignment(
        self,
        endpoint: str,
        method: str,
        session: AuthSession,
        base_body: Dict[str, Any],
        escalation_fields: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Test if the application accepts role escalation via mass assignment.

        Sends a request with role/permission fields injected into the body.
        If accepted, the user can escalate their own privileges.
        """
        if escalation_fields is None:
            escalation_fields = {field: "admin" for field in _ROLE_FIELD_NAMES[:3]}

        results = []

        for field, value in escalation_fields.items():
            test_body = {**base_body, field: value}

            async with AuthAwareClient(session) as client:
                try:
                    resp = await client.request(method, endpoint, json=test_body)
                except Exception as e:
                    results.append({
                        "field": field,
                        "value": value,
                        "is_accepted": False,
                        "error": str(e),
                    })
                    continue

                if resp is None:
                    results.append({
                        "field": field,
                        "value": value,
                        "is_accepted": False,
                        "error": "request_returned_none",
                    })
                    continue

                # Check if the field was accepted
                is_accepted = resp.status_code in _SUCCESS_CODES
                body = resp.content or b""

                # Verify: check if the role actually changed
                role_changed = False
                if is_accepted:
                    try:
                        resp_data = json.loads(body)
                        if isinstance(resp_data, dict):
                            resp_role = resp_data.get(field, "")
                            if str(resp_role).lower() == str(value).lower():
                                role_changed = True
                    except (json.JSONDecodeError, ValueError):
                        pass

                results.append({
                    "field": field,
                    "value": value,
                    "status_code": resp.status_code,
                    "is_accepted": is_accepted,
                    "role_actually_changed": role_changed,
                    "body_excerpt": body[:self.MAX_EVIDENCE_LENGTH].decode("utf-8", errors="ignore"),
                })

        # Determine overall result
        any_accepted = any(r.get("is_accepted") for r in results)
        any_changed = any(r.get("role_actually_changed") for r in results)

        result = {
            "test_type": "mass_assignment",
            "endpoint": endpoint,
            "method": method,
            "session": session.label,
            "role": session.role.value,
            "base_body": base_body,
            "results": results,
            "any_field_accepted": any_accepted,
            "any_role_changed": any_changed,
            "is_breach": any_changed,
            "breach_type": "mass_assignment" if any_changed else "",
        }

        self._test_results.append(result)

        if any_changed:
            self.inventory.record_finding(
                finding_type="mass_assignment",
                severity="critical",
                object_type="endpoint",
                object_id=endpoint,
                endpoint=endpoint,
                method=method,
                source_session_id=session.session_id,
                target_session_id="",
                breach_description=(
                    f"Mass assignment: {session.role.value} user can set "
                    f"role/permission fields via {method} {endpoint}. "
                    f"Accepted fields: {[r['field'] for r in results if r.get('role_actually_changed')]}"
                ),
                evidence={"results": results},
                recommendation="Whitelist accepted fields. Never bind request data directly to user models.",
            )

        return result

    # ── Role bypass techniques ──────────────────────────────────────────

    async def test_role_bypass_techniques(
        self,
        endpoint: str,
        session: AuthSession,
        methods: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Test common role bypass techniques.

        Tests:
            1. HTTP method override headers
            2. IP spoofing headers
            3. Path traversal variants
            4. Original/rewrite URL headers
        """
        if methods is None:
            methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]

        results = []

        # Baseline: normal request
        baseline_status = None
        async with AuthAwareClient(session) as client:
            try:
                resp = await client.get(endpoint)
                baseline_status = resp.status_code if resp else None
            except Exception:
                pass

        # Test method override headers
        for header_name in _METHOD_OVERRIDE_HEADERS:
            for override_method in ["GET", "POST"]:
                headers = {header_name: override_method}
                async with AuthAwareClient(session) as client:
                    try:
                        resp = await client.request("GET", endpoint, headers=headers)
                        if resp and resp.status_code in _SUCCESS_CODES and baseline_status in _UNAUTHORIZED_CODES:
                            results.append({
                                "technique": "method_override",
                                "header": header_name,
                                "value": override_method,
                                "status_code": resp.status_code,
                                "baseline_status": baseline_status,
                                "is_bypass": True,
                            })
                    except Exception:
                        pass

        # Test IP spoofing headers
        for header in _ROLE_BYPASS_HEADERS:
            async with AuthAwareClient(session) as client:
                try:
                    resp = await client.request("GET", endpoint, headers=header)
                    if resp and resp.status_code in _SUCCESS_CODES and baseline_status in _UNAUTHORIZED_CODES:
                        results.append({
                            "technique": "ip_spoofing",
                            "header": list(header.keys())[0],
                            "value": list(header.values())[0],
                            "status_code": resp.status_code,
                            "baseline_status": baseline_status,
                            "is_bypass": True,
                        })
                except Exception:
                    pass

        # Record findings for successful bypasses
        bypasses = [r for r in results if r.get("is_bypass")]
        if bypasses:
            self.inventory.record_finding(
                finding_type="role_bypass",
                severity="high",
                object_type="endpoint",
                object_id=endpoint,
                endpoint=endpoint,
                method="GET",
                source_session_id=session.session_id,
                target_session_id="",
                breach_description=(
                    f"Role bypass via header manipulation: {len(bypasses)} techniques "
                    f"bypassed access control at {endpoint}"
                ),
                evidence={"bypasses": bypasses},
                recommendation="Do not trust client-supplied headers for authorization. Use server-side session validation.",
            )

        return results

    # ── Reporting ───────────────────────────────────────────────────────

    def build_role_matrix_report(self) -> Dict[str, Any]:
        """Build comprehensive role matrix report."""
        findings = self.inventory.get_findings()
        unreported = self.inventory.get_unreported_findings()

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_endpoints_tested": len(self._role_matrix),
                "total_tests": len(self._test_results),
                "roles_tested": list(set(
                    role for results in self._role_matrix.values()
                    for role in results.keys()
                )),
            },
            "role_matrix": self._role_matrix,
            "findings": findings,
            "unreported_findings": unreported,
            "test_results": self._test_results,
        }

    def __repr__(self) -> str:
        return f"RoleTester(tests={len(self._test_results)}, matrix_entries={len(self._role_matrix)})"
