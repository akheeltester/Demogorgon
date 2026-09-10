"""
authcore/boundary_tester.py — Cross-account boundary testing.

Provides AccountBoundaryTester: tests horizontal IDOR and vertical
privilege escalation across account boundaries.

Test methodology (human bug bounty hunter):
    1. Horizontal IDOR: User A accesses User B's objects
    2. Vertical privesc: Member accesses Admin endpoints
    3. Mass enumeration: Iterate ID patterns across accounts
    4. Session fixation: Does login properly invalidate old sessions?
    5. Concurrent sessions: Multiple sessions for same user
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from demogorgon.auth.authcore.session import AuthSession, UserRole
from demogorgon.auth.authcore.auth_client import AuthAwareClient
from demogorgon.auth.authcore.object_inventory import ObjectInventoryDB
from demogorgon.auth.authcore.store import AuthSessionStore

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Response comparison
# ---------------------------------------------------------------------------

_SUCCESS_CODES = {200, 201, 204}
_UNAUTHORIZED_CODES = {401, 403}


def _response_similar(resp1_bytes: bytes, resp2_bytes: bytes, threshold: float = 0.85) -> bool:
    """Check if two response bodies are similar enough to indicate data leakage."""
    if not resp1_bytes or not resp2_bytes:
        return False
    # Length similarity
    len1, len2 = len(resp1_bytes), len(resp2_bytes)
    if min(len1, len2) < 50:
        return False
    length_ratio = min(len1, len2) / max(len1, len2)
    if length_ratio < threshold:
        return False
    # Content similarity (Jaccard on words)
    words1 = set(resp1_bytes.decode("utf-8", errors="ignore").split())
    words2 = set(resp2_bytes.decode("utf-8", errors="ignore").split())
    if not words1 or not words2:
        return False
    intersection = words1 & words2
    union = words1 | words2
    jaccard = len(intersection) / len(union)
    return jaccard >= threshold


# ---------------------------------------------------------------------------
# AccountBoundaryTester
# ---------------------------------------------------------------------------

class AccountBoundaryTester:
    """
    Tests horizontal IDOR and vertical privilege escalation across accounts.

    Usage:
        tester = AccountBoundaryTester(inventory)

        # Test horizontal IDOR
        result = await tester.test_horizontal_idor(
            endpoint="/api/users/{victim_id}/profile",
            object_id="victim_123",
            owner_session=victim_session,
            attacker_session=attacker_session,
        )

        # Test vertical privilege escalation
        results = await tester.test_vertical_privilege_escalation(
            admin_endpoints=["/api/admin/users", "/api/admin/settings"],
            admin_session=admin_session,
            member_session=member_session,
        )

        # Full boundary test
        report = await tester.run_full_boundary_test(endpoints, sessions)
    """

    MAX_ENUM_IDS = 20
    MAX_EVIDENCE_LENGTH = 2000

    def __init__(
        self,
        inventory: ObjectInventoryDB,
        max_enum_ids: int = MAX_ENUM_IDS,
    ):
        self.inventory = inventory
        self.max_enum_ids = max_enum_ids
        self._test_results: List[Dict[str, Any]] = []

    # ── Horizontal IDOR ─────────────────────────────────────────────────

    async def test_horizontal_idor(
        self,
        endpoint: str,
        object_id: str,
        owner_session: AuthSession,
        attacker_session: AuthSession,
        method: str = "GET",
        payload: Optional[Dict[str, Any]] = None,
        url_pattern: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Test if attacker can access an object they don't own.

        Compares owner's access vs attacker's access:
            - Owner gets 200 + data → expected
            - Attacker gets 200 + similar data → IDOR breach
            - Attacker gets 401/403 → properly protected
            - Attacker gets 404 → access control working (or object doesn't exist)
        """
        # Build URL
        if url_pattern and "{id}" in url_pattern:
            url = url_pattern.replace("{id}", object_id)
        else:
            url = endpoint

        # Owner's access (baseline)
        owner_status = None
        owner_body = b""
        async with AuthAwareClient(owner_session) as client:
            resp = await client.request(method, url, json=payload)
            if resp:
                owner_status = resp.status_code
                owner_body = resp.content or b""

        # Attacker's access
        attacker_status = None
        attacker_body = b""
        async with AuthAwareClient(attacker_session) as client:
            resp = await client.request(method, url, json=payload)
            if resp:
                attacker_status = resp.status_code
                attacker_body = resp.content or b""

        # Classification
        is_breach = False
        breach_type = ""
        confidence = 0.0
        reason = ""

        if attacker_status in _UNAUTHORIZED_CODES:
            reason = "properly_protected"
            confidence = 1.0
        elif attacker_status == 404:
            reason = "not_found_or_no_access"
            confidence = 0.8
        elif attacker_status in _SUCCESS_CODES:
            if _response_similar(owner_body, attacker_body):
                is_breach = True
                breach_type = "horizontal_idor_read"
                confidence = 0.95
                reason = "attacker_got_owner_data"
            elif len(attacker_body) > 100:
                is_breach = True
                breach_type = "horizontal_idor_access"
                confidence = 0.6
                reason = "attacker_got_data_uncertain_match"
            else:
                reason = "attacker_got_success_different_data"
                confidence = 0.4
        elif attacker_status is None:
            reason = "request_failed"
            confidence = 0.0
        else:
            reason = f"attacker_status_{attacker_status}"
            confidence = 0.2

        result = {
            "test_type": "horizontal_idor",
            "endpoint": url,
            "method": method,
            "object_id": object_id,
            "owner_session": owner_session.label,
            "owner_role": owner_session.role.value,
            "attacker_session": attacker_session.label,
            "attacker_role": attacker_session.role.value,
            "owner_status": owner_status,
            "attacker_status": attacker_status,
            "is_breach": is_breach,
            "breach_type": breach_type,
            "confidence": confidence,
            "reason": reason,
            "evidence": {
                "owner_body_excerpt": owner_body[:self.MAX_EVIDENCE_LENGTH].decode("utf-8", errors="ignore"),
                "attacker_body_excerpt": attacker_body[:self.MAX_EVIDENCE_LENGTH].decode("utf-8", errors="ignore"),
            },
        }

        self._test_results.append(result)

        # Record in inventory
        if object_id:
            self.inventory.record_access_test(
                object_id=object_id,
                source_session_id=owner_session.session_id,
                source_role=owner_session.role.value,
                target_session_id=attacker_session.session_id,
                target_role=attacker_session.role.value,
                endpoint=url,
                method=method,
                status_code=attacker_status,
                response_length=len(attacker_body),
                is_breach=is_breach,
                breach_type=breach_type,
            )

        if is_breach:
            self.inventory.record_finding(
                finding_type="horizontal_idor",
                severity="high",
                object_type="resource",
                object_id=object_id,
                endpoint=url,
                method=method,
                source_session_id=owner_session.session_id,
                target_session_id=attacker_session.session_id,
                breach_description=(
                    f"Horizontal IDOR: {attacker_session.label} ({attacker_session.role.value}) "
                    f"can access {object_id} owned by {owner_session.label}"
                ),
                evidence=result["evidence"],
                recommendation="Implement object-level authorization. Verify user ownership before returning data.",
            )

        return result

    # ── Vertical privilege escalation ───────────────────────────────────

    async def test_vertical_privilege_escalation(
        self,
        admin_endpoints: List[str],
        admin_session: AuthSession,
        member_session: AuthSession,
        methods: Optional[List[str]] = None,
        payloads: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Test if a lower-privilege user can access admin-only endpoints.

        Tests each admin endpoint with the member session:
            - Member gets 200 → vertical privesc
            - Member gets 401/403 → properly protected
            - Member gets 404 → endpoint exists but access denied
        """
        if methods is None:
            methods = ["GET"]

        results = []
        payloads = payloads or {}

        async with AuthAwareClient(member_session) as client:
            for endpoint in admin_endpoints:
                for method in methods:
                    payload = payloads.get(endpoint)

                    try:
                        resp = await client.request(method, endpoint, json=payload)
                    except Exception as e:
                        results.append({
                            "test_type": "vertical_privesc",
                            "endpoint": endpoint,
                            "method": method,
                            "member_session": member_session.label,
                            "status_code": None,
                            "is_breach": False,
                            "reason": f"request_failed: {e}",
                        })
                        continue

                    if resp is None:
                        results.append({
                            "test_type": "vertical_privesc",
                            "endpoint": endpoint,
                            "method": method,
                            "member_session": member_session.label,
                            "status_code": None,
                            "is_breach": False,
                            "reason": "request_returned_none",
                        })
                        continue

                    is_breach = resp.status_code in _SUCCESS_CODES
                    result = {
                        "test_type": "vertical_privesc",
                        "endpoint": endpoint,
                        "method": method,
                        "member_session": member_session.label,
                        "member_role": member_session.role.value,
                        "admin_session": admin_session.label,
                        "status_code": resp.status_code,
                        "response_length": len(resp.content or b""),
                        "is_breach": is_breach,
                        "breach_type": "vertical_privesc" if is_breach else "",
                        "reason": "member_accessed_admin_endpoint" if is_breach else f"status_{resp.status_code}",
                        "evidence": {
                            "body_excerpt": (resp.content or b"")[:self.MAX_EVIDENCE_LENGTH].decode("utf-8", errors="ignore"),
                        },
                    }

                    results.append(result)
                    self._test_results.append(result)

                    if is_breach:
                        self.inventory.record_finding(
                            finding_type="vertical_privesc",
                            severity="critical",
                            object_type="admin_endpoint",
                            object_id=endpoint,
                            endpoint=endpoint,
                            method=method,
                            source_session_id=admin_session.session_id,
                            target_session_id=member_session.session_id,
                            breach_description=(
                                f"Vertical privilege escalation: {member_session.label} "
                                f"({member_session.role.value}) can access admin endpoint {endpoint}"
                            ),
                            evidence=result["evidence"],
                            recommendation="Implement role-based access control on admin endpoints.",
                        )

        return results

    # ── Mass enumeration ────────────────────────────────────────────────

    async def test_mass_enumeration(
        self,
        endpoint_pattern: str,
        sessions: List[AuthSession],
        id_range: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Test if object IDs are enumerable across accounts.

        Tests sequential/guessable IDs to detect mass enumeration.
        """
        if id_range is None:
            id_range = [str(i) for i in range(1, self.max_enum_ids + 1)]

        results = []

        for session in sessions:
            async with AuthAwareClient(session) as client:
                for obj_id in id_range[:self.max_enum_ids]:
                    url = endpoint_pattern.replace("{id}", obj_id)
                    try:
                        resp = await client.get(url)
                        if resp and resp.status_code in _SUCCESS_CODES:
                            results.append({
                                "test_type": "mass_enumeration",
                                "endpoint": url,
                                "session": session.label,
                                "role": session.role.value,
                                "object_id": obj_id,
                                "status_code": resp.status_code,
                                "response_length": len(resp.content or b""),
                                "is_enumerable": True,
                            })
                    except Exception:
                        pass

        # Check if multiple objects were enumerable
        if len(results) > 3:
            self.inventory.record_finding(
                finding_type="mass_enumeration",
                severity="medium",
                object_type="enumerable_resource",
                object_id="multiple",
                endpoint=endpoint_pattern,
                method="GET",
                source_session_id=sessions[0].session_id if sessions else "",
                target_session_id="",
                breach_description=(
                    f"Mass enumeration: {len(results)} objects accessible via "
                    f"sequential IDs at {endpoint_pattern}"
                ),
                evidence={"enumerated_count": len(results)},
                recommendation="Use UUIDs instead of sequential IDs. Implement rate limiting on list endpoints.",
            )

        return results

    # ── Session fixation ────────────────────────────────────────────────

    async def test_session_fixation(
        self,
        login_endpoint: str,
        pre_login_session: AuthSession,
        post_login_session: AuthSession,
        protected_endpoint: str,
    ) -> Dict[str, Any]:
        """
        Test if old session remains valid after login with new session.

        Session fixation: attacker sets a known session ID, victim logs in,
        attacker uses the known session ID to access victim's account.
        """
        # Check pre-login session validity
        pre_valid = False
        async with AuthAwareClient(pre_login_session) as client:
            resp = await client.get(protected_endpoint)
            if resp:
                pre_valid = resp.status_code in _SUCCESS_CODES

        # Check post-login session validity
        post_valid = False
        async with AuthAwareClient(post_login_session) as client:
            resp = await client.get(protected_endpoint)
            if resp:
                post_valid = resp.status_code in _SUCCESS_CODES

        # If pre-login session still works after login → session fixation
        is_vulnerable = pre_valid and post_valid

        result = {
            "test_type": "session_fixation",
            "login_endpoint": login_endpoint,
            "protected_endpoint": protected_endpoint,
            "pre_login_session": pre_login_session.label,
            "post_login_session": post_login_session.label,
            "pre_login_valid": pre_valid,
            "post_login_valid": post_valid,
            "is_vulnerable": is_vulnerable,
        }

        self._test_results.append(result)

        if is_vulnerable:
            self.inventory.record_finding(
                finding_type="session_fixation",
                severity="high",
                object_type="session",
                object_id=pre_login_session.session_id,
                endpoint=login_endpoint,
                method="POST",
                source_session_id=pre_login_session.session_id,
                target_session_id=post_login_session.session_id,
                breach_description=(
                    f"Session fixation: pre-login session remains valid "
                    f"after authentication at {login_endpoint}"
                ),
                evidence=result,
                recommendation="Invalidate old sessions on login. Generate new session ID after authentication.",
            )

        return result

    # ── Concurrent sessions ─────────────────────────────────────────────

    async def test_concurrent_session_enforcement(
        self,
        endpoint: str,
        sessions: List[AuthSession],
        max_concurrent: int = 1,
    ) -> Dict[str, Any]:
        """
        Test if the application enforces single-session policy.

        If max_concurrent=1, only one session should be valid at a time.
        Creating a second session should invalidate the first.
        """
        if len(sessions) < 2:
            return {
                "test_type": "concurrent_sessions",
                "is_vulnerable": False,
                "reason": "need_at_least_2_sessions",
            }

        # Check all sessions are valid
        valid_sessions = []
        for session in sessions:
            async with AuthAwareClient(session) as client:
                resp = await client.get(endpoint)
                if resp and resp.status_code in _SUCCESS_CODES:
                    valid_sessions.append(session)

        # If multiple sessions are valid simultaneously → vulnerability
        is_vulnerable = len(valid_sessions) > max_concurrent

        result = {
            "test_type": "concurrent_sessions",
            "endpoint": endpoint,
            "total_sessions": len(sessions),
            "valid_sessions": len(valid_sessions),
            "max_concurrent_allowed": max_concurrent,
            "is_vulnerable": is_vulnerable,
            "valid_session_labels": [s.label for s in valid_sessions],
        }

        self._test_results.append(result)

        if is_vulnerable:
            self.inventory.record_finding(
                finding_type="concurrent_session",
                severity="medium",
                object_type="session",
                object_id="multiple",
                endpoint=endpoint,
                method="GET",
                source_session_id=sessions[0].session_id,
                target_session_id=sessions[1].session_id,
                breach_description=(
                    f"Concurrent session vulnerability: {len(valid_sessions)} "
                    f"simultaneous sessions active (max allowed: {max_concurrent})"
                ),
                evidence=result,
                recommendation="Invalidate previous sessions when a new session is created.",
            )

        return result

    # ── Full boundary test ──────────────────────────────────────────────

    async def run_full_boundary_test(
        self,
        endpoints: List[Dict[str, Any]],
        sessions: List[AuthSession],
        role_groups: Optional[Dict[str, List[str]]] = None,
    ) -> Dict[str, Any]:
        """
        Run comprehensive boundary testing across all endpoints and sessions.

        Args:
            endpoints: [{"url": "/api/{id}", "method": "GET", "object_id": "123"}]
            sessions: All available sessions
            role_groups: {"admin": ["session_a"], "member": ["session_b"]}

        Returns:
            Complete boundary test report
        """
        results = []

        # Group sessions by role
        if role_groups is None:
            role_groups = {}
            for s in sessions:
                role_groups.setdefault(s.role.value, []).append(s.session_id)

        # Horizontal IDOR: test each endpoint pair
        for spec in endpoints:
            url = spec.get("url", "")
            method = spec.get("method", "GET")
            object_id = spec.get("object_id", "")

            # Find owner and non-owner sessions
            for i, owner in enumerate(sessions):
                for j, attacker in enumerate(sessions):
                    if i == j:
                        continue
                    if owner.session_id == attacker.session_id:
                        continue

                    result = await self.test_horizontal_idor(
                        endpoint=url,
                        object_id=object_id,
                        owner_session=owner,
                        attacker_session=attacker,
                        method=method,
                    )
                    results.append(result)

        # Vertical privesc: test admin endpoints with lower roles
        admin_endpoints = [s.get("url", "") for s in endpoints if s.get("requires_admin")]
        if admin_endpoints:
            for role, session_ids in role_groups.items():
                if role in ("admin", "owner"):
                    continue
                for sid in session_ids:
                    member = next((s for s in sessions if s.session_id == sid), None)
                    if not member:
                        continue
                    admin_session = sessions[0]  # Use first session as admin reference
                    v_results = await self.test_vertical_privilege_escalation(
                        admin_endpoints=admin_endpoints,
                        admin_session=admin_session,
                        member_session=member,
                    )
                    results.extend(v_results)

        return self.build_boundary_report()

    # ── Reporting ───────────────────────────────────────────────────────

    def build_boundary_report(self) -> Dict[str, Any]:
        """Build comprehensive boundary test report."""
        total = len(self._test_results)
        breaches = [r for r in self._test_results if r.get("is_breach")]

        by_type: Dict[str, int] = {}
        for r in breaches:
            bt = r.get("breach_type", r.get("test_type", "unknown"))
            by_type[bt] = by_type.get(bt, 0) + 1

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_tests": total,
                "total_breaches": len(breaches),
                "breach_types": by_type,
            },
            "findings": self.inventory.get_findings(),
            "unreported_findings": self.inventory.get_unreported_findings(),
            "test_results": self._test_results,
        }

    def __repr__(self) -> str:
        breaches = sum(1 for r in self._test_results if r.get("is_breach"))
        return f"AccountBoundaryTester(tests={len(self._test_results)}, breaches={breaches})"
