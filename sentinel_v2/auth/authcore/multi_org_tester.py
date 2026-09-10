"""
authcore/multi_org_tester.py — Cross-tenant IDOR detection.

Provides MultiOrgTester: tests whether users from Organization A can
access resources belonging to Organization B. Critical for SaaS targets.

Cross-tenant attack patterns:
    1. IDOR across orgs: /api/orgs/{org_id}/data → swap org_id
    2. JWT claim manipulation: org_id in JWT → forge different org
    3. API key scope: API key for org A → access org B endpoints
    4. Shared resources: files, webhooks, integrations across orgs
    5. Invitation/invite link: org A invites user to org B
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, quote

from sentinel_v2.auth.authcore.session import AuthSession, UserRole, OrgMeta
from sentinel_v2.auth.authcore.auth_client import AuthAwareClient
from sentinel_v2.auth.authcore.object_inventory import ObjectInventoryDB

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SUCCESS_CODES = {200, 201, 204}
_UNAUTHORIZED_CODES = {401, 403}

# Common URL patterns containing org_id
_ORG_ID_PATTERNS = [
    "/orgs/{org_id}",
    "/organizations/{org_id}",
    "/teams/{org_id}",
    "/workspace/{org_id}",
    "/v1/org/{org_id}",
    "/api/v1/organizations/{org_id}",
    "/api/org/{org_id}",
]


# ---------------------------------------------------------------------------
# MultiOrgTester
# ---------------------------------------------------------------------------

class MultiOrgTester:
    """
    Cross-tenant IDOR testing for multi-organization SaaS applications.

    Usage:
        tester = MultiOrgTester(inventory)

        # Test cross-org access
        result = await tester.test_cross_org_access(
            endpoint="/api/orgs/{org_id}/members",
            source_session=org_a_member,
            target_org_sessions=[org_b_member, org_b_admin],
        )

        # Test org_id parameter tampering
        result = await tester.test_org_id_tampering(
            endpoint="/api/data",
            session=org_a_session,
            original_org_id="org_a_123",
            target_org_ids=["org_b_456", "org_c_789"],
        )

        # Test invitation flow
        result = await tester.test_cross_org_invitation(
            invite_endpoint="/api/invitations",
            accept_endpoint="/api/invitations/accept",
            inviter_session=org_a_admin,
            target_org_session=org_b_member,
        )

        # Full cross-org test suite
        report = await tester.run_full_multi_org_test(endpoints, sessions_by_org)
    """

    MAX_EVIDENCE_LENGTH = 2000
    MAX_ENUM_ORGS = 20

    def __init__(self, inventory: ObjectInventoryDB):
        self.inventory = inventory
        self._test_results: List[Dict[str, Any]] = []

    # ── Cross-org access ────────────────────────────────────────────────

    async def test_cross_org_access(
        self,
        endpoint: str,
        source_session: AuthSession,
        target_org_sessions: List[AuthSession],
        url_pattern: Optional[str] = None,
        method: str = "GET",
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Test if a user from one org can access resources of another org.

        Args:
            endpoint: URL to test (may contain {org_id} placeholder)
            source_session: Session that owns the resource (org A)
            target_org_sessions: Sessions from other orgs (org B, C, ...)
            url_pattern: URL pattern with {org_id} placeholder
        """
        results = []

        # Build URL for source org
        source_org_id = source_session.org.org_id
        if url_pattern:
            source_url = url_pattern.replace("{org_id}", source_org_id)
        else:
            source_url = endpoint

        # Source org access (baseline)
        source_status = None
        source_body = b""
        async with AuthAwareClient(source_session) as client:
            try:
                resp = await client.request(method, source_url, json=payload)
                if resp:
                    source_status = resp.status_code
                    source_body = resp.content or b""
            except Exception:
                pass

        # Test each target org session
        for target_session in target_org_sessions:
            target_org_id = target_session.org.org_id

            if target_org_id == source_org_id:
                continue  # Skip same org

            if url_pattern:
                test_url = url_pattern.replace("{org_id}", target_org_id)
            else:
                test_url = endpoint

            async with AuthAwareClient(target_session) as client:
                try:
                    resp = await client.request(method, test_url, json=payload)
                except Exception as e:
                    results.append({
                        "target_org": target_org_id,
                        "target_session": target_session.label,
                        "error": str(e),
                        "is_breach": False,
                    })
                    continue

                if resp is None:
                    results.append({
                        "target_org": target_org_id,
                        "target_session": target_session.label,
                        "error": "request_returned_none",
                        "is_breach": False,
                    })
                    continue

                is_breach = resp.status_code in _SUCCESS_CODES
                body = resp.content or b""

                result = {
                    "target_org": target_org_id,
                    "target_session": target_session.label,
                    "target_role": target_session.role.value,
                    "status_code": resp.status_code,
                    "response_length": len(body),
                    "is_breach": is_breach,
                    "breach_type": "cross_org_idor" if is_breach else "",
                    "evidence": {
                        "body_excerpt": body[:self.MAX_EVIDENCE_LENGTH].decode("utf-8", errors="ignore"),
                    },
                }
                results.append(result)

                if is_breach:
                    self.inventory.record_finding(
                        finding_type="cross_org_idor",
                        severity="critical",
                        object_type="org_resource",
                        object_id=f"{source_org_id}/{target_org_id}",
                        endpoint=test_url,
                        method=method,
                        source_session_id=source_session.session_id,
                        target_session_id=target_session.session_id,
                        breach_description=(
                            f"Cross-tenant IDOR: user from org {target_org_id} "
                            f"({target_session.label}) can access resources of "
                            f"org {source_org_id} at {test_url}"
                        ),
                        evidence=result["evidence"],
                        recommendation="Implement organization-level authorization on all multi-tenant endpoints.",
                    )

        overall_result = {
            "test_type": "cross_org_access",
            "endpoint": endpoint,
            "url_pattern": url_pattern,
            "source_org": source_org_id,
            "source_session": source_session.label,
            "source_status": source_status,
            "results": results,
            "any_breach": any(r.get("is_breach") for r in results),
        }

        self._test_results.append(overall_result)
        return overall_result

    # ── Org ID parameter tampering ──────────────────────────────────────

    async def test_org_id_tampering(
        self,
        endpoint: str,
        session: AuthSession,
        original_org_id: str,
        target_org_ids: List[str],
        method: str = "GET",
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Test if org_id can be tampered in request body/params.

        Some apps use org_id from JWT/session, but also accept it
        in the request body. If the body value overrides the JWT value,
        the user can access other orgs' data.
        """
        results = []

        # Tamper in URL
        for target_org_id in target_org_ids:
            test_url = endpoint.replace(original_org_id, target_org_id)

            async with AuthAwareClient(session) as client:
                try:
                    resp = await client.request(method, test_url, json=payload)
                except Exception as e:
                    results.append({
                        "technique": "url_tampering",
                        "target_org": target_org_id,
                        "error": str(e),
                        "is_breach": False,
                    })
                    continue

                if resp is None:
                    continue

                is_breach = resp.status_code in _SUCCESS_CODES
                results.append({
                    "technique": "url_tampering",
                    "target_org": target_org_id,
                    "status_code": resp.status_code,
                    "is_breach": is_breach,
                })

                if is_breach:
                    self.inventory.record_finding(
                        finding_type="cross_org_idor",
                        severity="critical",
                        object_type="org_resource",
                        object_id=f"{original_org_id}/{target_org_id}",
                        endpoint=test_url,
                        method=method,
                        source_session_id=session.session_id,
                        target_session_id="",
                        breach_description=(
                            f"Cross-tenant IDOR via URL tampering: user from org "
                            f"{original_org_id} can access org {target_org_id} "
                            f"data by modifying URL"
                        ),
                        evidence={"technique": "url_tampering", "target_org": target_org_id},
                        recommendation="Do not use org_id from request parameters. Use the org_id from the authenticated session.",
                    )

        # Tamper in request body
        if payload is None:
            payload = {}

        for target_org_id in target_org_ids:
            tampered_body = {**payload, "org_id": target_org_id, "organization_id": target_org_id}

            async with AuthAwareClient(session) as client:
                try:
                    resp = await client.request(method, endpoint, json=tampered_body)
                except Exception:
                    continue

                if resp is None:
                    continue

                is_breach = resp.status_code in _SUCCESS_CODES
                results.append({
                    "technique": "body_tampering",
                    "target_org": target_org_id,
                    "status_code": resp.status_code,
                    "is_breach": is_breach,
                })

                if is_breach:
                    self.inventory.record_finding(
                        finding_type="cross_org_idor",
                        severity="critical",
                        object_type="org_resource",
                        object_id=f"{original_org_id}/{target_org_id}",
                        endpoint=endpoint,
                        method=method,
                        source_session_id=session.session_id,
                        target_session_id="",
                        breach_description=(
                            f"Cross-tenant IDOR via body tampering: user from org "
                            f"{original_org_id} can access org {target_org_id} "
                            f"data by modifying org_id in request body"
                        ),
                        evidence={"technique": "body_tampering", "target_org": target_org_id},
                        recommendation="Do not accept org_id from request body. Use the org_id from the authenticated session/JWT.",
                    )

        overall_result = {
            "test_type": "org_id_tampering",
            "endpoint": endpoint,
            "original_org": original_org_id,
            "session": session.label,
            "results": results,
            "any_breach": any(r.get("is_breach") for r in results),
        }

        self._test_results.append(overall_result)
        return overall_result

    # ── Invitation flow ─────────────────────────────────────────────────

    async def test_cross_org_invitation(
        self,
        invite_endpoint: str,
        accept_endpoint: str,
        inviter_session: AuthSession,
        target_org_session: AuthSession,
        invite_payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Test if invitation flow can be abused for cross-org access.

        Attack: Org A admin invites a user to org A, but the invitation
        acceptance endpoint can be modified to add the user to org B instead.
        """
        target_org_id = target_org_session.org.org_id
        inviter_org_id = inviter_session.org.org_id

        # Step 1: Inviter creates invitation
        invitation_id = None
        async with AuthAwareClient(inviter_session) as client:
            try:
                payload = invite_payload or {
                    "email": "test@example.com",
                    "role": "member",
                }
                resp = await client.post(invite_endpoint, json=payload)
                if resp and resp.status_code in {200, 201}:
                    try:
                        data = resp.json()
                        invitation_id = data.get("id") or data.get("invitation_id")
                    except (json.JSONDecodeError, ValueError):
                        pass
            except Exception:
                pass

        if not invitation_id:
            return {
                "test_type": "cross_org_invitation",
                "is_breach": False,
                "reason": "could_not_create_invitation",
            }

        # Step 2: Try to accept with target org session
        async with AuthAwareClient(target_org_session) as client:
            try:
                accept_payload = {
                    "invitation_id": invitation_id,
                    "org_id": target_org_id,
                }
                resp = await client.post(accept_endpoint, json=accept_payload)
                is_breach = resp is not None and resp.status_code in _SUCCESS_CODES
            except Exception as e:
                is_breach = False

        result = {
            "test_type": "cross_org_invitation",
            "invitation_id": invitation_id,
            "inviter_org": inviter_org_id,
            "target_org": target_org_id,
            "is_breach": is_breach,
            "breach_type": "cross_org_invitation" if is_breach else "",
        }

        self._test_results.append(result)

        if is_breach:
            self.inventory.record_finding(
                finding_type="cross_org_invitation",
                severity="critical",
                object_type="invitation",
                object_id=invitation_id,
                endpoint=accept_endpoint,
                method="POST",
                source_session_id=inviter_session.session_id,
                target_session_id=target_org_session.session_id,
                breach_description=(
                    f"Cross-tenant invitation abuse: invitation from org "
                    f"{inviter_org_id} was accepted by user in org {target_org_id}"
                ),
                evidence=result,
                recommendation="Validate that invitation acceptance happens within the same organization context.",
            )

        return result

    # ── API key scope ───────────────────────────────────────────────────

    async def test_api_key_cross_org(
        self,
        endpoints: List[str],
        source_session: AuthSession,
        target_org_sessions: List[AuthSession],
    ) -> List[Dict[str, Any]]:
        """
        Test if API keys/tokens are scoped to a single organization.

        Uses the same API key from org A to access org B endpoints.
        """
        results = []

        for target_session in target_org_sessions:
            if target_session.org.org_id == source_session.org.org_id:
                continue

            for endpoint in endpoints:
                async with AuthAwareClient(source_session) as client:
                    try:
                        resp = await client.get(endpoint)
                    except Exception:
                        continue

                    if resp is None:
                        continue

                    is_breach = resp.status_code in _SUCCESS_CODES
                    result = {
                        "endpoint": endpoint,
                        "source_org": source_session.org.org_id,
                        "target_org": target_session.org.org_id,
                        "status_code": resp.status_code,
                        "is_breach": is_breach,
                    }
                    results.append(result)

                    if is_breach:
                        self.inventory.record_finding(
                            finding_type="cross_org_api_key",
                            severity="critical",
                            object_type="api_endpoint",
                            object_id=endpoint,
                            endpoint=endpoint,
                            method="GET",
                            source_session_id=source_session.session_id,
                            target_session_id=target_session.session_id,
                            breach_description=(
                                f"Cross-tenant API key scope bypass: API key from org "
                                f"{source_session.org.org_id} can access endpoint "
                                f"{endpoint} meant for org {target_session.org.org_id}"
                            ),
                            evidence=result,
                            recommendation="Scope API keys to specific organizations. Validate org membership on every request.",
                        )

        return results

    # ── Full multi-org test ─────────────────────────────────────────────

    async def run_full_multi_org_test(
        self,
        endpoints: List[Dict[str, Any]],
        sessions_by_org: Dict[str, List[AuthSession]],
    ) -> Dict[str, Any]:
        """
        Run comprehensive cross-tenant testing.

        Args:
            endpoints: [{"url": "/api/orgs/{org_id}/data", "url_pattern": "..."}]
            sessions_by_org: {"org_a": [session1], "org_b": [session2]}
        """
        results = []

        # Cross-org access for each endpoint
        for spec in endpoints:
            url = spec.get("url", "")
            url_pattern = spec.get("url_pattern", "")

            for source_org, source_sessions in sessions_by_org.items():
                if not source_sessions:
                    continue
                source_session = source_sessions[0]

                target_sessions = []
                for target_org, org_sessions in sessions_by_org.items():
                    if target_org != source_org and org_sessions:
                        target_sessions.extend(org_sessions)

                if target_sessions:
                    result = await self.test_cross_org_access(
                        endpoint=url,
                        source_session=source_session,
                        target_org_sessions=target_sessions,
                        url_pattern=url_pattern,
                    )
                    results.append(result)

        return self.build_report()

    # ── Reporting ───────────────────────────────────────────────────────

    def build_report(self) -> Dict[str, Any]:
        """Build comprehensive multi-org test report."""
        findings = self.inventory.get_findings()
        unreported = self.inventory.get_unreported_findings()

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_tests": len(self._test_results),
                "total_breaches": sum(1 for r in self._test_results if r.get("any_breach")),
                "findings_count": len(findings),
                "unreported_count": len(unreported),
            },
            "test_results": self._test_results,
            "findings": findings,
            "unreported_findings": unreported,
        }

    def __repr__(self) -> str:
        breaches = sum(1 for r in self._test_results if r.get("any_breach"))
        return f"MultiOrgTester(tests={len(self._test_results)}, breaches={breaches})"
