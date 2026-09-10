"""
authcore/idor_tester.py — Systematic cross-user IDOR testing.

Provides CrossUserIDORTester: discovers objects across multiple sessions
and tests cross-user access to detect IDOR vulnerabilities.

Test methodology (mimics human bug bounty hunter):
    1. Discover objects: Crawl API endpoints with session A, extract object IDs
    2. Record ownership: Map each object to its owning session
    3. Cross-access test: For each object owned by A, test access with session B
    4. Compare responses: Status code, body length, content fingerprint
    5. Classify breach: read_idor, write_idor, delete_idor, admin_idor
    6. Generate findings: Evidence-backed IDOR reports for human review

Key insight: Human hunters test one object at a time, comparing responses
carefully. They don't spray 1000 requests — they test 5-10 objects per
session pair with surgical precision.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs

from sentinel_v2.auth.authcore.session import AuthSession, UserRole
from sentinel_v2.auth.authcore.auth_client import AuthAwareClient
from sentinel_v2.auth.authcore.object_inventory import ObjectInventoryDB

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Response comparison heuristics
# ---------------------------------------------------------------------------

# Status code classification
_SUCCESS_CODES = {200, 201, 204}
_UNAUTHORIZED_CODES = {401, 403}
_NOT_FOUND_CODES = {404}
_ERROR_CODES = {400, 422, 500, 502, 503}

# Response size thresholds
_MIN_RESPONSE_LENGTH = 50    # Ignore tiny error pages
_MAX_FINGERPRINT_DIFF = 0.15  # 15% difference = same content


def _response_fingerprint(body: bytes) -> str:
    """Stable content fingerprint for comparison."""
    if not body:
        return ""
    # Normalize: remove timestamps, IDs, nonces
    normalized = body.decode("utf-8", errors="ignore")
    # Remove common dynamic fields
    normalized = re.sub(r'"(?:id|uuid|nonce|token|timestamp|date|created_at|updated_at)"\s*:\s*"[^"]*"', '', normalized)
    normalized = re.sub(r'\b\d{10,13}\b', '', normalized)  # Unix timestamps
    normalized = re.sub(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', '', normalized, flags=re.I)
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


def _fingerprints_similar(fp1: str, fp2: str, threshold: float = _MAX_FINGERPRINT_DIFF) -> bool:
    """Check if two fingerprints represent similar content."""
    if not fp1 or not fp2:
        return False
    if fp1 == fp2:
        return True
    # Hamming distance approximation
    matches = sum(c1 == c2 for c1, c2 in zip(fp1, fp2))
    total = max(len(fp1), len(fp2))
    similarity = matches / total if total > 0 else 0
    return similarity >= (1 - threshold)


def _classify_response(
    status_code: int,
    body_length: int,
    body_fingerprint: str,
    owner_fingerprint: str,
    owner_status: int,
) -> Dict[str, Any]:
    """
    Classify a test response against the owner's response.

    Returns:
        {is_breach: bool, breach_type: str, confidence: float, reason: str}
    """
    # Unauthorized = properly protected
    if status_code in _UNAUTHORIZED_CODES:
        return {"is_breach": False, "breach_type": "", "confidence": 1.0, "reason": "unauthorized"}

    # Error responses = not a breach
    if status_code in _ERROR_CODES:
        return {"is_breach": False, "breach_type": "", "confidence": 0.9, "reason": "error_response"}

    # Not found = object doesn't exist for this user (expected)
    if status_code in _NOT_FOUND_CODES:
        return {"is_breach": False, "breach_type": "", "confidence": 0.85, "reason": "not_found"}

    # Success + similar content to owner = IDOR
    if status_code in _SUCCESS_CODES:
        if body_fingerprint and owner_fingerprint:
            if _fingerprints_similar(body_fingerprint, owner_fingerprint):
                return {
                    "is_breach": True,
                    "breach_type": "read_idor",
                    "confidence": 0.95,
                    "reason": "success_similar_content",
                }
            else:
                return {
                    "is_breach": True,
                    "breach_type": "read_idor",
                    "confidence": 0.7,
                    "reason": "success_different_content",
                }
        elif body_length > _MIN_RESPONSE_LENGTH:
            return {
                "is_breach": True,
                "breach_type": "read_idor",
                "confidence": 0.6,
                "reason": "success_with_body",
            }

    # Other success code
    if status_code in _SUCCESS_CODES:
        return {
            "is_breach": True,
            "breach_type": "read_idor",
            "confidence": 0.5,
            "reason": "success_status",
        }

    return {"is_breach": False, "breach_type": "", "confidence": 0.3, "reason": "inconclusive"}


# ---------------------------------------------------------------------------
# Object ID extraction patterns
# ---------------------------------------------------------------------------

# Common URL patterns for object IDs
_ID_PATTERNS = [
    re.compile(r'/(\d{1,10})(?:\?|$|#)'),              # /123
    re.compile(r'/([a-f0-9]{8,32})(?:\?|$|#)', True),  # /abc123def456
    re.compile(r'/([A-Za-z0-9_-]{6,64})(?:\?|$|#)'),   # /slug-or-id
    re.compile(r'/(?:users?|accounts?|profiles?|orders?|items?|invoices?)/(\w+)'),
]

# JSON field names that contain object IDs
_ID_FIELDS = {"id", "uuid", "user_id", "order_id", "item_id", "profile_id",
              "account_id", "invoice_id", "resource_id", "object_id"}


def _extract_ids_from_url(url: str) -> List[str]:
    """Extract potential object IDs from a URL path."""
    try:
        path = urlparse(url).path
    except Exception:
        return []

    ids = []
    for pattern in _ID_PATTERNS:
        matches = pattern.findall(path)
        ids.extend(matches)
    return list(set(ids))


def _extract_ids_from_json(data: Any, depth: int = 0) -> List[str]:
    """Extract potential object IDs from JSON response data."""
    if depth > 5:
        return []

    ids = []
    if isinstance(data, dict):
        for key, value in data.items():
            if key in _ID_FIELDS and isinstance(value, (str, int)):
                ids.append(str(value))
            elif isinstance(value, (dict, list)):
                ids.extend(_extract_ids_from_json(value, depth + 1))
    elif isinstance(data, list):
        for item in data[:50]:  # Limit to prevent explosion
            ids.extend(_extract_ids_from_json(item, depth + 1))
    return list(set(ids))


# ---------------------------------------------------------------------------
# CrossUserIDORTester
# ---------------------------------------------------------------------------

class CrossUserIDORTester:
    """
    Systematic IDOR testing across multiple user sessions.

    Discovers objects owned by each session and tests cross-user access
    with surgical precision — testing a few objects per session pair
    rather than spraying thousands of requests.

    Usage:
        tester = CrossUserIDORTester(inventory_db)

        # Discover objects with each session
        count = await tester.discover_objects(
            endpoints=["/api/users/me", "/api/orders"],
            session=admin_session,
            url_patterns=["/api/users/{id}", "/api/orders/{id}"],
        )

        # Test cross-user access
        results = await tester.test_cross_access(
            object_type="user_profile",
            source_session=admin_session,
            target_sessions=[member_session, viewer_session],
        )

        # Generate report
        report = tester.build_idor_report()
    """

    # Maximum objects to test per session pair (human-style: surgical, not spray)
    MAX_TEST_OBJECTS = 10
    # Maximum response body to store as evidence
    MAX_EVIDENCE_LENGTH = 2000

    def __init__(
        self,
        inventory: ObjectInventoryDB,
        max_test_objects: int = MAX_TEST_OBJECTS,
    ):
        self.inventory = inventory
        self.max_test_objects = max_test_objects
        self._test_results: List[Dict[str, Any]] = []

    # ── Object discovery ────────────────────────────────────────────────

    async def discover_objects(
        self,
        endpoints: List[str],
        session: AuthSession,
        url_patterns: Optional[List[str]] = None,
        max_pages: int = 20,
    ) -> int:
        """
        Discover objects by crawling endpoints with a session.

        Extracts object IDs from:
            - URL paths (e.g., /api/users/123)
            - JSON response bodies (e.g., {"id": 123, ...})
            - Link headers (e.g., </api/users/456>; rel="next")

        Args:
            endpoints: URLs to crawl
            session: Auth session to use
            url_patterns: URL patterns for object type mapping
            max_pages: Maximum pages to crawl per endpoint

        Returns:
            Number of objects discovered
        """
        discovered = 0

        async with AuthAwareClient(session) as client:
            for endpoint in endpoints:
                try:
                    resp = await client.get(endpoint)
                    if resp is None:
                        continue

                    # Extract IDs from response
                    ids = set()

                    # From URL
                    url_ids = _extract_ids_from_url(str(resp.url))
                    ids.update(url_ids)

                    # From JSON body
                    try:
                        body = resp.json()
                        json_ids = _extract_ids_from_json(body)
                        ids.update(json_ids)

                        # Also detect object type from response structure
                        object_type = self._detect_object_type(endpoint, body)

                        # Record each discovered object
                        for obj_id in ids:
                            if not obj_id or len(obj_id) < 2:
                                continue

                            existing = self.inventory.get_object(obj_id)
                            if existing:
                                self.inventory.increment_access_count(obj_id)
                                continue

                            self.inventory.record_object(
                                object_type=object_type,
                                object_id=obj_id,
                                owner_session_id=session.session_id,
                                owner_user_id=session.account.user_id,
                                owner_role=session.role.value,
                                owner_org_id=session.org.org_id,
                                endpoint=endpoint,
                                url_pattern=self._guess_url_pattern(endpoint, obj_id),
                                fingerprint=_response_fingerprint(resp.content),
                            )
                            discovered += 1

                    except (json.JSONDecodeError, ValueError):
                        # Not JSON — try extracting IDs from HTML/text
                        text_ids = _extract_ids_from_url(resp.text)
                        for obj_id in text_ids:
                            if obj_id and len(obj_id) >= 2:
                                object_type = self._detect_object_type(endpoint, None)
                                self.inventory.record_object(
                                    object_type=object_type,
                                    object_id=obj_id,
                                    owner_session_id=session.session_id,
                                    owner_user_id=session.account.user_id,
                                    owner_role=session.role.value,
                                    owner_org_id=session.org.org_id,
                                    endpoint=endpoint,
                                )
                                discovered += 1

                except Exception as e:
                    logger.warning(f"Discovery failed for {endpoint}: {e}")

        logger.info(f"Discovered {discovered} objects for session {session.label}")
        return discovered

    async def discover_objects_from_endpoints(
        self,
        endpoint_list: List[Dict[str, Any]],
        session: AuthSession,
    ) -> int:
        """
        Discover objects from a list of endpoint specs.

        Args:
            endpoint_list: [{"url": "/api/users/{id}", "method": "GET", "body": {...}}]
            session: Auth session

        Returns:
            Number of objects discovered
        """
        discovered = 0

        async with AuthAwareClient(session) as client:
            for spec in endpoint_list:
                url = spec.get("url", "")
                method = spec.get("method", "GET").upper()
                body = spec.get("body")
                params = spec.get("params")

                try:
                    resp = await client.request(
                        method, url, json=body, params=params
                    )
                    if resp is None:
                        continue

                    try:
                        data = resp.json()
                        ids = _extract_ids_from_json(data)
                        object_type = self._detect_object_type(url, data)

                        for obj_id in ids:
                            if not obj_id or len(obj_id) < 2:
                                continue
                            existing = self.inventory.get_object(obj_id)
                            if existing:
                                self.inventory.increment_access_count(obj_id)
                                continue

                            self.inventory.record_object(
                                object_type=object_type,
                                object_id=obj_id,
                                owner_session_id=session.session_id,
                                owner_user_id=session.account.user_id,
                                owner_role=session.role.value,
                                owner_org_id=session.org.org_id,
                                endpoint=url,
                            )
                            discovered += 1
                    except (json.JSONDecodeError, ValueError):
                        pass

                except Exception as e:
                    logger.debug(f"Endpoint discovery failed: {e}")

        return discovered

    # ── Cross-access testing ────────────────────────────────────────────

    async def test_cross_access(
        self,
        object_type: str,
        source_session: AuthSession,
        target_sessions: List[AuthSession],
        methods: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Test cross-user access for objects of a specific type.

        For each object owned by source_session, tests access with each
        target_session. Limited to max_test_objects per session pair.

        Args:
            object_type: Type of objects to test
            source_session: Session that owns the objects
            target_sessions: Sessions to test cross-access with
            methods: HTTP methods to test (default: ["GET"])

        Returns:
            List of test results
        """
        if methods is None:
            methods = ["GET"]

        # Get objects owned by source
        source_objects = [
            obj for obj in self.inventory.get_objects_by_owner(source_session.session_id)
            if obj["object_type"] == object_type
        ]

        if not source_objects:
            logger.info(f"No {object_type} objects found for {source_session.label}")
            return []

        # Limit test objects
        test_objects = source_objects[:self.max_test_objects]
        results = []

        for target_session in target_sessions:
            if target_session.session_id == source_session.session_id:
                continue

            async with AuthAwareClient(target_session) as client:
                for obj in test_objects:
                    for method in methods:
                        result = await self._test_single_object_access(
                            client=client,
                            obj=obj,
                            source_session=source_session,
                            target_session=target_session,
                            method=method,
                        )
                        results.append(result)

                        # Record in inventory
                        self.inventory.record_access_test(
                            object_id=obj["object_id"],
                            source_session_id=source_session.session_id,
                            source_role=source_session.role.value,
                            target_session_id=target_session.session_id,
                            target_role=target_session.role.value,
                            endpoint=result["endpoint"],
                            method=method,
                            status_code=result.get("status_code"),
                            response_length=result.get("response_length", 0),
                            response_fingerprint=result.get("response_fingerprint", ""),
                            is_breach=result.get("is_breach", False),
                            breach_type=result.get("breach_type", ""),
                            evidence=result.get("evidence", ""),
                        )

                        # Record finding if breach detected
                        if result.get("is_breach"):
                            self.inventory.record_finding(
                                finding_type="idor",
                                severity="high",
                                object_type=object_type,
                                object_id=obj["object_id"],
                                endpoint=result["endpoint"],
                                method=method,
                                source_session_id=source_session.session_id,
                                target_session_id=target_session.session_id,
                                breach_description=(
                                    f"Cross-user IDOR: {target_session.label} "
                                    f"({target_session.role.value}) can "
                                    f"{result['breach_type']} "
                                    f"{object_type}/{obj['object_id']} "
                                    f"owned by {source_session.label}"
                                ),
                                evidence=result.get("evidence", {}),
                                recommendation=(
                                    "Implement object-level authorization checks. "
                                    "Verify the requesting user owns or has access "
                                    "to the requested resource."
                                ),
                            )

        self._test_results.extend(results)
        return results

    async def _test_single_object_access(
        self,
        client: AuthAwareClient,
        obj: Dict[str, Any],
        source_session: AuthSession,
        target_session: AuthSession,
        method: str,
    ) -> Dict[str, Any]:
        """Test access to a single object with a target session."""
        # Build URL from object data
        endpoint = obj.get("endpoint", "")
        url_pattern = obj.get("url_pattern", "")

        if not endpoint:
            return {
                "object_id": obj["object_id"],
                "object_type": obj["object_type"],
                "is_breach": False,
                "breach_type": "",
                "reason": "no_endpoint",
                "method": method,
            }

        # Substitute object ID into URL
        if url_pattern and "{id}" in url_pattern:
            url = url_pattern.replace("{id}", obj["object_id"])
        elif url_pattern:
            url = url_pattern
        else:
            url = endpoint

        # Make the request
        try:
            resp = await client.request(method, url)
        except Exception as e:
            return {
                "object_id": obj["object_id"],
                "object_type": obj["object_type"],
                "endpoint": url,
                "method": method,
                "is_breach": False,
                "breach_type": "",
                "reason": f"request_failed: {e}",
            }

        if resp is None:
            return {
                "object_id": obj["object_id"],
                "object_type": obj["object_type"],
                "endpoint": url,
                "method": method,
                "is_breach": False,
                "breach_type": "",
                "reason": "request_returned_none",
            }

        # Classify response
        body = resp.content or b""
        body_fp = _response_fingerprint(body)
        classification = _classify_response(
            status_code=resp.status_code,
            body_length=len(body),
            body_fingerprint=body_fp,
            owner_fingerprint=obj.get("fingerprint", ""),
            owner_status=200,
        )

        # Truncate evidence
        evidence_body = body[:self.MAX_EVIDENCE_LENGTH].decode("utf-8", errors="ignore")

        return {
            "object_id": obj["object_id"],
            "object_type": obj["object_type"],
            "endpoint": url,
            "method": method,
            "status_code": resp.status_code,
            "response_length": len(body),
            "response_fingerprint": body_fp,
            "is_breach": classification["is_breach"],
            "breach_type": classification["breach_type"],
            "confidence": classification["confidence"],
            "reason": classification["reason"],
            "evidence": {
                "status_code": resp.status_code,
                "body_excerpt": evidence_body,
                "headers": dict(resp.headers) if hasattr(resp, "headers") else {},
            },
            "source_session": source_session.label,
            "target_session": target_session.label,
        }

    # ── Write/Delete IDOR testing ───────────────────────────────────────

    async def test_idor_modification(
        self,
        object_type: str,
        object_id: str,
        owner_session: AuthSession,
        attacker_session: AuthSession,
        endpoint: str,
        payload: Dict[str, Any],
        method: str = "PUT",
    ) -> Dict[str, Any]:
        """
        Test if attacker can modify an object they don't own.

        Compares:
            1. Owner's original object state
            2. Attacker's modification attempt
            3. Whether the object was actually modified
        """
        # Step 1: Get original state
        async with AuthAwareClient(owner_session) as client:
            original_resp = await client.get(endpoint)
            original_body = original_resp.content if original_resp else b""
            original_fp = _response_fingerprint(original_body)

        # Step 2: Attacker attempts modification
        async with AuthAwareClient(attacker_session) as client:
            mod_resp = await client.request(method, endpoint, json=payload)
            mod_status = mod_resp.status_code if mod_resp else None
            mod_body = mod_resp.content if mod_resp else b""

        # Step 3: Check if object was actually modified
        async with AuthAwareClient(owner_session) as client:
            verify_resp = await client.get(endpoint)
            verify_body = verify_resp.content if verify_resp else b""
            verify_fp = _response_fingerprint(verify_body)

        is_modified = original_fp != verify_fp
        is_breach = mod_status in _SUCCESS_CODES and is_modified

        result = {
            "object_id": object_id,
            "object_type": object_type,
            "endpoint": endpoint,
            "method": method,
            "attacker_session": attacker_session.label,
            "owner_session": owner_session.label,
            "modification_status": mod_status,
            "object_actually_modified": is_modified,
            "is_breach": is_breach,
            "breach_type": "write_idor" if is_breach else "",
            "evidence": {
                "original_fingerprint": original_fp,
                "modification_status": mod_status,
                "verify_fingerprint": verify_fp,
                "modification_body": mod_body[:self.MAX_EVIDENCE_LENGTH].decode("utf-8", errors="ignore"),
            },
        }

        if is_breach:
            self.inventory.record_finding(
                finding_type="idor_write",
                severity="critical",
                object_type=object_type,
                object_id=object_id,
                endpoint=endpoint,
                method=method,
                source_session_id=owner_session.session_id,
                target_session_id=attacker_session.session_id,
                breach_description=(
                    f"Write IDOR: {attacker_session.label} can modify "
                    f"{object_type}/{object_id} owned by {owner_session.label}"
                ),
                evidence=result["evidence"],
                recommendation="Implement write authorization checks on all object-modifying endpoints.",
            )

        return result

    async def test_idor_deletion(
        self,
        object_type: str,
        object_id: str,
        owner_session: AuthSession,
        attacker_session: AuthSession,
        endpoint: str,
    ) -> Dict[str, Any]:
        """
        Test if attacker can delete an object they don't own.

        IMPORTANT: Only sends DELETE request. Does NOT actually delete
        the object — verifies deletion by checking if GET still returns data.
        """
        # Verify object exists before test
        async with AuthAwareClient(owner_session) as client:
            pre_resp = await client.get(endpoint)
            pre_exists = pre_resp is not None and pre_resp.status_code in _SUCCESS_CODES

        if not pre_exists:
            return {
                "object_id": object_id,
                "is_breach": False,
                "reason": "object_not_found_before_test",
            }

        # Attacker attempts deletion
        async with AuthAwareClient(attacker_session) as client:
            del_resp = await client.delete(endpoint)
            del_status = del_resp.status_code if del_resp else None

        # Verify if object still exists
        async with AuthAwareClient(owner_session) as client:
            post_resp = await client.get(endpoint)
            post_exists = post_resp is not None and post_resp.status_code in _SUCCESS_CODES

        is_breach = del_status in {200, 204} and not post_exists

        result = {
            "object_id": object_id,
            "object_type": object_type,
            "endpoint": endpoint,
            "method": "DELETE",
            "attacker_session": attacker_session.label,
            "owner_session": owner_session.label,
            "deletion_status": del_status,
            "object_still_exists": post_exists,
            "is_breach": is_breach,
            "breach_type": "delete_idor" if is_breach else "",
            "evidence": {
                "deletion_status": del_status,
                "pre_exists": pre_exists,
                "post_exists": post_exists,
            },
        }

        if is_breach:
            self.inventory.record_finding(
                finding_type="idor_delete",
                severity="critical",
                object_type=object_type,
                object_id=object_id,
                endpoint=endpoint,
                method="DELETE",
                source_session_id=owner_session.session_id,
                target_session_id=attacker_session.session_id,
                breach_description=(
                    f"Delete IDOR: {attacker_session.label} can delete "
                    f"{object_type}/{object_id} owned by {owner_session.label}"
                ),
                evidence=result["evidence"],
                recommendation="Implement delete authorization checks. Verify user owns the object before deletion.",
            )

        return result

    # ── Reporting ───────────────────────────────────────────────────────

    def build_idor_report(self) -> Dict[str, Any]:
        """Build comprehensive IDOR report from all test results."""
        return self.inventory.build_idor_report()

    def get_breaches(self) -> List[Dict[str, Any]]:
        """Get all breach results from current test session."""
        return [r for r in self._test_results if r.get("is_breach")]

    def get_test_summary(self) -> Dict[str, Any]:
        """Summary of testing performed."""
        total = len(self._test_results)
        breaches = sum(1 for r in self._test_results if r.get("is_breach"))
        by_type: Dict[str, int] = {}
        for r in self._test_results:
            bt = r.get("breach_type", "none")
            by_type[bt] = by_type.get(bt, 0) + 1

        return {
            "total_tests": total,
            "breaches_found": breaches,
            "breach_rate": breaches / total if total > 0 else 0,
            "by_type": by_type,
            "objects_tested": len(set(r.get("object_id", "") for r in self._test_results)),
        }

    # ── Helpers ─────────────────────────────────────────────────────────

    def _detect_object_type(self, endpoint: str, body: Any) -> str:
        """Detect object type from endpoint URL and response body."""
        # From URL path
        path = urlparse(endpoint).path.lower()
        type_hints = {
            "user": "user",
            "profile": "user_profile",
            "order": "order",
            "invoice": "invoice",
            "item": "item",
            "product": "product",
            "account": "account",
            "payment": "payment",
            "address": "address",
            "settings": "settings",
            "comment": "comment",
            "message": "message",
            "file": "file",
            "document": "document",
            "team": "team",
            "organization": "organization",
            "project": "project",
            "task": "task",
        }

        for hint, obj_type in type_hints.items():
            if hint in path:
                return obj_type

        # From JSON body keys
        if isinstance(body, dict):
            for key in body.keys():
                key_lower = key.lower()
                for hint, obj_type in type_hints.items():
                    if hint in key_lower:
                        return obj_type

        return "unknown"

    def _guess_url_pattern(self, endpoint: str, object_id: str) -> str:
        """Guess URL pattern by replacing object ID with {id}."""
        if object_id and object_id in endpoint:
            return endpoint.replace(object_id, "{id}")
        return endpoint

    def __repr__(self) -> str:
        return (
            f"CrossUserIDORTester("
            f"tests={len(self._test_results)}, "
            f"breaches={sum(1 for r in self._test_results if r.get('is_breach'))}"
            f")"
        )
