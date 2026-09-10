"""
authcore/object_inventory.py — Object inventory for IDOR intelligence.

Provides ObjectInventoryDB: SQLite-backed tracking of discovered objects,
ownership, and access control tests. Core dependency for:
    - CrossUserIDORTester: cross-user access testing
    - AccountBoundaryTester: horizontal/vertical boundary testing
    - RoleTester: RBAC testing
    - GraphQL Auth Tester: GraphQL object discovery

Design:
    Objects are discovered during authenticated testing (crawling, API calls,
    GraphQL queries). Each object is recorded with its type, ID, owning session,
    and the endpoint that discovered it. The inventory then identifies IDOR
    candidates: objects of the same type owned by different sessions.

    SQLite provides persistence across pipeline runs. WAL mode for concurrent
    reads during testing.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from sentinel_v2.auth.authcore.session import AuthSession, UserRole

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS objects (
    object_id TEXT PRIMARY KEY,
    object_type TEXT NOT NULL,
    owner_session_id TEXT NOT NULL,
    owner_user_id TEXT DEFAULT '',
    owner_role TEXT DEFAULT 'member',
    owner_org_id TEXT DEFAULT '',
    endpoint TEXT DEFAULT '',
    url_pattern TEXT DEFAULT '',
    data TEXT DEFAULT '{}',
    fingerprint TEXT DEFAULT '',
    discovered_at TEXT NOT NULL,
    last_seen TEXT,
    access_count INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_objects_type
    ON objects(object_type);
CREATE INDEX IF NOT EXISTS idx_objects_owner
    ON objects(owner_session_id);
CREATE INDEX IF NOT EXISTS idx_objects_user
    ON objects(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_objects_org
    ON objects(owner_org_id);
CREATE INDEX IF NOT EXISTS idx_objects_fingerprint
    ON objects(fingerprint);

CREATE TABLE IF NOT EXISTS access_tests (
    test_id TEXT PRIMARY KEY,
    object_id TEXT NOT NULL,
    object_type TEXT NOT NULL,
    source_session_id TEXT NOT NULL,
    source_role TEXT NOT NULL,
    target_session_id TEXT NOT NULL,
    target_role TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    method TEXT NOT NULL,
    status_code INTEGER,
    response_length INTEGER DEFAULT 0,
    response_fingerprint TEXT DEFAULT '',
    is_breach INTEGER DEFAULT 0,
    breach_type TEXT DEFAULT '',
    evidence TEXT DEFAULT '',
    tested_at TEXT NOT NULL,
    FOREIGN KEY (object_id) REFERENCES objects(object_id)
);

CREATE INDEX IF NOT EXISTS idx_access_tests_object
    ON access_tests(object_id);
CREATE INDEX IF NOT EXISTS idx_access_tests_source
    ON access_tests(source_session_id);
CREATE INDEX IF NOT EXISTS idx_access_tests_target
    ON access_tests(target_session_id);
CREATE INDEX IF NOT EXISTS idx_access_tests_breach
    ON access_tests(is_breach);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    finding_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    object_type TEXT NOT NULL,
    object_id TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    method TEXT NOT NULL,
    source_session_id TEXT NOT NULL,
    target_session_id TEXT NOT NULL,
    breach_description TEXT NOT NULL,
    evidence TEXT DEFAULT '{}',
    recommendation TEXT DEFAULT '',
    reported INTEGER DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_type
    ON findings(finding_type);
CREATE INDEX IF NOT EXISTS idx_findings_severity
    ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_reported
    ON findings(reported);
"""


# ---------------------------------------------------------------------------
# ObjectInventoryDB
# ---------------------------------------------------------------------------

class ObjectInventoryDB:
    """
    SQLite-backed object inventory for IDOR intelligence.

    Tracks discovered objects, their owners, and access control test results.
    Identifies IDOR candidates and generates findings.

    Usage:
        db = ObjectInventoryDB("object_inventory.db")

        # Record objects discovered during testing
        db.record_object(
            object_type="user_profile",
            object_id="usr_123",
            owner_session_id="session_abc",
            owner_user_id="user_a",
            endpoint="/api/users/usr_123",
        )

        # Find IDOR candidates (same type, different owners)
        candidates = db.get_idor_candidates("user_profile")

        # Record an access test
        db.record_access_test(
            object_id="usr_123",
            source_session_id="session_abc",
            target_session_id="session_xyz",
            endpoint="/api/users/usr_123",
            method="GET",
            status_code=200,
        )

        # Generate report
        report = db.build_idor_report()
    """

    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize inventory database.

        Args:
            db_path: SQLite path. None = memory-only mode.
        """
        self._db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._lock = threading.Lock()

        # In-memory cache for fast lookups
        self._objects: Dict[str, Dict[str, Any]] = {}
        self._access_tests: List[Dict[str, Any]] = []
        self._findings: List[Dict[str, Any]] = []

        if db_path:
            self._init_sqlite()

    # ── SQLite lifecycle ────────────────────────────────────────────────

    def _init_sqlite(self) -> None:
        """Initialize SQLite connection and schema."""
        try:
            self._conn = sqlite3.connect(
                self._db_path,
                check_same_thread=False,
                timeout=5.0,
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.executescript(_SCHEMA_SQL)
            self._conn.commit()
            self._load_from_sqlite()
            logger.info(f"ObjectInventoryDB initialized at {self._db_path}")
        except Exception as e:
            logger.error(f"SQLite init failed: {e}")
            self._conn = None

    def _load_from_sqlite(self) -> None:
        """Load cached data from SQLite."""
        if not self._conn:
            return
        try:
            cursor = self._conn.execute("SELECT * FROM objects")
            for row in cursor.fetchall():
                self._objects[row["object_id"]] = dict(row)

            cursor = self._conn.execute(
                "SELECT * FROM access_tests ORDER BY tested_at DESC LIMIT 1000"
            )
            self._access_tests = [dict(row) for row in cursor.fetchall()]

            cursor = self._conn.execute("SELECT * FROM findings")
            self._findings = [dict(row) for row in cursor.fetchall()]

            logger.info(
                f"Loaded {len(self._objects)} objects, "
                f"{len(self._access_tests)} tests, "
                f"{len(self._findings)} findings from SQLite"
            )
        except Exception as e:
            logger.error(f"Failed to load from SQLite: {e}")

    def _persist_object(self, obj: Dict[str, Any]) -> None:
        """Write object to SQLite."""
        if not self._conn:
            return
        try:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO objects
                (object_id, object_type, owner_session_id, owner_user_id,
                 owner_role, owner_org_id, endpoint, url_pattern, data,
                 fingerprint, discovered_at, last_seen, access_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    obj["object_id"],
                    obj["object_type"],
                    obj["owner_session_id"],
                    obj.get("owner_user_id", ""),
                    obj.get("owner_role", "member"),
                    obj.get("owner_org_id", ""),
                    obj.get("endpoint", ""),
                    obj.get("url_pattern", ""),
                    json.dumps(obj.get("data", {})),
                    obj.get("fingerprint", ""),
                    obj["discovered_at"],
                    obj.get("last_seen"),
                    obj.get("access_count", 0),
                ),
            )
            self._conn.commit()
        except Exception as e:
            logger.error(f"SQLite persist object failed: {e}")

    def _persist_access_test(self, test: Dict[str, Any]) -> None:
        """Write access test to SQLite."""
        if not self._conn:
            return
        try:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO access_tests
                (test_id, object_id, object_type, source_session_id, source_role,
                 target_session_id, target_role, endpoint, method, status_code,
                 response_length, response_fingerprint, is_breach, breach_type,
                 evidence, tested_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    test["test_id"],
                    test["object_id"],
                    test["object_type"],
                    test["source_session_id"],
                    test["source_role"],
                    test["target_session_id"],
                    test["target_role"],
                    test["endpoint"],
                    test["method"],
                    test.get("status_code"),
                    test.get("response_length", 0),
                    test.get("response_fingerprint", ""),
                    1 if test.get("is_breach") else 0,
                    test.get("breach_type", ""),
                    test.get("evidence", ""),
                    test["tested_at"],
                ),
            )
            self._conn.commit()
        except Exception as e:
            logger.error(f"SQLite persist access test failed: {e}")

    def _persist_finding(self, finding: Dict[str, Any]) -> None:
        """Write finding to SQLite."""
        if not self._conn:
            return
        try:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO findings
                (finding_id, finding_type, severity, object_type, object_id,
                 endpoint, method, source_session_id, target_session_id,
                 breach_description, evidence, recommendation, reported, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding["finding_id"],
                    finding["finding_type"],
                    finding["severity"],
                    finding["object_type"],
                    finding["object_id"],
                    finding["endpoint"],
                    finding["method"],
                    finding["source_session_id"],
                    finding["target_session_id"],
                    finding["breach_description"],
                    json.dumps(finding.get("evidence", {})),
                    finding.get("recommendation", ""),
                    1 if finding.get("reported") else 0,
                    finding["created_at"],
                ),
            )
            self._conn.commit()
        except Exception as e:
            logger.error(f"SQLite persist finding failed: {e}")

    # ── Public API: Record objects ──────────────────────────────────────

    def record_object(
        self,
        object_type: str,
        object_id: str,
        owner_session_id: str,
        owner_user_id: str = "",
        owner_role: str = "member",
        owner_org_id: str = "",
        endpoint: str = "",
        url_pattern: str = "",
        data: Optional[Dict[str, Any]] = None,
        fingerprint: str = "",
    ) -> str:
        """
        Record a discovered object in the inventory.

        Args:
            object_type: Category (e.g., "user_profile", "order", "invoice")
            object_id: Unique identifier within the type
            owner_session_id: Session that owns this object
            owner_user_id: User ID of the owner
            owner_role: Role of the owner
            owner_org_id: Organization of the owner
            endpoint: URL that discovered this object
            url_pattern: URL pattern (e.g., "/api/users/{id}")
            data: Additional object data (serialized as JSON)
            fingerprint: Content fingerprint for deduplication

        Returns:
            object_id
        """
        now = datetime.now(timezone.utc).isoformat()
        obj = {
            "object_id": object_id,
            "object_type": object_type,
            "owner_session_id": owner_session_id,
            "owner_user_id": owner_user_id,
            "owner_role": owner_role,
            "owner_org_id": owner_org_id,
            "endpoint": endpoint,
            "url_pattern": url_pattern,
            "data": data or {},
            "fingerprint": fingerprint or self._compute_fingerprint(object_type, object_id),
            "discovered_at": now,
            "last_seen": now,
            "access_count": 0,
        }

        with self._lock:
            self._objects[object_id] = obj
            self._persist_object(obj)

        return object_id

    def update_object(
        self,
        object_id: str,
        **kwargs,
    ) -> bool:
        """Update fields on an existing object. Returns True if found."""
        with self._lock:
            obj = self._objects.get(object_id)
            if not obj:
                return False
            for key, value in kwargs.items():
                if key in obj:
                    obj[key] = value
            obj["last_seen"] = datetime.now(timezone.utc).isoformat()
            self._persist_object(obj)
            return True

    def increment_access_count(self, object_id: str) -> int:
        """Increment access count. Returns new count."""
        with self._lock:
            obj = self._objects.get(object_id)
            if not obj:
                return 0
            obj["access_count"] = obj.get("access_count", 0) + 1
            obj["last_seen"] = datetime.now(timezone.utc).isoformat()
            self._persist_object(obj)
            return obj["access_count"]

    def remove_object(self, object_id: str) -> bool:
        """Remove an object. Returns True if found."""
        with self._lock:
            obj = self._objects.pop(object_id, None)
            if not obj:
                return False
            if self._conn:
                try:
                    self._conn.execute(
                        "DELETE FROM objects WHERE object_id = ?",
                        (object_id,),
                    )
                    self._conn.commit()
                except Exception as e:
                    logger.error(f"SQLite delete object failed: {e}")
            return True

    # ── Public API: Query objects ───────────────────────────────────────

    def get_object(self, object_id: str) -> Optional[Dict[str, Any]]:
        """Get object by ID."""
        return self._objects.get(object_id)

    def get_objects_by_owner(self, session_id: str) -> List[Dict[str, Any]]:
        """Get all objects owned by a session."""
        return [
            obj for obj in self._objects.values()
            if obj["owner_session_id"] == session_id
        ]

    def get_objects_by_type(self, object_type: str) -> List[Dict[str, Any]]:
        """Get all objects of a specific type."""
        return [
            obj for obj in self._objects.values()
            if obj["object_type"] == object_type
        ]

    def get_objects_by_user(self, user_id: str) -> List[Dict[str, Any]]:
        """Get all objects owned by a user ID."""
        return [
            obj for obj in self._objects.values()
            if obj.get("owner_user_id") == user_id
        ]

    def get_objects_by_org(self, org_id: str) -> List[Dict[str, Any]]:
        """Get all objects belonging to an organization."""
        return [
            obj for obj in self._objects.values()
            if obj.get("owner_org_id") == org_id
        ]

    def get_objects_by_endpoint(self, endpoint: str) -> List[Dict[str, Any]]:
        """Get all objects discovered from a specific endpoint."""
        return [
            obj for obj in self._objects.values()
            if obj.get("endpoint") == endpoint
        ]

    def get_all_object_types(self) -> List[str]:
        """Get list of all object types."""
        types = set()
        for obj in self._objects.values():
            types.add(obj["object_type"])
        return sorted(types)

    def get_object_count(self) -> int:
        """Total number of objects."""
        return len(self._objects)

    def get_object_count_by_type(self) -> Dict[str, int]:
        """Object counts grouped by type."""
        counts: Dict[str, int] = {}
        for obj in self._objects.values():
            counts[obj["object_type"]] = counts.get(obj["object_type"], 0) + 1
        return counts

    # ── Public API: IDOR detection ──────────────────────────────────────

    def get_idor_candidates(
        self,
        object_type: Optional[str] = None,
        min_owners: int = 2,
    ) -> List[Dict[str, Any]]:
        """
        Find objects with multiple owners — IDOR candidates.

        An IDOR candidate is an object type where at least min_owners
        different sessions own objects of that type.

        Returns:
            List of {object_type, owner_count, owners: [{session_id, user_id, role, object_count}]}
        """
        # Group by type → owner
        type_owners: Dict[str, Dict[str, List[str]]] = {}
        for obj in self._objects.values():
            otype = obj["object_type"]
            owner = obj["owner_session_id"]
            if otype not in type_owners:
                type_owners[otype] = {}
            if owner not in type_owners[otype]:
                type_owners[otype][owner] = []
            type_owners[otype][owner].append(obj["object_id"])

        candidates = []
        for otype, owners in type_owners.items():
            if object_type and otype != object_type:
                continue
            if len(owners) < min_owners:
                continue

            owner_info = []
            for session_id, object_ids in owners.items():
                obj_sample = self._objects.get(object_ids[0], {})
                owner_info.append({
                    "session_id": session_id,
                    "user_id": obj_sample.get("owner_user_id", ""),
                    "role": obj_sample.get("owner_role", "member"),
                    "org_id": obj_sample.get("owner_org_id", ""),
                    "object_count": len(object_ids),
                    "object_ids": object_ids[:10],  # Limit for readability
                })

            candidates.append({
                "object_type": otype,
                "owner_count": len(owners),
                "total_objects": sum(len(ids) for ids in owners.values()),
                "owners": owner_info,
            })

        # Sort by owner count (most owners = highest IDOR potential)
        candidates.sort(key=lambda c: c["owner_count"], reverse=True)
        return candidates

    def get_cross_role_objects(
        self,
        object_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Find object types where owners have different roles.

        Critical for detecting privilege escalation: if a MEMBER and an ADMIN
        both own objects of the same type, test whether MEMBER can access
        ADMIN objects.
        """
        type_roles: Dict[str, Set[str]] = {}
        type_owners: Dict[str, Dict[str, str]] = {}  # type → {session_id: role}
        for obj in self._objects.values():
            otype = obj["object_type"]
            if object_type and otype != object_type:
                continue
            role = obj.get("owner_role", "member")
            type_roles.setdefault(otype, set()).add(role)
            type_owners.setdefault(otype, {})[obj["owner_session_id"]] = role

        results = []
        for otype, roles in type_roles.items():
            if len(roles) < 2:
                continue
            results.append({
                "object_type": otype,
                "roles": sorted(roles),
                "owners": type_owners[otype],
            })

        return results

    def build_access_matrix(self) -> Dict[str, Dict[str, Dict[str, Any]]]:
        """
        Build complete access control matrix.

        Returns:
            {object_type: {owner_session_id: {target_session_id: test_result}}}
        """
        matrix: Dict[str, Dict[str, Dict[str, Any]]] = {}

        for test in self._access_tests:
            otype = test["object_type"]
            source = test["source_session_id"]
            target = test["target_session_id"]

            matrix.setdefault(otype, {}).setdefault(source, {})[target] = {
                "method": test["method"],
                "status_code": test.get("status_code"),
                "is_breach": bool(test.get("is_breach")),
                "breach_type": test.get("breach_type", ""),
                "tested_at": test["tested_at"],
            }

        return matrix

    def detect_ownership_bypass(
        self,
        object_type: str,
        test_session_id: str,
        object_id: str,
    ) -> Dict[str, Any]:
        """
        Check if a session accessed an object it doesn't own.

        Returns:
            {is_bypass: bool, object_owner: str, test_session: str, evidence: dict}
        """
        obj = self._objects.get(object_id)
        if not obj:
            return {
                "is_bypass": False,
                "reason": "object_not_found",
                "object_id": object_id,
            }

        if obj["owner_session_id"] == test_session_id:
            return {
                "is_bypass": False,
                "reason": "same_owner",
                "object_id": object_id,
            }

        # Check if there was a successful access test
        for test in self._access_tests:
            if (
                test["object_id"] == object_id
                and test["target_session_id"] == test_session_id
                and test.get("is_breach")
            ):
                return {
                    "is_bypass": True,
                    "object_owner": obj["owner_session_id"],
                    "test_session": test_session_id,
                    "test_id": test["test_id"],
                    "endpoint": test["endpoint"],
                    "method": test["method"],
                    "status_code": test.get("status_code"),
                    "breach_type": test.get("breach_type", ""),
                    "evidence": test.get("evidence", ""),
                }

        return {
            "is_bypass": False,
            "reason": "no_successful_access",
            "object_id": object_id,
            "object_owner": obj["owner_session_id"],
            "test_session": test_session_id,
        }

    # ── Public API: Record access tests ─────────────────────────────────

    def record_access_test(
        self,
        object_id: str,
        source_session_id: str,
        source_role: str,
        target_session_id: str,
        target_role: str,
        endpoint: str,
        method: str,
        status_code: Optional[int] = None,
        response_length: int = 0,
        response_fingerprint: str = "",
        is_breach: bool = False,
        breach_type: str = "",
        evidence: str = "",
    ) -> str:
        """
        Record an access control test result.

        Args:
            object_id: Object that was tested
            source_session_id: Session that owns the object
            source_role: Role of the source session
            target_session_id: Session that attempted access
            target_role: Role of the target session
            endpoint: URL tested
            method: HTTP method
            status_code: Response status code
            response_length: Response body length
            response_fingerprint: Content hash for comparison
            is_breach: Whether access was unauthorized
            breach_type: "read", "write", "delete", "admin"
            evidence: Evidence string (headers, body excerpt)

        Returns:
            test_id
        """
        test_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        obj = self._objects.get(object_id, {})
        otype = obj.get("object_type", "unknown")

        test = {
            "test_id": test_id,
            "object_id": object_id,
            "object_type": otype,
            "source_session_id": source_session_id,
            "source_role": source_role,
            "target_session_id": target_session_id,
            "target_role": target_role,
            "endpoint": endpoint,
            "method": method,
            "status_code": status_code,
            "response_length": response_length,
            "response_fingerprint": response_fingerprint,
            "is_breach": is_breach,
            "breach_type": breach_type,
            "evidence": evidence,
            "tested_at": now,
        }

        with self._lock:
            self._access_tests.insert(0, test)
            if len(self._access_tests) > 10000:
                self._access_tests = self._access_tests[:10000]
            self._persist_access_test(test)

        return test_id

    # ── Public API: Findings ────────────────────────────────────────────

    def record_finding(
        self,
        finding_type: str,
        severity: str,
        object_type: str,
        object_id: str,
        endpoint: str,
        method: str,
        source_session_id: str,
        target_session_id: str,
        breach_description: str,
        evidence: Optional[Dict[str, Any]] = None,
        recommendation: str = "",
    ) -> str:
        """
        Record a security finding (IDOR, privesc, etc.).

        Returns:
            finding_id
        """
        finding_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        finding = {
            "finding_id": finding_id,
            "finding_type": finding_type,
            "severity": severity,
            "object_type": object_type,
            "object_id": object_id,
            "endpoint": endpoint,
            "method": method,
            "source_session_id": source_session_id,
            "target_session_id": target_session_id,
            "breach_description": breach_description,
            "evidence": evidence or {},
            "recommendation": recommendation,
            "reported": False,
            "created_at": now,
        }

        with self._lock:
            self._findings.append(finding)
            self._persist_finding(finding)

        return finding_id

    def get_findings(
        self,
        finding_type: Optional[str] = None,
        severity: Optional[str] = None,
        reported: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """Query findings with optional filters."""
        results = list(self._findings)

        if finding_type:
            results = [f for f in results if f["finding_type"] == finding_type]
        if severity:
            results = [f for f in results if f["severity"] == severity]
        if reported is not None:
            results = [f for f in results if bool(f.get("reported")) == reported]

        return results

    def mark_finding_reported(self, finding_id: str) -> bool:
        """Mark a finding as reported."""
        with self._lock:
            for f in self._findings:
                if f["finding_id"] == finding_id:
                    f["reported"] = True
                    if self._conn:
                        try:
                            self._conn.execute(
                                "UPDATE findings SET reported = 1 WHERE finding_id = ?",
                                (finding_id,),
                            )
                            self._conn.commit()
                        except Exception:
                            pass
                    return True
        return False

    def get_unreported_findings(self) -> List[Dict[str, Any]]:
        """Get all findings not yet reported."""
        return self.get_findings(reported=False)

    # ── Public API: Reporting ───────────────────────────────────────────

    def build_idor_report(self) -> Dict[str, Any]:
        """
        Build comprehensive IDOR report from inventory data.

        Returns:
            Summary of all IDOR testing with findings, candidates, and matrix.
        """
        candidates = self.get_idor_candidates()
        cross_role = self.get_cross_role_objects()
        matrix = self.build_access_matrix()
        findings = self.get_findings()
        unreported = self.get_unreported_findings()

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_objects": len(self._objects),
                "object_types": len(set(
                    o["object_type"] for o in self._objects.values()
                )),
                "total_sessions": len(set(
                    o["owner_session_id"] for o in self._objects.values()
                )),
                "total_access_tests": len(self._access_tests),
                "total_findings": len(findings),
                "unreported_findings": len(unreported),
                "breach_count": sum(1 for t in self._access_tests if t.get("is_breach")),
            },
            "idor_candidates": candidates,
            "cross_role_objects": cross_role,
            "access_matrix": matrix,
            "findings": findings,
            "unreported_findings": unreported,
        }

    def to_summary(self) -> Dict[str, Any]:
        """Quick summary for LLM context."""
        return {
            "total_objects": len(self._objects),
            "object_types": self.get_object_count_by_type(),
            "total_sessions": len(set(
                o["owner_session_id"] for o in self._objects.values()
            )),
            "idor_candidate_types": len(self.get_idor_candidates()),
            "cross_role_types": len(self.get_cross_role_objects()),
            "total_access_tests": len(self._access_tests),
            "breach_count": sum(1 for t in self._access_tests if t.get("is_breach")),
            "total_findings": len(self._findings),
            "unreported_findings": len(self.get_unreported_findings()),
        }

    # ── Helpers ─────────────────────────────────────────────────────────

    def _compute_fingerprint(self, object_type: str, object_id: str) -> str:
        """Compute a simple fingerprint for deduplication."""
        import hashlib
        raw = f"{object_type}:{object_id}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def clear(self) -> int:
        """Remove all data. Returns count of objects removed."""
        with self._lock:
            count = len(self._objects)
            self._objects.clear()
            self._access_tests.clear()
            self._findings.clear()
            if self._conn:
                try:
                    self._conn.execute("DELETE FROM objects")
                    self._conn.execute("DELETE FROM access_tests")
                    self._conn.execute("DELETE FROM findings")
                    self._conn.commit()
                except Exception:
                    pass
            return count

    def close(self) -> None:
        """Close SQLite connection."""
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __repr__(self) -> str:
        return (
            f"ObjectInventoryDB("
            f"objects={len(self._objects)}, "
            f"tests={len(self._access_tests)}, "
            f"findings={len(self._findings)}"
            f")"
        )
