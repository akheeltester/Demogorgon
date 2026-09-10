"""
Tests for authcore M5-M10: ObjectInventoryDB, CrossUserIDORTester,
AccountBoundaryTester, RoleTester, GraphQLAuthTester, MultiOrgTester.
"""

import os
import sys
import tempfile
import json
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel_v2.auth.authcore.session import AuthSession, UserRole, AuthType, OrgMeta, AccountMeta
from sentinel_v2.auth.authcore.store import AuthSessionStore
from sentinel_v2.auth.authcore.object_inventory import ObjectInventoryDB


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_session(
    label: str = "test_user",
    role: UserRole = UserRole.MEMBER,
    domain: str = "target.com",
    user_id: str = "",
    org_id: str = "",
    cookies: dict = None,
) -> AuthSession:
    """Create a test AuthSession."""
    session = AuthSession(
        label=label,
        role=role,
        auth_type=AuthType.COOKIE,
        target_domain=domain,
    )
    if cookies:
        for k, v in cookies.items():
            session.cookies.set(k, v)
    if user_id:
        session.account.user_id = user_id
    if org_id:
        session.org.org_id = org_id
    return session


# ---------------------------------------------------------------------------
# M5: ObjectInventoryDB Tests
# ---------------------------------------------------------------------------

class TestObjectInventoryDB:
    """Tests for ObjectInventoryDB (M5)."""

    def test_init_memory_only(self):
        db = ObjectInventoryDB()
        assert db.get_object_count() == 0

    def test_init_sqlite(self, tmp_path):
        db_path = str(tmp_path / "test_inventory.db")
        db = ObjectInventoryDB(db_path)
        assert db.get_object_count() == 0
        db.close()

    def test_record_object(self):
        db = ObjectInventoryDB()
        obj_id = db.record_object(
            object_type="user_profile",
            object_id="usr_123",
            owner_session_id="sess_a",
            owner_user_id="user_a",
            owner_role="member",
        )
        assert obj_id == "usr_123"
        assert db.get_object_count() == 1

    def test_record_object_with_data(self):
        db = ObjectInventoryDB()
        db.record_object(
            object_type="order",
            object_id="ord_456",
            owner_session_id="sess_a",
            data={"total": 99.99, "currency": "USD"},
        )
        obj = db.get_object("ord_456")
        assert obj is not None
        assert obj["data"]["total"] == 99.99

    def test_get_objects_by_owner(self):
        db = ObjectInventoryDB()
        db.record_object("profile", "p1", "sess_a")
        db.record_object("profile", "p2", "sess_a")
        db.record_object("profile", "p3", "sess_b")

        a_objects = db.get_objects_by_owner("sess_a")
        assert len(a_objects) == 2

        b_objects = db.get_objects_by_owner("sess_b")
        assert len(b_objects) == 1

    def test_get_objects_by_type(self):
        db = ObjectInventoryDB()
        db.record_object("user", "u1", "sess_a")
        db.record_object("user", "u2", "sess_b")
        db.record_object("order", "o1", "sess_a")

        users = db.get_objects_by_type("user")
        assert len(users) == 2

        orders = db.get_objects_by_type("order")
        assert len(orders) == 1

    def test_get_objects_by_user(self):
        db = ObjectInventoryDB()
        db.record_object("profile", "p1", "sess_a", owner_user_id="user_a")
        db.record_object("profile", "p2", "sess_b", owner_user_id="user_b")

        a_objects = db.get_objects_by_user("user_a")
        assert len(a_objects) == 1

    def test_get_objects_by_org(self):
        db = ObjectInventoryDB()
        db.record_object("project", "proj1", "sess_a", owner_org_id="org_1")
        db.record_object("project", "proj2", "sess_b", owner_org_id="org_1")
        db.record_object("project", "proj3", "sess_c", owner_org_id="org_2")

        org1 = db.get_objects_by_org("org_1")
        assert len(org1) == 2

    def test_update_object(self):
        db = ObjectInventoryDB()
        db.record_object("user", "u1", "sess_a", data={"name": "Alice"})
        updated = db.update_object("u1", data={"name": "Alice Updated"})
        assert updated is True
        obj = db.get_object("u1")
        assert obj["data"]["name"] == "Alice Updated"

    def test_update_nonexistent(self):
        db = ObjectInventoryDB()
        assert db.update_object("nonexistent") is False

    def test_increment_access_count(self):
        db = ObjectInventoryDB()
        db.record_object("user", "u1", "sess_a")
        count = db.increment_access_count("u1")
        assert count == 1
        count = db.increment_access_count("u1")
        assert count == 2

    def test_remove_object(self):
        db = ObjectInventoryDB()
        db.record_object("user", "u1", "sess_a")
        assert db.remove_object("u1") is True
        assert db.get_object("u1") is None
        assert db.remove_object("u1") is False

    def test_get_idor_candidates(self):
        db = ObjectInventoryDB()
        db.record_object("profile", "p1", "sess_a", owner_user_id="user_a")
        db.record_object("profile", "p2", "sess_b", owner_user_id="user_b")
        db.record_object("profile", "p3", "sess_c", owner_user_id="user_c")

        candidates = db.get_idor_candidates("profile")
        assert len(candidates) == 1
        assert candidates[0]["object_type"] == "profile"
        assert candidates[0]["owner_count"] == 3

    def test_get_idor_candidates_min_owners(self):
        db = ObjectInventoryDB()
        db.record_object("profile", "p1", "sess_a")
        db.record_object("profile", "p2", "sess_b")

        # min_owners=3 → no candidates
        candidates = db.get_idor_candidates("profile", min_owners=3)
        assert len(candidates) == 0

        # min_owners=2 → one candidate
        candidates = db.get_idor_candidates("profile", min_owners=2)
        assert len(candidates) == 1

    def test_get_cross_role_objects(self):
        db = ObjectInventoryDB()
        db.record_object("doc", "d1", "sess_a", owner_role="admin")
        db.record_object("doc", "d2", "sess_b", owner_role="member")

        cross = db.get_cross_role_objects("doc")
        assert len(cross) == 1
        assert set(cross[0]["roles"]) == {"admin", "member"}

    def test_record_access_test(self):
        db = ObjectInventoryDB()
        db.record_object("user", "u1", "sess_a")
        test_id = db.record_access_test(
            object_id="u1",
            source_session_id="sess_a",
            source_role="admin",
            target_session_id="sess_b",
            target_role="member",
            endpoint="/api/users/u1",
            method="GET",
            status_code=200,
            is_breach=True,
            breach_type="read_idor",
        )
        assert test_id is not None

    def test_detect_ownership_bypass(self):
        db = ObjectInventoryDB()
        db.record_object("user", "u1", "sess_a")
        db.record_access_test(
            object_id="u1",
            source_session_id="sess_a",
            source_role="admin",
            target_session_id="sess_b",
            target_role="member",
            endpoint="/api/users/u1",
            method="GET",
            status_code=200,
            is_breach=True,
            breach_type="read_idor",
        )

        bypass = db.detect_ownership_bypass("user", "sess_b", "u1")
        assert bypass["is_bypass"] is True

    def test_detect_ownership_bypass_same_owner(self):
        db = ObjectInventoryDB()
        db.record_object("user", "u1", "sess_a")
        bypass = db.detect_ownership_bypass("user", "sess_a", "u1")
        assert bypass["is_bypass"] is False
        assert bypass["reason"] == "same_owner"

    def test_record_finding(self):
        db = ObjectInventoryDB()
        finding_id = db.record_finding(
            finding_type="idor",
            severity="high",
            object_type="user",
            object_id="u1",
            endpoint="/api/users/u1",
            method="GET",
            source_session_id="sess_a",
            target_session_id="sess_b",
            breach_description="User B can access User A's profile",
        )
        assert finding_id is not None
        findings = db.get_findings()
        assert len(findings) == 1
        assert findings[0]["finding_type"] == "idor"

    def test_mark_finding_reported(self):
        db = ObjectInventoryDB()
        fid = db.record_finding(
            finding_type="idor", severity="high",
            object_type="user", object_id="u1",
            endpoint="/api/users/u1", method="GET",
            source_session_id="a", target_session_id="b",
            breach_description="test",
        )
        assert db.mark_finding_reported(fid) is True
        unreported = db.get_unreported_findings()
        assert len(unreported) == 0

    def test_build_idor_report(self):
        db = ObjectInventoryDB()
        db.record_object("profile", "p1", "sess_a", owner_role="admin")
        db.record_object("profile", "p2", "sess_b", owner_role="member")
        report = db.build_idor_report()
        assert "summary" in report
        assert report["summary"]["total_objects"] == 2
        assert len(report["idor_candidates"]) == 1

    def test_to_summary(self):
        db = ObjectInventoryDB()
        db.record_object("user", "u1", "sess_a")
        summary = db.to_summary()
        assert summary["total_objects"] == 1
        assert "user" in summary["object_types"]

    def test_clear(self):
        db = ObjectInventoryDB()
        db.record_object("user", "u1", "sess_a")
        db.record_object("user", "u2", "sess_b")
        count = db.clear()
        assert count == 2
        assert db.get_object_count() == 0

    def test_persistence(self, tmp_path):
        db_path = str(tmp_path / "persist_test.db")
        db = ObjectInventoryDB(db_path)
        db.record_object("user", "u1", "sess_a")
        db.close()

        # Reload
        db2 = ObjectInventoryDB(db_path)
        assert db2.get_object_count() == 1
        obj = db2.get_object("u1")
        assert obj is not None
        db2.close()

    def test_get_all_object_types(self):
        db = ObjectInventoryDB()
        db.record_object("user", "u1", "s1")
        db.record_object("order", "o1", "s1")
        db.record_object("user", "u2", "s2")
        types = db.get_all_object_types()
        assert set(types) == {"order", "user"}

    def test_get_object_count_by_type(self):
        db = ObjectInventoryDB()
        db.record_object("user", "u1", "s1")
        db.record_object("user", "u2", "s1")
        db.record_object("order", "o1", "s1")
        counts = db.get_object_count_by_type()
        assert counts["user"] == 2
        assert counts["order"] == 1


# ---------------------------------------------------------------------------
# M5: ObjectInventoryDB — SQLite persistence tests
# ---------------------------------------------------------------------------

class TestObjectInventoryDBSQLite:
    """SQLite-specific tests for ObjectInventoryDB."""

    def test_sqlite_persistence_objects(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        db = ObjectInventoryDB(db_path)
        db.record_object("user", "u1", "sess_a", owner_user_id="user_a")
        db.record_object("order", "o1", "sess_b", data={"total": 50})
        db.close()

        db2 = ObjectInventoryDB(db_path)
        assert db2.get_object_count() == 2
        assert db2.get_objects_by_type("user")[0]["object_id"] == "u1"
        db2.close()

    def test_sqlite_persistence_access_tests(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        db = ObjectInventoryDB(db_path)
        db.record_object("user", "u1", "sess_a")
        db.record_access_test(
            object_id="u1",
            source_session_id="sess_a", source_role="admin",
            target_session_id="sess_b", target_role="member",
            endpoint="/api/users/u1", method="GET",
            status_code=200, is_breach=True, breach_type="read_idor",
        )
        db.close()

        db2 = ObjectInventoryDB(db_path)
        report = db2.build_idor_report()
        assert report["summary"]["breach_count"] == 1
        db2.close()

    def test_sqlite_persistence_findings(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        db = ObjectInventoryDB(db_path)
        db.record_finding(
            finding_type="idor", severity="high",
            object_type="user", object_id="u1",
            endpoint="/api/users/u1", method="GET",
            source_session_id="a", target_session_id="b",
            breach_description="test finding",
        )
        db.close()

        db2 = ObjectInventoryDB(db_path)
        findings = db2.get_findings()
        assert len(findings) == 1
        db2.close()


# ---------------------------------------------------------------------------
# M6: CrossUserIDORTester — unit tests (no network)
# ---------------------------------------------------------------------------

class TestCrossUserIDORHelpers:
    """Test helper functions used by CrossUserIDORTester."""

    def test_extract_ids_from_url(self):
        from authcore.idor_tester import _extract_ids_from_url
        ids = _extract_ids_from_url("https://api.target.com/users/12345/profile")
        assert "12345" in ids

    def test_extract_ids_from_url_no_numeric_ids(self):
        from authcore.idor_tester import _extract_ids_from_url
        ids = _extract_ids_from_url("https://api.target.com/a/b")
        assert len(ids) == 0

    def test_extract_ids_from_json(self):
        from authcore.idor_tester import _extract_ids_from_json
        data = {"user": {"id": "usr_abc", "name": "Test"}, "order_id": "ord_123"}
        ids = _extract_ids_from_json(data)
        assert "usr_abc" in ids
        assert "ord_123" in ids

    def test_extract_ids_from_json_nested(self):
        from authcore.idor_tester import _extract_ids_from_json
        data = {"items": [{"id": "i1"}, {"id": "i2"}]}
        ids = _extract_ids_from_json(data)
        assert "i1" in ids
        assert "i2" in ids

    def test_response_fingerprint(self):
        from authcore.idor_tester import _response_fingerprint
        fp1 = _response_fingerprint(b'{"name": "Alice", "id": "123"}')
        fp2 = _response_fingerprint(b'{"name": "Alice", "id": "456"}')
        # Same structure, different IDs → should be similar
        assert fp1 is not None
        assert fp2 is not None

    def test_classify_response_unauthorized(self):
        from authcore.idor_tester import _classify_response
        result = _classify_response(403, 100, "fp1", "fp1", 200)
        assert result["is_breach"] is False
        assert result["reason"] == "unauthorized"

    def test_classify_response_not_found(self):
        from authcore.idor_tester import _classify_response
        result = _classify_response(404, 50, "fp1", "fp1", 200)
        assert result["is_breach"] is False

    def test_classify_response_idor(self):
        from authcore.idor_tester import _classify_response
        result = _classify_response(200, 500, "fp1", "fp1", 200)
        assert result["is_breach"] is True
        assert result["breach_type"] == "read_idor"

    def test_fingerprints_similar(self):
        from authcore.idor_tester import _fingerprints_similar
        assert _fingerprints_similar("abc123", "abc123") is True
        assert _fingerprints_similar("abc123", "xyz789") is False


# ---------------------------------------------------------------------------
# M7: AccountBoundaryTester — helper tests
# ---------------------------------------------------------------------------

class TestAccountBoundaryHelpers:
    """Test helper functions used by AccountBoundaryTester."""

    def test_response_similar(self):
        from authcore.boundary_tester import _response_similar
        body = b'{"name": "Alice", "email": "alice@test.com", "role": "admin"}'
        assert _response_similar(body, body) is True

    def test_response_similar_different(self):
        from authcore.boundary_tester import _response_similar
        body1 = b'{"name": "Alice", "email": "alice@test.com"}'
        body2 = b'{"name": "Bob", "email": "bob@test.com", "role": "user"}'
        assert _response_similar(body1, body2) is False

    def test_response_similar_empty(self):
        from authcore.boundary_tester import _response_similar
        assert _response_similar(b"", b"") is False


# ---------------------------------------------------------------------------
# M8: RoleTester — helper tests
# ---------------------------------------------------------------------------

class TestRoleTesterHelpers:
    """Test RoleTester constants and helpers."""

    def test_role_field_names(self):
        from authcore.role_tester import _ROLE_FIELD_NAMES
        assert "role" in _ROLE_FIELD_NAMES
        assert "is_admin" in _ROLE_FIELD_NAMES

    def test_role_bypass_headers(self):
        from authcore.role_tester import _ROLE_BYPASS_HEADERS
        assert len(_ROLE_BYPASS_HEADERS) > 0
        assert all(isinstance(h, dict) for h in _ROLE_BYPASS_HEADERS)

    def test_method_override_headers(self):
        from authcore.role_tester import _METHOD_OVERRIDE_HEADERS
        assert "X-HTTP-Method" in _METHOD_OVERRIDE_HEADERS


# ---------------------------------------------------------------------------
# M9: GraphQL Auth Tester — helper tests
# ---------------------------------------------------------------------------

class TestGraphQLHelpers:
    """Test GraphQL tester constants and helpers."""

    def test_introspection_query(self):
        from authcore.graphql_tester import _INTROSPECTION_QUERY
        assert "__schema" in _INTROSPECTION_QUERY

    def test_sensitive_fields(self):
        from authcore.graphql_tester import _SENSITIVE_FIELDS
        assert "password" in _SENSITIVE_FIELDS
        assert "api_key" in _SENSITIVE_FIELDS
        assert "secret" in _SENSITIVE_FIELDS

    def test_extract_visible_fields(self):
        from authcore.graphql_tester import GraphQLAuthTester
        from authcore.object_inventory import ObjectInventoryDB
        tester = GraphQLAuthTester(ObjectInventoryDB())
        data = {
            "user": {
                "id": "1",
                "name": "Alice",
                "email": "alice@test.com",
                "password_hash": "abc123",
            }
        }
        visible = tester._extract_visible_fields(
            data, ["user.email", "user.password_hash", "user.name"]
        )
        assert "user.email" in visible
        assert "user.password_hash" in visible
        assert "user.name" in visible

    def test_extract_objects_from_response(self):
        from authcore.graphql_tester import GraphQLAuthTester
        from authcore.object_inventory import ObjectInventoryDB
        tester = GraphQLAuthTester(ObjectInventoryDB())
        data = {
            "data": {
                "users": [
                    {"id": "u1", "name": "Alice"},
                    {"id": "u2", "name": "Bob"},
                ]
            }
        }
        ids = tester._extract_objects_from_response(data)
        assert "u1" in ids
        assert "u2" in ids

    def test_parse_schema(self):
        from authcore.graphql_tester import GraphQLAuthTester
        from authcore.object_inventory import ObjectInventoryDB
        tester = GraphQLAuthTester(ObjectInventoryDB())
        schema = {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "types": [
                {
                    "name": "Query",
                    "kind": "OBJECT",
                    "fields": [
                        {"name": "users", "type": {"name": "User"}, "args": []},
                        {"name": "orders", "type": {"name": "Order"}, "args": []},
                    ],
                },
                {
                    "name": "Mutation",
                    "kind": "OBJECT",
                    "fields": [
                        {"name": "createUser", "type": {"name": "User"}, "args": []},
                    ],
                },
                {
                    "name": "User",
                    "kind": "OBJECT",
                    "fields": [
                        {"name": "id", "type": {"name": "String"}, "args": []},
                        {"name": "password_hash", "type": {"name": "String"}, "args": []},
                    ],
                },
                {"name": "__Schema", "kind": "OBJECT", "fields": []},
            ],
        }
        result = tester._parse_schema(schema)
        assert result["type_count"] == 3
        assert len(result["queries"]) == 2
        assert len(result["mutations"]) == 1
        assert len(result["sensitive_fields"]) == 1
        assert result["sensitive_fields"][0]["field"] == "password_hash"


# ---------------------------------------------------------------------------
# M10: Multi-Org Tester — helper tests
# ---------------------------------------------------------------------------

class TestMultiOrgHelpers:
    """Test MultiOrgTester constants."""

    def test_org_id_patterns(self):
        from authcore.multi_org_tester import _ORG_ID_PATTERNS
        assert len(_ORG_ID_PATTERNS) > 0
        assert all("{org_id}" in p for p in _ORG_ID_PATTERNS)


# ---------------------------------------------------------------------------
# Integration: ObjectInventoryDB + store
# ---------------------------------------------------------------------------

class TestInventoryIntegration:
    """Integration tests combining ObjectInventoryDB with AuthSessionStore."""

    def test_store_and_inventory_workflow(self):
        store = AuthSessionStore()
        inventory = ObjectInventoryDB()

        # Create sessions
        sess_a = _make_session("admin", UserRole.ADMIN, user_id="u1", org_id="org1")
        sess_b = _make_session("member", UserRole.MEMBER, user_id="u2", org_id="org1")
        sess_c = _make_session("viewer", UserRole.VIEWER, user_id="u3", org_id="org2")

        store.add_session(sess_a)
        store.add_session(sess_b)
        store.add_session(sess_c)

        # Record objects
        inventory.record_object("profile", "p1", sess_a.session_id, owner_user_id="u1", owner_role="admin")
        inventory.record_object("profile", "p2", sess_b.session_id, owner_user_id="u2", owner_role="member")
        inventory.record_object("profile", "p3", sess_c.session_id, owner_user_id="u3", owner_role="viewer")

        # Find IDOR candidates
        candidates = inventory.get_idor_candidates("profile")
        assert len(candidates) == 1
        assert candidates[0]["owner_count"] == 3

        # Cross-role detection
        cross_role = inventory.get_cross_role_objects("profile")
        assert len(cross_role) == 1
        assert set(cross_role[0]["roles"]) == {"admin", "member", "viewer"}

        # Build report
        report = inventory.build_idor_report()
        assert report["summary"]["total_objects"] == 3
        assert report["summary"]["total_sessions"] == 3

        store.close()
        inventory.close()

    def test_full_idor_workflow(self):
        inventory = ObjectInventoryDB()
        sess_a = _make_session("owner_a", UserRole.MEMBER, user_id="u1")
        sess_b = _make_session("attacker_b", UserRole.MEMBER, user_id="u2")

        # Record objects
        inventory.record_object("invoice", "inv_001", sess_a.session_id, owner_user_id="u1")
        inventory.record_object("invoice", "inv_002", sess_a.session_id, owner_user_id="u1")
        inventory.record_object("invoice", "inv_003", sess_b.session_id, owner_user_id="u2")

        # Record a breach test
        inventory.record_access_test(
            object_id="inv_001",
            source_session_id=sess_a.session_id,
            source_role="member",
            target_session_id=sess_b.session_id,
            target_role="member",
            endpoint="/api/invoices/inv_001",
            method="GET",
            status_code=200,
            is_breach=True,
            breach_type="read_idor",
        )

        # Record finding
        inventory.record_finding(
            finding_type="idor",
            severity="high",
            object_type="invoice",
            object_id="inv_001",
            endpoint="/api/invoices/inv_001",
            method="GET",
            source_session_id=sess_a.session_id,
            target_session_id=sess_b.session_id,
            breach_description="User B can read User A's invoice",
        )

        # Verify
        report = inventory.build_idor_report()
        assert report["summary"]["total_objects"] == 3
        assert report["summary"]["breach_count"] == 1
        assert report["summary"]["total_findings"] == 1
        assert len(report["idor_candidates"]) == 1

        # Check ownership bypass
        bypass = inventory.detect_ownership_bypass("invoice", sess_b.session_id, "inv_001")
        assert bypass["is_bypass"] is True

        inventory.close()

    def test_role_hierarchy_in_inventory(self):
        inventory = ObjectInventoryDB()
        sess_admin = _make_session("admin", UserRole.ADMIN)
        sess_member = _make_session("member", UserRole.MEMBER)
        sess_viewer = _make_session("viewer", UserRole.VIEWER)

        # All three roles own same object type
        inventory.record_object("settings", "s1", sess_admin.session_id, owner_role="admin")
        inventory.record_object("settings", "s2", sess_member.session_id, owner_role="member")
        inventory.record_object("settings", "s3", sess_viewer.session_id, owner_role="viewer")

        cross = inventory.get_cross_role_objects("settings")
        assert len(cross) == 1
        assert set(cross[0]["roles"]) == {"admin", "member", "viewer"}

        candidates = inventory.get_idor_candidates("settings")
        assert len(candidates) == 1
        assert candidates[0]["owner_count"] == 3

        inventory.close()

    def test_multi_org_inventory(self):
        inventory = ObjectInventoryDB()
        sess_a1 = _make_session("org_a_member", UserRole.MEMBER, org_id="org_a")
        sess_a2 = _make_session("org_a_admin", UserRole.ADMIN, org_id="org_a")
        sess_b1 = _make_session("org_b_member", UserRole.MEMBER, org_id="org_b")

        inventory.record_object("project", "proj1", sess_a1.session_id, owner_org_id="org_a")
        inventory.record_object("project", "proj2", sess_a2.session_id, owner_org_id="org_a")
        inventory.record_object("project", "proj3", sess_b1.session_id, owner_org_id="org_b")

        # Cross-org IDOR candidates
        candidates = inventory.get_idor_candidates("project")
        assert len(candidates) == 1
        assert candidates[0]["owner_count"] == 3

        # Org-specific query
        org_a_objects = inventory.get_objects_by_org("org_a")
        assert len(org_a_objects) == 2

        org_b_objects = inventory.get_objects_by_org("org_b")
        assert len(org_b_objects) == 1

        inventory.close()


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
