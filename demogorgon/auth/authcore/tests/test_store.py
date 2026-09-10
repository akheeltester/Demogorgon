"""
authcore/tests/test_store.py — Unit tests for AuthSessionStore.

Run: python -m pytest authcore/tests/test_store.py -v
"""

import json
import os
import tempfile
import time
import pytest
from datetime import datetime, timezone, timedelta

from demogorgon.auth.authcore.session import AuthSession, UserRole, AuthType, CookieJar, OrgMeta, AccountMeta
from demogorgon.auth.authcore.store import AuthSessionStore


# ── Fixtures ──────────────────────────────────────────────────────────

@pytest.fixture
def store():
    """In-memory store for testing."""
    return AuthSessionStore()


@pytest.fixture
def sqlite_store():
    """SQLite-backed store for persistence testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    store = AuthSessionStore(db_path=db_path)
    yield store
    store.close()
    os.unlink(db_path)


@pytest.fixture
def alice_session():
    return AuthSession(
        label="alice",
        role=UserRole.MEMBER,
        auth_type=AuthType.COOKIE,
        cookies=CookieJar(cookies={"session": "alice_sess", "csrf": "alice_csrf"}, domain="app.example.com"),
        target_domain="app.example.com",
        account=AccountMeta(user_id="alice_id", username="alice", email="alice@example.com"),
        org=OrgMeta(org_id="org_1", org_name="Acme Corp"),
    )


@pytest.fixture
def bob_session():
    return AuthSession(
        label="bob",
        role=UserRole.MEMBER,
        auth_type=AuthType.COOKIE,
        cookies=CookieJar(cookies={"session": "bob_sess", "csrf": "bob_csrf"}, domain="app.example.com"),
        target_domain="app.example.com",
        account=AccountMeta(user_id="bob_id", username="bob", email="bob@example.com"),
        org=OrgMeta(org_id="org_1", org_name="Acme Corp"),
    )


@pytest.fixture
def admin_session():
    return AuthSession(
        label="admin",
        role=UserRole.ADMIN,
        auth_type=AuthType.COOKIE,
        cookies=CookieJar(cookies={"session": "admin_sess"}, domain="app.example.com"),
        target_domain="app.example.com",
        account=AccountMeta(user_id="admin_id", username="admin", email="admin@example.com"),
        org=OrgMeta(org_id="org_1", org_name="Acme Corp"),
    )


@pytest.fixture
def owner_session():
    return AuthSession(
        label="owner",
        role=UserRole.OWNER,
        auth_type=AuthType.COOKIE,
        cookies=CookieJar(cookies={"session": "owner_sess"}, domain="app.example.com"),
        target_domain="app.example.com",
        account=AccountMeta(user_id="owner_id", username="owner", email="owner@example.com"),
        org=OrgMeta(org_id="org_1", org_name="Acme Corp"),
    )


@pytest.fixture
def org2_admin():
    return AuthSession(
        label="org2_admin",
        role=UserRole.ADMIN,
        auth_type=AuthType.COOKIE,
        cookies=CookieJar(cookies={"session": "org2_admin"}, domain="app.example.com"),
        target_domain="app.example.com",
        account=AccountMeta(user_id="org2_admin_id", email="admin@widget.com"),
        org=OrgMeta(org_id="org_2", org_name="Widget Inc"),
    )


# ── Add/Remove Tests ──────────────────────────────────────────────────

class TestAddRemove:
    def test_add_session(self, store, alice_session):
        sid = store.add_session(alice_session)
        assert sid == alice_session.session_id
        assert store.get_session_count() == 1

    def test_add_multiple(self, store, alice_session, bob_session):
        store.add_session(alice_session)
        store.add_session(bob_session)
        assert store.get_session_count() == 2

    def test_remove_session(self, store, alice_session):
        store.add_session(alice_session)
        assert store.remove_session(alice_session.session_id) is True
        assert store.get_session_count() == 0

    def test_remove_nonexistent(self, store):
        assert store.remove_session("nonexistent") is False

    def test_clear(self, store, alice_session, bob_session):
        store.add_session(alice_session)
        store.add_session(bob_session)
        count = store.clear()
        assert count == 2
        assert store.get_session_count() == 0

    def test_replace_by_fingerprint(self, store):
        # Two sessions with identical auth data but different labels/IDs
        s1 = AuthSession(
            label="first", role=UserRole.MEMBER, auth_type=AuthType.COOKIE,
            cookies=CookieJar(cookies={"s": "v1"}, domain="example.com"),
            target_domain="example.com",
        )
        s2 = AuthSession(
            label="second", role=UserRole.MEMBER, auth_type=AuthType.COOKIE,
            cookies=CookieJar(cookies={"s": "v1"}, domain="example.com"),
            target_domain="example.com",
        )
        # Verify fingerprints match
        assert s1.fingerprint() == s2.fingerprint()
        store.add_session(s1)
        store.add_session(s2)
        # Same fingerprint, should replace
        assert store.get_session_count() == 1
        retrieved = store.get_session(s2.session_id)
        assert retrieved.label == "second"


# ── Lookup Tests ───────────────────────────────────────────────────────

class TestLookup:
    def test_get_by_id(self, store, alice_session):
        store.add_session(alice_session)
        found = store.get_session(alice_session.session_id)
        assert found is alice_session

    def test_get_by_fingerprint(self, store, alice_session):
        store.add_session(alice_session)
        fp = alice_session.fingerprint()
        found = store.get_by_fingerprint(fp)
        assert found is alice_session

    def test_has_session(self, store, alice_session):
        store.add_session(alice_session)
        assert store.has_session(alice_session.session_id) is True
        assert store.has_session("nonexistent") is False

    def test_not_found(self, store):
        assert store.get_session("nonexistent") is None
        assert store.get_by_fingerprint("nonexistent") is None


# ── Role Query Tests ──────────────────────────────────────────────────

class TestRoleQuery:
    def test_get_by_role(self, store, alice_session, bob_session, admin_session):
        store.add_session(alice_session)
        store.add_session(bob_session)
        store.add_session(admin_session)
        members = store.get_sessions_by_role(UserRole.MEMBER)
        assert len(members) == 2
        admins = store.get_sessions_by_role(UserRole.ADMIN)
        assert len(admins) == 1

    def test_get_highest_role(self, store, alice_session, admin_session, owner_session):
        store.add_session(alice_session)
        store.add_session(admin_session)
        store.add_session(owner_session)
        best = store.get_highest_role_session("app.example.com")
        assert best.role == UserRole.OWNER


# ── Domain Query Tests ────────────────────────────────────────────────

class TestDomainQuery:
    def test_get_for_domain(self, store, alice_session):
        store.add_session(alice_session)
        sessions = store.get_sessions_for_domain("app.example.com")
        assert len(sessions) == 1

    def test_get_best_session(self, store, alice_session, admin_session):
        store.add_session(alice_session)
        store.add_session(admin_session)
        best = store.get_best_session("app.example.com", UserRole.ADMIN)
        assert best.role == UserRole.ADMIN

    def test_get_best_fallback(self, store, alice_session):
        store.add_session(alice_session)
        best = store.get_best_session("app.example.com", UserRole.ADMIN)
        assert best.role == UserRole.MEMBER  # Falls back to available

    def test_get_best_none(self, store):
        best = store.get_best_session("nonexistent.com")
        assert best is None

    def test_parent_domain_match(self, store):
        s = AuthSession.from_cookies({"s": "v"}, "example.com", label="parent_test")
        store.add_session(s)
        found = store.get_sessions_for_domain("api.example.com")
        assert len(found) == 1


# ── Org Query Tests ───────────────────────────────────────────────────

class TestOrgQuery:
    def test_get_by_org(self, store, alice_session, bob_session, org2_admin):
        store.add_session(alice_session)
        store.add_session(bob_session)
        store.add_session(org2_admin)
        org1 = store.get_sessions_by_org("org_1")
        assert len(org1) == 2
        org2 = store.get_sessions_by_org("org_2")
        assert len(org2) == 1

    def test_get_org_members(self, store, alice_session, admin_session, owner_session):
        store.add_session(alice_session)
        store.add_session(admin_session)
        store.add_session(owner_session)
        members = store.get_org_members("org_1")
        assert len(members) == 3
        # Sorted by role level
        assert members[0].role == UserRole.MEMBER
        assert members[1].role == UserRole.ADMIN
        assert members[2].role == UserRole.OWNER

    def test_get_org_role_matrix(self, store, alice_session, admin_session, owner_session):
        store.add_session(alice_session)
        store.add_session(admin_session)
        store.add_session(owner_session)
        matrix = store.get_org_role_matrix("org_1")
        assert "member" in matrix
        assert "admin" in matrix
        assert "owner" in matrix


# ── User Query Tests ──────────────────────────────────────────────────

class TestUserQuery:
    def test_get_by_user(self, store, alice_session):
        store.add_session(alice_session)
        found = store.get_sessions_by_user("alice_id")
        assert len(found) == 1
        assert found[0].account.user_id == "alice_id"


# ── Search Tests ───────────────────────────────────────────────────────

class TestSearch:
    def test_search_by_query(self, store, alice_session, bob_session):
        store.add_session(alice_session)
        store.add_session(bob_session)
        results = store.search(query="alice")
        assert len(results) == 1
        assert results[0].label == "alice"

    def test_search_by_role(self, store, alice_session, admin_session):
        store.add_session(alice_session)
        store.add_session(admin_session)
        results = store.search(role=UserRole.ADMIN)
        assert len(results) == 1

    def test_search_by_domain(self, store, alice_session):
        store.add_session(alice_session)
        results = store.search(domain="example.com")
        assert len(results) == 1

    def test_search_by_org(self, store, alice_session, org2_admin):
        store.add_session(alice_session)
        store.add_session(org2_admin)
        results = store.search(org_id="org_1")
        assert len(results) == 1

    def test_search_combined(self, store, alice_session, bob_session, admin_session):
        store.add_session(alice_session)
        store.add_session(bob_session)
        store.add_session(admin_session)
        results = store.search(role=UserRole.MEMBER, domain="example.com")
        assert len(results) == 2


# ── SQLite Persistence Tests ──────────────────────────────────────────

class TestSQLite:
    def test_persist_and_load(self, sqlite_store, alice_session):
        sqlite_store.add_session(alice_session)
        # Create new store from same DB
        new_store = AuthSessionStore(db_path=sqlite_store._db_path)
        found = new_store.get_session(alice_session.session_id)
        assert found is not None
        assert found.label == "alice"
        new_store.close()

    def test_persist_multiple(self, sqlite_store, alice_session, bob_session):
        sqlite_store.add_session(alice_session)
        sqlite_store.add_session(bob_session)
        new_store = AuthSessionStore(db_path=sqlite_store._db_path)
        assert new_store.get_session_count() == 2
        new_store.close()

    def test_delete_persisted(self, sqlite_store, alice_session):
        sqlite_store.add_session(alice_session)
        sqlite_store.remove_session(alice_session.session_id)
        new_store = AuthSessionStore(db_path=sqlite_store._db_path)
        assert new_store.get_session_count() == 0
        new_store.close()


# ── File Persistence Tests ────────────────────────────────────────────

class TestFilePersistence:
    def test_save_and_load(self, store, alice_session, bob_session):
        store.add_session(alice_session)
        store.add_session(bob_session)
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            store.save_to_file(path)
            new_store = AuthSessionStore()
            count = new_store.load_from_file(path)
            assert count == 2
            assert new_store.get_session(alice_session.session_id) is not None
            assert new_store.get_session(bob_session.session_id) is not None
        finally:
            os.unlink(path)


# ── Health Check Tests ────────────────────────────────────────────────

class TestHealthCheck:
    def test_remove_expired(self, store):
        expired = AuthSession(
            label="expired",
            target_domain="example.com",
            expires_at=(datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
            cookies=CookieJar(cookies={"s": "expired_val"}, domain="example.com"),
        )
        valid = AuthSession(
            label="valid",
            target_domain="example.com",
            cookies=CookieJar(cookies={"s": "valid_val"}, domain="example.com"),
        )
        store.add_session(expired)
        store.add_session(valid)
        removed = store.remove_expired()
        assert removed == 1
        assert store.get_session_count() == 1

    def test_remove_invalid(self, store):
        invalid = AuthSession(label="invalid", target_domain="example.com")
        invalid.is_valid = False
        valid = AuthSession.from_cookies({"s": "v"}, "example.com", label="valid")
        store.add_session(invalid)
        store.add_session(valid)
        removed = store.remove_invalid()
        assert removed == 1
        assert store.get_session_count() == 1


# ── Summary Tests ─────────────────────────────────────────────────────

class TestSummary:
    def test_to_summary(self, store, alice_session, admin_session):
        store.add_session(alice_session)
        store.add_session(admin_session)
        summary = store.to_summary()
        assert summary["total_sessions"] == 2
        assert summary["by_role"]["member"] == 1
        assert summary["by_role"]["admin"] == 1

    def test_to_list(self, store, alice_session):
        store.add_session(alice_session)
        lst = store.to_list()
        assert len(lst) == 1
        assert lst[0]["label"] == "alice"


# ── Search API Tests ──────────────────────────────────────────────────

class TestSearchAPI:
    def test_search_by_auth_type(self, store, alice_session):
        bearer = AuthSession.from_bearer_token("tok", "api.example.com", label="api_user")
        store.add_session(alice_session)
        store.add_session(bearer)
        results = store.search(auth_type=AuthType.BEARER)
        assert len(results) == 1
        assert results[0].label == "api_user"

    def test_search_by_source(self, store, alice_session):
        alice_session.source = "browser_export"
        store.add_session(alice_session)
        results = store.search(source="browser_export")
        assert len(results) == 1

    def test_search_by_valid(self, store, alice_session):
        store.add_session(alice_session)
        results = store.search(is_valid=True)
        assert len(results) == 1
        results = store.search(is_valid=False)
        assert len(results) == 0
