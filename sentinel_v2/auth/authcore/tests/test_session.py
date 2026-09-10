"""
authcore/tests/test_session.py — Unit tests for AuthSession and containers.

Run: python -m pytest authcore/tests/test_session.py -v
"""

import json
import time
import pytest
from datetime import datetime, timezone, timedelta

from sentinel_v2.auth.authcore.session import (
    AuthSession,
    UserRole,
    AuthType,
    CookieJar,
    HeaderSet,
    JWTToken,
    CSRFToken,
    AccountMeta,
    OrgMeta,
    ScopeMeta,
)


# ── UserRole Tests ─────────────────────────────────────────────────────

class TestUserRole:
    def test_role_levels(self):
        assert UserRole.VIEWER.level == 0
        assert UserRole.MEMBER.level == 1
        assert UserRole.ADMIN.level == 2
        assert UserRole.OWNER.level == 3

    def test_role_comparison(self):
        assert UserRole.OWNER.is_higher_than(UserRole.ADMIN)
        assert UserRole.ADMIN.is_higher_than(UserRole.MEMBER)
        assert UserRole.MEMBER.is_higher_than(UserRole.VIEWER)
        assert not UserRole.VIEWER.is_higher_than(UserRole.ADMIN)

    def test_role_includes(self):
        assert UserRole.OWNER.includes(UserRole.ADMIN)
        assert UserRole.ADMIN.includes(UserRole.MEMBER)
        assert UserRole.MEMBER.includes(UserRole.VIEWER)
        assert not UserRole.VIEWER.includes(UserRole.MEMBER)

    def test_role_values(self):
        assert UserRole.VIEWER.value == "viewer"
        assert UserRole.MEMBER.value == "member"
        assert UserRole.ADMIN.value == "admin"
        assert UserRole.OWNER.value == "owner"

    def test_role_from_value(self):
        assert UserRole("viewer") == UserRole.VIEWER
        assert UserRole("admin") == UserRole.ADMIN


# ── CookieJar Tests ───────────────────────────────────────────────────

class TestCookieJar:
    def test_set_get(self):
        jar = CookieJar(domain="example.com")
        jar.set("session", "abc123")
        assert jar.get("session") == "abc123"
        assert "session" in jar
        assert len(jar) == 1

    def test_delete(self):
        jar = CookieJar(domain="example.com")
        jar.set("session", "abc123")
        assert jar.delete("session") is True
        assert jar.get("session") == ""
        assert "session" not in jar

    def test_delete_nonexistent(self):
        jar = CookieJar(domain="example.com")
        assert jar.delete("nonexistent") is False

    def test_expiry(self):
        jar = CookieJar(domain="example.com")
        jar.set("expired_cookie", "val", expires=int(time.time()) - 100)
        jar.set("valid_cookie", "val", expires=int(time.time()) + 3600)
        assert jar.is_expired("expired_cookie") is True
        assert jar.is_expired("valid_cookie") is False

    def test_remove_expired(self):
        jar = CookieJar(domain="example.com")
        jar.set("expired1", "v", expires=int(time.time()) - 100)
        jar.set("expired2", "v", expires=int(time.time()) - 200)
        jar.set("valid", "v", expires=int(time.time()) + 3600)
        removed = jar.remove_expired()
        assert removed == 2
        assert len(jar) == 1

    def test_filter_by_domain(self):
        jar = CookieJar(domain="example.com")
        jar.set("s1", "v1", domain="example.com")
        jar.set("s2", "v2", domain="other.com")
        filtered = jar.filter_by_domain("example.com")
        assert "s1" in filtered
        assert "s2" not in filtered

    def test_to_header_string(self):
        jar = CookieJar(domain="example.com")
        jar.set("a", "1")
        jar.set("b", "2")
        header = jar.to_header_string()
        assert "a=1" in header
        assert "b=2" in header
        assert "; " in header

    def test_to_dict_from_dict(self):
        jar = CookieJar(domain="example.com")
        jar.set("test", "value", httponly=True, secure=True)
        data = jar.to_dict()
        restored = CookieJar.from_dict(data)
        assert restored.get("test") == "value"
        assert "test" in restored._httponly
        assert "test" in restored._secure

    def test_iteration(self):
        jar = CookieJar(domain="example.com")
        jar.set("a", "1")
        jar.set("b", "2")
        names = list(jar)
        assert "a" in names
        assert "b" in names

    def test_items(self):
        jar = CookieJar(domain="example.com")
        jar.set("a", "1")
        items = dict(jar.items())
        assert items["a"] == "1"


# ── HeaderSet Tests ───────────────────────────────────────────────────

class TestHeaderSet:
    def test_set_get(self):
        hs = HeaderSet()
        hs.set("Content-Type", "application/json")
        assert hs.get("Content-Type") == "application/json"
        assert "Content-Type" in hs

    def test_case_insensitive(self):
        hs = HeaderSet()
        hs.set("Content-Type", "application/json")
        assert hs.get("content-type") == "application/json"
        assert hs.get("CONTENT-TYPE") == "application/json"

    def test_auth_headers_override(self):
        hs = HeaderSet()
        hs.set("Authorization", "Bearer old", is_auth=False)
        hs.set("Authorization", "Bearer new", is_auth=True)
        assert hs.get("Authorization") == "Bearer new"

    def test_merge(self):
        hs1 = HeaderSet()
        hs1.set("X-Custom", "value1")
        hs2 = HeaderSet()
        hs2.set("X-Other", "value2")
        hs1.merge(hs2)
        assert hs1.get("X-Custom") == "value1"
        assert hs1.get("X-Other") == "value2"

    def test_to_dict(self):
        hs = HeaderSet()
        hs.set("A", "1")
        hs.set("B", "2", is_auth=True)
        d = hs.to_dict()
        assert d["A"] == "1"
        assert d["B"] == "2"

    def test_delete(self):
        hs = HeaderSet()
        hs.set("X-Remove", "value")
        assert hs.delete("X-Remove") is True
        assert hs.get("X-Remove") == ""

    def test_to_raw_headers(self):
        hs = HeaderSet()
        hs.set("A", "1")
        raw = hs.to_raw_headers()
        assert ("A", "1") in raw


# ── JWTToken Tests ────────────────────────────────────────────────────

class TestJWTToken:
    def test_parse_jwt(self):
        # Minimal JWT (header.payload.signature)
        header = json.dumps({"alg": "RS256", "typ": "JWT"})
        payload = json.dumps({
            "sub": "user123",
            "iss": "auth.example.com",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "scope": "read write",
        })
        import base64
        h = base64.urlsafe_b64encode(header.encode()).decode().rstrip("=")
        p = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
        token_str = f"{h}.{p}.signature"

        jwt = JWTToken(token=token_str)
        assert jwt.subject == "user123"
        assert jwt.issuer == "auth.example.com"
        assert jwt.is_expired is False
        assert "read" in jwt.scopes
        assert "write" in jwt.scopes

    def test_expired_jwt(self):
        header = json.dumps({"alg": "RS256", "typ": "JWT"})
        payload = json.dumps({"exp": int(time.time()) - 100})
        import base64
        h = base64.urlsafe_b64encode(header.encode()).decode().rstrip("=")
        p = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
        token_str = f"{h}.{p}.sig"

        jwt = JWTToken(token=token_str)
        assert jwt.is_expired is True

    def test_authorization_value(self):
        jwt = JWTToken(token="test.token", token_type="Bearer")
        assert jwt.authorization_value == "Bearer test.token"

    def test_to_dict_from_dict(self):
        jwt = JWTToken(token="t", subject="user1", issuer="iss")
        data = jwt.to_dict()
        restored = JWTToken.from_dict(data)
        assert restored.subject == "user1"


# ── CSRFToken Tests ───────────────────────────────────────────────────

class TestCSRFToken:
    def test_to_header(self):
        csrf = CSRFToken(token="abc123", header_name="X-CSRF-Token")
        assert csrf.to_header() == {"X-CSRF-Token": "abc123"}

    def test_to_form_data(self):
        csrf = CSRFToken(token="abc123", form_field="csrf_token")
        assert csrf.to_form_data() == {"csrf_token": "abc123"}

    def test_to_query_param(self):
        csrf = CSRFToken(token="abc123", query_param="_csrf")
        assert csrf.to_query_param() == {"_csrf": "abc123"}

    def test_empty_token(self):
        csrf = CSRFToken(token="")
        assert csrf.to_header() == {}

    def test_to_dict_from_dict(self):
        csrf = CSRFToken(token="x", header_name="X-CSRF", form_field="f", query_param="q")
        data = csrf.to_dict()
        restored = CSRFToken.from_dict(data)
        assert restored.token == "x"
        assert restored.header_name == "X-CSRF"


# ── Metadata Tests ────────────────────────────────────────────────────

class TestAccountMeta:
    def test_to_dict_from_dict(self):
        acc = AccountMeta(user_id="u1", username="alice", email="alice@test.com")
        data = acc.to_dict()
        restored = AccountMeta.from_dict(data)
        assert restored.user_id == "u1"
        assert restored.email == "alice@test.com"


class TestOrgMeta:
    def test_to_dict_from_dict(self):
        org = OrgMeta(org_id="o1", org_name="Acme", plan="enterprise")
        data = org.to_dict()
        restored = OrgMeta.from_dict(data)
        assert restored.org_id == "o1"
        assert restored.plan == "enterprise"


class TestScopeMeta:
    def test_has_scope(self):
        scope = ScopeMeta(scopes=["read", "write"])
        assert scope.has_scope("read") is True
        assert scope.has_scope("delete") is False

    def test_wildcard_scope(self):
        scope = ScopeMeta(scopes=["*"])
        assert scope.has_scope("anything") is True

    def test_has_permission(self):
        scope = ScopeMeta(permissions=["admin"])
        assert scope.has_permission("admin") is True
        assert scope.has_permission("user") is False

    def test_can_access(self):
        scope = ScopeMeta(api_access=["/api/users", "/api/orders"])
        assert scope.can_access("/api/users") is True
        assert scope.can_access("/api/admin") is False


# ── AuthSession Tests ─────────────────────────────────────────────────

class TestAuthSession:
    def test_construction(self):
        s = AuthSession(label="test", role=UserRole.ADMIN, target_domain="example.com")
        assert s.label == "test"
        assert s.role == UserRole.ADMIN
        assert s.target_domain == "example.com"
        assert s.session_id  # Auto-generated UUID

    def test_build_headers_cookie(self):
        s = AuthSession.from_cookies(
            {"session": "abc123", "csrf": "xyz"},
            "example.com",
            role=UserRole.MEMBER,
        )
        headers = s.build_request_headers()
        assert "Cookie" in headers
        assert "session=abc123" in headers["Cookie"]
        assert "csrf=xyz" in headers["Cookie"]

    def test_build_headers_bearer(self):
        s = AuthSession.from_bearer_token(
            "my_token_123",
            "api.example.com",
        )
        headers = s.build_request_headers()
        assert headers["Authorization"] == "Bearer my_token_123"

    def test_build_headers_basic(self):
        s = AuthSession.from_basic_auth("user", "pass", "example.com")
        headers = s.build_request_headers()
        assert "Authorization" in headers
        assert headers["Authorization"].startswith("Basic ")

    def test_build_headers_api_key(self):
        s = AuthSession.from_api_key(
            "key_123",
            "X-API-Key",
            "api.example.com",
        )
        headers = s.build_request_headers()
        assert headers["X-API-Key"] == "key_123"

    def test_build_headers_csrf(self):
        s = AuthSession.from_cookies({"s": "v"}, "example.com")
        s.csrf = CSRFToken(token="csrf_val", header_name="X-CSRF-Token")
        headers = s.build_request_headers()
        assert headers["X-CSRF-Token"] == "csrf_val"

    def test_build_headers_extra_override(self):
        s = AuthSession.from_cookies({"s": "v"}, "example.com")
        headers = s.build_request_headers(extra_headers={"Cookie": "overridden"})
        assert headers["Cookie"] == "overridden"

    def test_validate_valid(self):
        s = AuthSession(
            label="test",
            target_domain="example.com",
            cookies=CookieJar(cookies={"s": "v"}),
        )
        ok, issues = s.validate()
        assert ok is True
        assert len(issues) == 0

    def test_validate_no_auth(self):
        s = AuthSession(label="test", target_domain="example.com")
        ok, issues = s.validate()
        assert ok is False
        assert any("no auth data" in i for i in issues)

    def test_validate_no_domain(self):
        s = AuthSession(label="test", cookies=CookieJar(cookies={"s": "v"}))
        ok, issues = s.validate()
        assert ok is False
        assert any("target_domain" in i for i in issues)

    def test_is_expired(self):
        s = AuthSession(
            label="test",
            target_domain="example.com",
            expires_at=(datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
            cookies=CookieJar(cookies={"s": "v"}),
        )
        assert s.is_expired() is True

    def test_not_expired(self):
        s = AuthSession(
            label="test",
            target_domain="example.com",
            expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            cookies=CookieJar(cookies={"s": "v"}),
        )
        assert s.is_expired() is False

    def test_fingerprint_stability(self):
        s1 = AuthSession.from_cookies({"s": "v"}, "example.com", role=UserRole.ADMIN)
        s2 = AuthSession.from_cookies({"s": "v"}, "example.com", role=UserRole.ADMIN)
        assert s1.fingerprint() == s2.fingerprint()

    def test_fingerprint_different(self):
        s1 = AuthSession.from_cookies({"s": "v1"}, "example.com", role=UserRole.ADMIN)
        s2 = AuthSession.from_cookies({"s": "v2"}, "example.com", role=UserRole.ADMIN)
        assert s1.fingerprint() != s2.fingerprint()

    def test_to_dict_from_dict(self):
        s = AuthSession(
            label="test",
            role=UserRole.ADMIN,
            auth_type=AuthType.BEARER,
            target_domain="example.com",
            cookies=CookieJar(cookies={"s": "v"}),
            jwt=JWTToken(token="t", subject="u1"),
            account=AccountMeta(user_id="u1", email="a@b.com"),
            org=OrgMeta(org_id="o1", org_name="Acme"),
        )
        data = s.to_dict()
        restored = AuthSession.from_dict(data)
        assert restored.label == "test"
        assert restored.role == UserRole.ADMIN
        assert restored.auth_type == AuthType.BEARER
        assert restored.target_domain == "example.com"
        assert restored.cookies.get("s") == "v"
        assert restored.jwt.subject == "u1"
        assert restored.account.user_id == "u1"
        assert restored.org.org_id == "o1"

    def test_to_json_from_json(self):
        s = AuthSession(label="test", target_domain="example.com")
        j = s.to_json()
        restored = AuthSession.from_json(j)
        assert restored.label == "test"

    def test_from_cookies_factory(self):
        s = AuthSession.from_cookies({"a": "1"}, "d.com", label="l", role=UserRole.OWNER)
        assert s.auth_type == AuthType.COOKIE
        assert s.cookies.get("a") == "1"
        assert s.role == UserRole.OWNER

    def test_from_bearer_factory(self):
        s = AuthSession.from_bearer_token("tok", "d.com")
        assert s.auth_type == AuthType.BEARER
        assert s.jwt.token == "tok"

    def test_from_jwt_factory(self):
        s = AuthSession.from_jwt("tok", "d.com")
        assert s.auth_type == AuthType.JWT

    def test_from_api_key_factory(self):
        s = AuthSession.from_api_key("key", "X-Key", "d.com")
        assert s.auth_type == AuthType.API_KEY
        assert s.api_key == "key"

    def test_from_basic_factory(self):
        s = AuthSession.from_basic_auth("u", "p", "d.com")
        assert s.auth_type == AuthType.BASIC
        assert s.basic_user == "u"

    def test_mark_used(self):
        s = AuthSession(label="test", target_domain="example.com")
        s.mark_used()
        assert s.last_used is not None

    def test_mark_validated(self):
        s = AuthSession(label="test", target_domain="example.com")
        s.mark_validated(200)
        assert s.is_valid is True
        assert s.last_validation_status == 200

    def test_mark_invalid(self):
        s = AuthSession(label="test", target_domain="example.com")
        s.mark_validated(401)
        assert s.is_valid is False

    def test_equality(self):
        s1 = AuthSession(session_id="fixed-id", label="a")
        s2 = AuthSession(session_id="fixed-id", label="b")
        assert s1 == s2

    def test_hash(self):
        s1 = AuthSession(session_id="id-1")
        s2 = AuthSession(session_id="id-2")
        assert hash(s1) != hash(s2)
        assert len({s1, s2}) == 2

    def test_repr(self):
        s = AuthSession(label="test", role=UserRole.ADMIN, target_domain="example.com")
        r = repr(s)
        assert "test" in r
        assert "admin" in r
        assert "example.com" in r
