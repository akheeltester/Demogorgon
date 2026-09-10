"""
authcore/tests/mock_sessions.py — Pre-built mock sessions for testing.

These represent real-world session patterns that Sentinel will encounter.
Use them in unit tests, integration tests, and development.

Sessions:
    1. ShopifyPartnerSession — Partner portal with session token
    2. ShopifyAdminSession — Admin panel with cookie auth
    3. JWTAPISession — JWT-based API authentication
    4. OAuth2Session — OAuth2 access token
    5. MultiOrgSession — User belonging to multiple orgs
    6. GraphQLSession — GraphQL API with API key
    7. BasicAuthSession — HTTP Basic auth (internal tools)
    8. ExpiredSession — Session past expiry
    9. csrfProtectedSession — Session with CSRF token
"""

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


# ── 1. Shopify Partner Session ────────────────────────────────────────

def shopify_partner_session() -> AuthSession:
    """
    Represents a Shopify Partner portal session.
    
    Auth mechanism: Session cookie (_shopifyPartner)
    Role: Member (can manage apps, view analytics)
    Org: Partner organization
    """
    return AuthSession(
        label="shopify_partner_alice",
        role=UserRole.MEMBER,
        auth_type=AuthType.COOKIE,
        cookies=CookieJar(
            cookies={
                "_shopifyPartner": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.partner_token",
                "_shopifyPartnerNonce": "a1b2c3d4e5f6",
                "partner_session": "sess_abc123def456",
            },
            domain=".shopify.com",
        ),
        target_domain="partners.shopify.com",
        account=AccountMeta(
            user_id="partner_123456",
            username="alice_partners",
            email="alice@acmecorp.com",
            display_name="Alice Chen",
            account_type="partner",
            account_status="active",
        ),
        org=OrgMeta(
            org_id="partner_org_789",
            org_name="Acme Corp",
            org_slug="acme-corp",
            org_type="partner",
            plan="partner_standard",
            role_in_org="admin",
            member_count=5,
        ),
        scope=ScopeMeta(
            scopes=["partner_api", "app_management", "analytics_read"],
            permissions=["manage_apps", "view_analytics", "manage_billing"],
        ),
        source="browser_export",
        validation_endpoint="https://partners.shopify.com/api/auth/session",
    )


# ── 2. Shopify Admin Session ──────────────────────────────────────────

def shopify_admin_session() -> AuthSession:
    """
    Represents a Shopify Admin panel session.
    
    Auth mechanism: Session cookie (_shopify_admin, secure_session)
    Role: Admin (full store access)
    Org: Store (single-store)
    """
    return AuthSession(
        label="shopify_admin_store1",
        role=UserRole.ADMIN,
        auth_type=AuthType.COOKIE,
        cookies=CookieJar(
            cookies={
                "_shopify_admin": "admin_session_token_abc123",
                "secure_session": "secure_val_xyz789",
                "_shopify_uniq": "unique_identifier",
                "cart": "cart_cookie_value",
            },
            domain="my-store.myshopify.com",
        ),
        headers=HeaderSet({
            "X-Shopify-Store-Access-Token": "shpat_abc123def456",
        }),
        target_domain="my-store.myshopify.com",
        account=AccountMeta(
            user_id="store_user_456",
            username="store_admin",
            email="admin@my-store.com",
            display_name="Store Admin",
            account_type="store_admin",
            account_status="active",
        ),
        org=OrgMeta(
            org_id="store_789",
            org_name="My Store",
            org_slug="my-store",
            org_type="store",
            plan="shopify_plus",
            role_in_org="admin",
        ),
        scope=ScopeMeta(
            scopes=["read_products", "write_products", "read_orders", "write_orders"],
            permissions=[
                "manage_products", "manage_orders", "manage_customers",
                "manage_discounts", "manage_themes", "manage_apps",
            ],
            api_access=["/admin/api/*", "/admin/*"],
        ),
        source="browser_export",
        validation_endpoint="https://my-store.myshopify.com/admin/account.json",
    )


# ── 3. JWT API Session ───────────────────────────────────────────────

def jwt_api_session() -> AuthSession:
    """
    Represents a JWT-based API session (e.g., REST API, microservice).
    
    Auth mechanism: Bearer token (JWT)
    Role: Member (API access)
    """
    # Construct a realistic JWT payload
    import base64
    import time
    import json

    header = json.dumps({"alg": "RS256", "typ": "JWT"})
    payload = json.dumps({
        "sub": "user_789",
        "iss": "auth.api.example.com",
        "aud": "api.example.com",
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
        "scope": "read write",
        "org_id": "org_api_123",
        "role": "member",
    })
    h = base64.urlsafe_b64encode(header.encode()).decode().rstrip("=")
    p = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
    token = f"{h}.{p}.signature_hash"

    return AuthSession(
        label="api_jwt_bob",
        role=UserRole.MEMBER,
        auth_type=AuthType.JWT,
        jwt=JWTToken(token=token),
        target_domain="api.example.com",
        account=AccountMeta(
            user_id="user_789",
            username="bob_api",
            email="bob@example.com",
            account_type="api_user",
        ),
        org=OrgMeta(
            org_id="org_api_123",
            org_name="Example API Org",
            org_type="api",
        ),
        scope=ScopeMeta(
            scopes=["read", "write"],
            permissions=["api_access"],
            api_access=["/api/v1/*"],
        ),
        source="cli",
    )


# ── 4. OAuth2 Session ────────────────────────────────────────────────

def oauth2_session() -> AuthSession:
    """
    Represents an OAuth2 access token session.
    
    Auth mechanism: Bearer token (OAuth2)
    Role: Member
    """
    return AuthSession(
        label="oauth2_carol",
        role=UserRole.MEMBER,
        auth_type=AuthType.OAUTH2,
        jwt=JWTToken(
            token="oauth2_access_token_xyz789",
            token_type="Bearer",
            expires_at=int(__import__("time").time()) + 3600,
        ),
        target_domain="app.oauth-provider.com",
        account=AccountMeta(
            user_id="oauth_user_321",
            username="carol",
            email="carol@example.com",
        ),
        scope=ScopeMeta(
            scopes=["openid", "profile", "email", "api.read"],
        ),
        source="browser_export",
    )


# ── 5. Multi-Org Session ─────────────────────────────────────────────

def multi_org_sessions() -> list:
    """
    User belonging to multiple organizations.
    Tests cross-tenant IDOR detection.
    """
    return [
        AuthSession(
            label="dave_org1_member",
            role=UserRole.MEMBER,
            auth_type=AuthType.COOKIE,
            cookies=CookieJar(cookies={"s": "dave_org1"}, domain="app.example.com"),
            target_domain="app.example.com",
            account=AccountMeta(user_id="dave_id", username="dave", email="dave@example.com"),
            org=OrgMeta(org_id="org_alpha", org_name="Alpha Inc", org_type="team"),
        ),
        AuthSession(
            label="dave_org2_admin",
            role=UserRole.ADMIN,
            auth_type=AuthType.COOKIE,
            cookies=CookieJar(cookies={"s": "dave_org2"}, domain="app.example.com"),
            target_domain="app.example.com",
            account=AccountMeta(user_id="dave_id", username="dave", email="dave@example.com"),
            org=OrgMeta(org_id="org_beta", org_name="Beta LLC", org_type="enterprise"),
        ),
    ]


# ── 6. GraphQL Session ───────────────────────────────────────────────

def graphql_api_session() -> AuthSession:
    """
    GraphQL API with API key authentication.
    """
    return AuthSession(
        label="graphql_eve",
        role=UserRole.MEMBER,
        auth_type=AuthType.API_KEY,
        api_key="gql_api_key_abc123def456",
        api_key_header="x-api-key",
        target_domain="graphql.example.com",
        account=AccountMeta(
            user_id="eve_id",
            username="eve",
            email="eve@example.com",
        ),
        scope=ScopeMeta(
            scopes=["graphql:read", "graphql:write"],
            permissions=["query_users", "mutation_orders"],
            api_access=["/graphql"],
        ),
        source="cli",
    )


# ── 7. Basic Auth Session ────────────────────────────────────────────

def basic_auth_session() -> AuthSession:
    """
    HTTP Basic auth (internal tools, staging environments).
    """
    return AuthSession(
        label="basic_staging_admin",
        role=UserRole.ADMIN,
        auth_type=AuthType.BASIC,
        basic_user="admin",
        basic_pass="staging_secret_123",
        target_domain="staging.internal.example.com",
        account=AccountMeta(
            user_id="admin_internal",
            username="admin",
            email="admin@internal.example.com",
        ),
        org=OrgMeta(
            org_id="internal",
            org_name="Internal",
            org_type="internal",
        ),
        source="cli",
    )


# ── 8. Expired Session ───────────────────────────────────────────────

def expired_session() -> AuthSession:
    """
    Session that has already expired.
    Tests expiry detection and cleanup.
    """
    from datetime import datetime, timezone, timedelta

    return AuthSession(
        label="expired_session",
        role=UserRole.MEMBER,
        auth_type=AuthType.COOKIE,
        cookies=CookieJar(cookies={"s": "expired"}, domain="example.com"),
        target_domain="example.com",
        expires_at=(datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
        source="browser_export",
    )


# ── 9. CSRF-Protected Session ────────────────────────────────────────

def csrf_protected_session() -> AuthSession:
    """
    Session with CSRF token (Rails/Django style).
    """
    return AuthSession(
        label="csrf_frank",
        role=UserRole.MEMBER,
        auth_type=AuthType.COOKIE,
        cookies=CookieJar(
            cookies={
                "session_id": "frank_session_abc",
                "XSRF-TOKEN": "xsrf_token_value",
            },
            domain="rails-app.example.com",
        ),
        csrf=CSRFToken(
            token="xsrf_token_value",
            header_name="X-XSRF-TOKEN",
            form_field="_csrf",
            query_param="_csrf",
        ),
        target_domain="rails-app.example.com",
        account=AccountMeta(
            user_id="frank_id",
            username="frank",
            email="frank@example.com",
        ),
        source="browser_export",
    )


# ── All Sessions Registry ────────────────────────────────────────────

MOCK_SESSIONS = {
    "shopify_partner": shopify_partner_session,
    "shopify_admin": shopify_admin_session,
    "jwt_api": jwt_api_session,
    "oauth2": oauth2_session,
    "graphql_api": graphql_api_session,
    "basic_auth": basic_auth_session,
    "expired": expired_session,
    "csrf_protected": csrf_protected_session,
}


def get_all_mock_sessions() -> list:
    """Get one instance of every mock session."""
    sessions = [fn() for fn in MOCK_SESSIONS.values()]
    sessions.extend(multi_org_sessions())
    return sessions


def get_mock_session(name: str) -> AuthSession:
    """Get a specific mock session by name."""
    if name == "multi_org":
        return multi_org_sessions()[0]
    fn = MOCK_SESSIONS.get(name)
    if fn:
        return fn()
    raise ValueError(f"Unknown mock session: {name}. Available: {list(MOCK_SESSIONS.keys())}")
