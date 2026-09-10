"""
authcore — Authenticated Testing Foundation Layer for Demogorgon.

Milestones M1-M10: Complete authenticated vulnerability hunting architecture.

Modules:
    session         — AuthSession dataclass, UserRole, AuthType, containers
    store           — AuthSessionStore, multi-account management, persistence
    auth_client     — AuthAwareClient, HTTP client with auth injection
    object_inventory — ObjectInventoryDB, SQLite object tracking for IDOR
    idor_tester     — CrossUserIDORTester, systematic cross-user IDOR testing
    boundary_tester — AccountBoundaryTester, horizontal/vertical boundary tests
    role_tester     — RoleTester, RBAC testing with role matrix
    graphql_tester  — GraphQLAuthTester, introspection/mutation/field auth
    multi_org_tester — MultiOrgTester, cross-tenant IDOR detection

Usage:
    from authcore import AuthSession, UserRole, AuthType
    from authcore import AuthSessionStore
    from authcore import ObjectInventoryDB
    from authcore import CrossUserIDORTester
    from authcore import AccountBoundaryTester
    from authcore import RoleTester
    from authcore import GraphQLAuthTester
    from authcore import MultiOrgTester
"""

from demogorgon.auth.authcore.session import (
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
from demogorgon.auth.authcore.store import AuthSessionStore
from demogorgon.auth.authcore.auth_client import AuthAwareClient
from demogorgon.auth.authcore.object_inventory import ObjectInventoryDB
from demogorgon.auth.authcore.idor_tester import CrossUserIDORTester
from demogorgon.auth.authcore.boundary_tester import AccountBoundaryTester
from demogorgon.auth.authcore.role_tester import RoleTester
from demogorgon.auth.authcore.graphql_tester import GraphQLAuthTester
from demogorgon.auth.authcore.multi_org_tester import MultiOrgTester

__all__ = [
    # M1: Core primitives
    "AuthSession",
    "UserRole",
    "AuthType",
    "CookieJar",
    "HeaderSet",
    "JWTToken",
    "CSRFToken",
    "AccountMeta",
    "OrgMeta",
    "ScopeMeta",
    # M1: Session store
    "AuthSessionStore",
    # M3+M4: Auth-aware HTTP client
    "AuthAwareClient",
    # M5: Object inventory
    "ObjectInventoryDB",
    # M6: Cross-user IDOR
    "CrossUserIDORTester",
    # M7: Account boundary
    "AccountBoundaryTester",
    # M8: RBAC testing
    "RoleTester",
    # M9: GraphQL testing
    "GraphQLAuthTester",
    # M10: Multi-org testing
    "MultiOrgTester",
]

__version__ = "1.1.0"
