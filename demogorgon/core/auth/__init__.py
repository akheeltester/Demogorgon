"""Auth — authentication management for engagements.

Components:
- AuthSession: Holds credentials for a single authentication method
- AuthManager: Manages multiple auth sessions, provides auth injection
- AuthStrategy: Pluggable auth strategies (API key, cookie, bearer, OAuth)
"""

from .session import AuthSession, AuthType, AuthStatus
from .manager import AuthManager
from .strategies import (
    AuthStrategy,
    ApiKeyStrategy,
    BearerTokenStrategy,
    CookieStrategy,
    BasicAuthStrategy,
    OAuthStrategy,
)

__all__ = [
    "AuthSession",
    "AuthType",
    "AuthStatus",
    "AuthManager",
    "AuthStrategy",
    "ApiKeyStrategy",
    "BearerTokenStrategy",
    "CookieStrategy",
    "BasicAuthStrategy",
    "OAuthStrategy",
]
