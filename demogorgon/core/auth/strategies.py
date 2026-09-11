"""Auth strategies — pluggable authentication methods.

Each strategy knows how to inject its auth into HTTP requests
and how to validate that the auth is still working.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

from .session import AuthSession, AuthType, AuthStatus

logger = logging.getLogger(__name__)


class AuthStrategy(ABC):
    """Base class for authentication strategies."""

    @abstractmethod
    def create_session(self, credentials: dict[str, Any], **kwargs) -> AuthSession:
        """Create an AuthSession from raw credentials."""

    @abstractmethod
    async def validate(self, session: AuthSession, http_client: Any) -> bool:
        """Validate that the auth session is still working."""

    @staticmethod
    def _make_session(
        name: str,
        auth_type: AuthType,
        credentials: dict[str, Any],
        scopes: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuthSession:
        return AuthSession(
            name=name,
            auth_type=auth_type,
            credentials=credentials,
            scopes=scopes or [],
            metadata=metadata or {},
        )


class ApiKeyStrategy(AuthStrategy):
    """API key authentication (header-based)."""

    def create_session(self, credentials: dict[str, Any], **kwargs) -> AuthSession:
        name = kwargs.pop("name", "api_key")
        return self._make_session(
            name=name,
            auth_type=AuthType.API_KEY,
            credentials={
                "key": credentials.get("key", ""),
                "header": credentials.get("header", "X-API-Key"),
            },
            scopes=kwargs.pop("scopes", None),
            metadata=kwargs.pop("metadata", None),
        )

    async def validate(self, session: AuthSession, http_client: Any) -> bool:
        """Validate by checking if the key is non-empty and status is active."""
        key = session.credentials.get("key", "")
        if not key:
            session.status = AuthStatus.INVALID
            return False
        return session.is_valid()


class BearerTokenStrategy(AuthStrategy):
    """Bearer token authentication (JWT, OAuth tokens, etc.)."""

    def create_session(self, credentials: dict[str, Any], **kwargs) -> AuthSession:
        name = kwargs.pop("name", "bearer_token")
        return self._make_session(
            name=name,
            auth_type=AuthType.BEARER_TOKEN,
            credentials={"token": credentials.get("token", "")},
            scopes=kwargs.pop("scopes", None),
            metadata=kwargs.pop("metadata", None),
        )

    async def validate(self, session: AuthSession, http_client: Any) -> bool:
        """Validate by checking if the token is non-empty."""
        token = session.credentials.get("token", "")
        if not token:
            session.status = AuthStatus.INVALID
            return False
        return session.is_valid()


class CookieStrategy(AuthStrategy):
    """Cookie-based authentication."""

    def create_session(self, credentials: dict[str, Any], **kwargs) -> AuthSession:
        name = kwargs.pop("name", "cookie")
        return self._make_session(
            name=name,
            auth_type=AuthType.COOKIE,
            credentials={"cookies": credentials.get("cookies", "")},
            scopes=kwargs.pop("scopes", None),
            metadata=kwargs.pop("metadata", None),
        )

    async def validate(self, session: AuthSession, http_client: Any) -> bool:
        """Validate by making a request to the target and checking response."""
        cookie_str = session.credentials.get("cookies", "")
        if not cookie_str:
            session.status = AuthStatus.INVALID
            return False

        if http_client is None:
            return session.is_valid()

        try:
            target_url = kwargs.get("validate_url", "")
            if not target_url:
                return session.is_valid()

            headers = session.get_header_injection()
            resp = await http_client.get(target_url, headers=headers)
            if resp.status_code == 401:
                session.status = AuthStatus.EXPIRED
                return False
            return True
        except Exception as e:
            logger.warning(f"Cookie validation failed: {e}")
            return session.is_valid()


class BasicAuthStrategy(AuthStrategy):
    """HTTP Basic authentication."""

    def create_session(self, credentials: dict[str, Any], **kwargs) -> AuthSession:
        name = kwargs.pop("name", "basic_auth")
        return self._make_session(
            name=name,
            auth_type=AuthType.BASIC_AUTH,
            credentials={
                "username": credentials.get("username", ""),
                "password": credentials.get("password", ""),
            },
            scopes=kwargs.pop("scopes", None),
            metadata=kwargs.pop("metadata", None),
        )

    async def validate(self, session: AuthSession, http_client: Any) -> bool:
        """Validate by checking credentials are present."""
        username = session.credentials.get("username", "")
        if not username:
            session.status = AuthStatus.INVALID
            return False
        return session.is_valid()


class OAuthStrategy(AuthStrategy):
    """OAuth2 authentication."""

    def create_session(self, credentials: dict[str, Any], **kwargs) -> AuthSession:
        name = kwargs.pop("name", "oauth2")
        return self._make_session(
            name=name,
            auth_type=AuthType.OAUTH2,
            credentials={
                "access_token": credentials.get("access_token", ""),
                "refresh_token": credentials.get("refresh_token", ""),
                "token_endpoint": credentials.get("token_endpoint", ""),
                "client_id": credentials.get("client_id", ""),
                "client_secret": credentials.get("client_secret", ""),
            },
            scopes=kwargs.pop("scopes", None),
            metadata=kwargs.pop("metadata", None),
        )

    async def validate(self, session: AuthSession, http_client: Any) -> bool:
        """Validate by checking if access token is present."""
        token = session.credentials.get("access_token", "")
        if not token:
            session.status = AuthStatus.INVALID
            return False
        return session.is_valid()
