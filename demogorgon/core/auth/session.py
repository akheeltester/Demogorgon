"""AuthSession — holds credentials for a single authentication method."""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AuthType(Enum):
    """Supported authentication types."""
    API_KEY = "api_key"
    BEARER_TOKEN = "bearer_token"
    COOKIE = "cookie"
    BASIC_AUTH = "basic_auth"
    OAUTH2 = "oauth2"
    CUSTOM_HEADERS = "custom_headers"


class AuthStatus(Enum):
    """Current status of an auth session."""
    ACTIVE = "active"
    EXPIRED = "expired"
    INVALID = "invalid"
    UNKNOWN = "unknown"


@dataclass
class AuthSession:
    """Holds credentials and metadata for a single authentication method.

    Attributes:
        id: Unique identifier for this auth session
        name: Human-readable name (e.g., "admin_api_key")
        auth_type: The authentication method
        credentials: The actual credentials (API key, token, cookies, etc.)
        scopes: Required OAuth scopes or access levels
        created_at: When this session was created
        expires_at: When this session expires (None = never)
        status: Current status
        metadata: Additional context (user_id, role, etc.)
    """
    id: str = field(default_factory=lambda: secrets.token_hex(8))
    name: str = ""
    auth_type: AuthType = AuthType.API_KEY
    credentials: dict[str, Any] = field(default_factory=dict)
    scopes: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    expires_at: float | None = None
    status: AuthStatus = AuthStatus.ACTIVE
    metadata: dict[str, Any] = field(default_factory=dict)

    def is_valid(self) -> bool:
        """Check if this auth session is currently valid."""
        if self.status != AuthStatus.ACTIVE:
            return False
        if self.expires_at is not None and time.time() > self.expires_at:
            self.status = AuthStatus.EXPIRED
            return False
        return True

    def has_scope(self, scope: str) -> bool:
        """Check if this session has a specific scope."""
        if not self.scopes:
            return True
        return scope in self.scopes

    def get_header_injection(self) -> dict[str, str]:
        """Get headers to inject into HTTP requests."""
        headers: dict[str, str] = {}

        if self.auth_type == AuthType.API_KEY:
            key = self.credentials.get("key", "")
            header_name = self.credentials.get("header", "X-API-Key")
            if key:
                headers[header_name] = key

        elif self.auth_type == AuthType.BEARER_TOKEN:
            token = self.credentials.get("token", "")
            if token:
                headers["Authorization"] = f"Bearer {token}"

        elif self.auth_type == AuthType.BASIC_AUTH:
            import base64
            username = self.credentials.get("username", "")
            password = self.credentials.get("password", "")
            if username:
                encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
                headers["Authorization"] = f"Basic {encoded}"

        elif self.auth_type == AuthType.COOKIE:
            cookies_str = self.credentials.get("cookies", "")
            if cookies_str:
                headers["Cookie"] = cookies_str

        elif self.auth_type == AuthType.CUSTOM_HEADERS:
            custom = self.credentials.get("headers", {})
            headers.update(custom)

        return headers

    def get_cookie_dict(self) -> dict[str, str]:
        """Get cookies as a dictionary for httpx."""
        if self.auth_type != AuthType.COOKIE:
            return {}

        cookies: dict[str, str] = {}
        cookie_str = self.credentials.get("cookies", "")
        if cookie_str:
            for pair in cookie_str.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    cookies[k.strip()] = v.strip()

        return cookies

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "auth_type": self.auth_type.value,
            "credentials": self.credentials,
            "scopes": self.scopes,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "status": self.status.value,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuthSession:
        """Deserialize from dictionary."""
        return cls(
            id=data.get("id", ""),
            name=data.get("name", ""),
            auth_type=AuthType(data.get("auth_type", "api_key")),
            credentials=data.get("credentials", {}),
            scopes=data.get("scopes", []),
            created_at=data.get("created_at", 0),
            expires_at=data.get("expires_at"),
            status=AuthStatus(data.get("status", "active")),
            metadata=data.get("metadata", {}),
        )
