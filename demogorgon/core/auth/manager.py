"""AuthManager — manages authentication sessions for engagements."""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from .session import AuthSession, AuthType, AuthStatus
from .strategies import (
    AuthStrategy,
    ApiKeyStrategy,
    BearerTokenStrategy,
    CookieStrategy,
    BasicAuthStrategy,
    OAuthStrategy,
)

logger = logging.getLogger(__name__)

STRATEGY_MAP: dict[AuthType, AuthStrategy] = {
    AuthType.API_KEY: ApiKeyStrategy(),
    AuthType.BEARER_TOKEN: BearerTokenStrategy(),
    AuthType.COOKIE: CookieStrategy(),
    AuthType.BASIC_AUTH: BasicAuthStrategy(),
    AuthType.OAUTH2: OAuthStrategy(),
}


class AuthManager:
    """Manages multiple authentication sessions.

    Provides methods to:
    - Register credentials using strategy pattern
    - Get auth injection for HTTP requests
    - Validate sessions are still working
    - Save/load sessions to disk
    """

    def __init__(self, workspace_dir: str = ""):
        self._sessions: dict[str, AuthSession] = {}
        self._strategies: dict[AuthType, AuthStrategy] = dict(STRATEGY_MAP)
        self._workspace_dir = workspace_dir

    def register_strategy(self, auth_type: AuthType, strategy: AuthStrategy) -> None:
        """Register a custom auth strategy."""
        self._strategies[auth_type] = strategy

    def add_session(self, session: AuthSession) -> str:
        """Add a pre-built auth session. Returns the session ID."""
        self._sessions[session.id] = session
        logger.info(f"Registered auth session: {session.name} ({session.auth_type.value})")
        return session.id

    def create_session(
        self,
        auth_type: AuthType,
        credentials: dict[str, Any],
        **kwargs,
    ) -> str:
        """Create and register an auth session from raw credentials."""
        strategy = self._strategies.get(auth_type)
        if not strategy:
            raise ValueError(f"No strategy registered for auth type: {auth_type}")

        session = strategy.create_session(credentials, **kwargs)
        self._sessions[session.id] = session
        logger.info(f"Created auth session: {session.name} ({auth_type.value})")
        return session.id

    def get_session(self, session_id: str) -> AuthSession | None:
        """Get an auth session by ID."""
        return self._sessions.get(session_id)

    def get_active_sessions(self) -> list[AuthSession]:
        """Get all currently valid auth sessions."""
        return [s for s in self._sessions.values() if s.is_valid()]

    def remove_session(self, session_id: str) -> bool:
        """Remove an auth session. Returns True if it existed."""
        if session_id in self._sessions:
            del self._sessions[session_id]
            return True
        return False

    async def validate_all(self, http_client: Any = None) -> dict[str, bool]:
        """Validate all sessions. Returns {session_id: is_valid}."""
        results: dict[str, bool] = {}
        for sid, session in self._sessions.items():
            strategy = self._strategies.get(session.auth_type)
            if strategy:
                try:
                    is_valid = await strategy.validate(session, http_client)
                    results[sid] = is_valid
                except Exception as e:
                    logger.error(f"Validation error for {sid}: {e}")
                    results[sid] = False
            else:
                results[sid] = session.is_valid()
        return results

    def get_auth_injection(self, scopes: list[str] | None = None) -> dict[str, Any]:
        """Get combined auth headers/cookies for all valid sessions.

        Returns:
            {
                "headers": {"Authorization": "Bearer ...", "X-API-Key": "..."},
                "cookies": {"session_id": "..."}
            }
        """
        combined_headers: dict[str, str] = {}
        combined_cookies: dict[str, str] = {}

        for session in self.get_active_sessions():
            if scopes and not any(session.has_scope(s) for s in scopes):
                continue

            headers = session.get_header_injection()
            combined_headers.update(headers)

            cookies = session.get_cookie_dict()
            combined_cookies.update(cookies)

        return {
            "headers": combined_headers,
            "cookies": combined_cookies,
        }

    def save(self, path: str | None = None) -> None:
        """Save sessions to disk."""
        if not path:
            if not self._workspace_dir:
                return
            path = os.path.join(self._workspace_dir, "auth_sessions.json")

        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        data = [s.to_dict() for s in self._sessions.values()]
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    def load(self, path: str | None = None) -> None:
        """Load sessions from disk."""
        if not path:
            if not self._workspace_dir:
                return
            path = os.path.join(self._workspace_dir, "auth_sessions.json")

        if not os.path.exists(path):
            return

        with open(path) as f:
            data = json.load(f)

        for item in data:
            session = AuthSession.from_dict(item)
            self._sessions[session.id] = session

    def get_summary(self) -> dict[str, Any]:
        """Get a summary of auth state."""
        active = self.get_active_sessions()
        return {
            "total_sessions": len(self._sessions),
            "active_sessions": len(active),
            "session_types": {
                s.auth_type.value: sum(
                    1 for x in self._sessions.values()
                    if x.auth_type == s.auth_type
                )
                for s in active
            },
            "sessions": [
                {
                    "id": s.id,
                    "name": s.name,
                    "type": s.auth_type.value,
                    "status": s.status.value,
                }
                for s in self._sessions.values()
            ],
        }
