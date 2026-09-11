"""Auth Tool — login, session management, authentication state.

Provides the researcher with the ability to:
1. Log in to applications
2. Maintain session cookies/tokens
3. Test with multiple roles (admin, user, etc.)
4. Extract auth state from browser sessions
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass
class AuthSession:
    """An authenticated session to a target."""
    label: str
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    token: str | None = None
    token_type: str = "Bearer"
    target_domain: str = ""
    logged_in_at: float = field(default_factory=time.time)

    def get_auth_headers(self) -> dict[str, str]:
        headers = dict(self.headers)
        if self.token:
            headers["Authorization"] = f"{self.token_type} {self.token}"
        return headers

    def get_auth_cookies(self) -> dict[str, str]:
        return dict(self.cookies)

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "cookies": self.cookies,
            "headers": self.headers,
            "token": self.token,
            "token_type": self.token_type,
            "target_domain": self.target_domain,
            "logged_in_at": self.logged_in_at,
        }


class AuthManager:
    """Manages authentication sessions for the researcher.

    Supports:
    - Cookie-based sessions (most web apps)
    - Token-based sessions (JWT, API keys)
    - Multi-role testing (admin, regular user, etc.)
    - Session extraction from browser
    - Login via HTTP POST with credentials
    """

    def __init__(self):
        self.sessions: dict[str, AuthSession] = {}
        self.active_session: str | None = None
        self._credentials: list[dict[str, str]] = []  # Stored login credentials

    def create_session(
        self,
        label: str,
        cookies: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        token: str | None = None,
        token_type: str = "Bearer",
        target_domain: str = "",
    ) -> AuthSession:
        """Create a new auth session."""
        session = AuthSession(
            label=label,
            cookies=cookies or {},
            headers=headers or {},
            token=token,
            token_type=token_type,
            target_domain=target_domain,
        )
        self.sessions[label] = session
        if self.active_session is None:
            self.active_session = label
        return session

    def set_active(self, label: str):
        """Switch the active session."""
        if label not in self.sessions:
            raise ValueError(f"Session '{label}' not found")
        self.active_session = label

    def get_active(self) -> AuthSession | None:
        """Get the currently active session."""
        if self.active_session and self.active_session in self.sessions:
            return self.sessions[self.active_session]
        return None

    def import_cookies(self, label: str, cookies: list[dict], target_domain: str = ""):
        """Import cookies from browser format to session format."""
        cookie_dict = {}
        for c in cookies:
            if target_domain and target_domain not in c.get("domain", ""):
                continue
            cookie_dict[c["name"]] = c["value"]
        return self.create_session(label, cookies=cookie_dict, target_domain=target_domain)

    def apply_to_request(self, session_label: str, headers: dict, cookies: dict) -> tuple[dict, dict]:
        """Apply auth state to a request's headers and cookies."""
        session = self.sessions.get(session_label)
        if not session:
            return headers, cookies

        merged_headers = {**headers, **session.get_auth_headers()}
        merged_cookies = {**cookies, **session.get_auth_cookies()}
        return merged_headers, merged_cookies

    def get_session_labels(self) -> list[str]:
        """Get all session labels."""
        return list(self.sessions.keys())

    def add_credentials(self, label: str, login_url: str, method: str,
                        body: dict[str, str], headers: dict[str, str] | None = None,
                        token_path: str | None = None, role: str = "user"):
        """Store login credentials for later session creation."""
        self._credentials.append({
            "label": label,
            "login_url": login_url,
            "method": method,
            "body": body,
            "headers": headers or {},
            "token_path": token_path,
            "role": role,
        })

    def get_credentials(self) -> list[dict]:
        """Get all stored credentials."""
        return list(self._credentials)

    async def create_session_from_login(self, http_client, cred: dict) -> AuthSession | None:
        """Login via HTTP and create a session from the response."""
        try:
            resp = await http_client.request(
                method=cred.get("method", "POST"),
                url=cred["login_url"],
                headers=cred.get("headers", {}),
                json_data=cred.get("body"),
            )
            if resp.get("error") or resp.get("status_code", 0) >= 400:
                return None

            # Extract token from response if path specified
            token = None
            token_path = cred.get("token_path")
            if token_path and resp.get("body"):
                try:
                    data = json.loads(resp["body"])
                    for key in token_path.split("."):
                        data = data.get(key, {})
                    token = data if isinstance(data, str) else json.dumps(data)
                except (json.JSONDecodeError, TypeError, AttributeError):
                    pass

            # Extract cookies from response headers
            cookies = {}
            for name, value in resp.get("headers", {}).items():
                if name.lower() == "set-cookie":
                    parts = value.split(";")[0].split("=", 1)
                    if len(parts) == 2:
                        cookies[parts[0].strip()] = parts[1].strip()

            return self.create_session(
                label=cred["label"],
                cookies=cookies,
                token=token,
                target_domain=cred.get("login_url", ""),
            )
        except Exception:
            return None

    async def create_all_sessions(self, http_client) -> dict[str, bool]:
        """Create sessions from all stored credentials. Returns {label: success}."""
        results = {}
        for cred in self._credentials:
            session = await self.create_session_from_login(http_client, cred)
            results[cred["label"]] = session is not None
        return results

    def rotate_sessions(self) -> list[str]:
        """Rotate through all sessions, returning labels in order."""
        labels = list(self.sessions.keys())
        if not labels:
            return []
        # Move active to end, return next
        if self.active_session in labels:
            idx = labels.index(self.active_session)
            labels = labels[idx + 1:] + labels[:idx + 1]
        return labels


