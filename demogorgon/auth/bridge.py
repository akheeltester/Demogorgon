"""Auth Bridge — bridges authcore into the researcher.

Wraps AuthSessionStore + AuthAwareClient to provide AuthManager-compatible API.
"""

from __future__ import annotations

import logging
from typing import Any, Optional
from urllib.parse import urlparse

from demogorgon.auth.authcore.session import AuthSession, UserRole, AuthType, CookieJar, HeaderSet
from demogorgon.auth.authcore.store import AuthSessionStore

logger = logging.getLogger("demogorgon.auth_bridge")


class AuthManager:
    """AuthManager-compatible interface backed by authcore."""

    def __init__(self, target_domain: str = "", db_path: str | None = None):
        self.target_domain = target_domain
        self.store = AuthSessionStore(db_path=db_path)
        self.active_label: str = ""
        self.sessions: dict[str, AuthSession] = {}

    def create_session(
        self,
        label: str,
        cookies: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        token: str | None = None,
        role: str = "user",
        user_id: str = "",
        username: str = "",
        org_id: str = "",
    ) -> AuthSession:
        domain = self.target_domain
        if not domain:
            from urllib.parse import urlparse as _parse
            # Try to extract from active or use placeholder
            domain = "unknown"

        cookie_jar = CookieJar()
        if cookies:
            for name, value in cookies.items():
                cookie_jar.set(name, value, domain=domain)

        header_set = HeaderSet()
        if headers:
            for name, value in headers.items():
                header_set.set(name, value)

        role_enum = UserRole.MEMBER
        try:
            role_enum = UserRole(role)
        except ValueError:
            pass

        session = AuthSession(
            label=label,
            role=role_enum,
            auth_type=AuthType.COOKIE if not token else AuthType.BEARER,
            target_domain=domain,
            cookies=cookie_jar,
            headers=header_set,
        )

        if token:
            from .authcore.session import JWTToken
            session.jwt = JWTToken(token=token, token_type="Bearer")
            session.auth_type = AuthType.BEARER

        if user_id:
            session.account.user_id = user_id
        if username:
            session.account.username = username
        if org_id:
            session.org.org_id = org_id

        self.store.add_session(session)
        self.sessions[label] = session
        if not self.active_label:
            self.active_label = label
        return session

    def import_cookies(
        self,
        label: str,
        cookies: list[dict[str, Any]],
        domain: str,
        role: str = "user",
        user_id: str = "",
    ) -> AuthSession:
        cookie_jar = CookieJar()
        for c in cookies:
            cookie_jar.set(
                c.get("name", ""),
                c.get("value", ""),
                domain=c.get("domain", domain),
                path=c.get("path", "/"),
            )

        role_enum = UserRole.MEMBER
        try:
            role_enum = UserRole(role)
        except ValueError:
            pass

        session = AuthSession(
            label=label,
            role=role_enum,
            auth_type=AuthType.COOKIE,
            target_domain=domain,
            cookies=cookie_jar,
        )
        if user_id:
            session.account.user_id = user_id

        self.store.add_session(session)
        self.sessions[label] = session
        if not self.active_label:
            self.active_label = label
        return session

    def set_active(self, label: str) -> None:
        if label in self.sessions:
            self.active_label = label

    def get_active(self) -> AuthSession | None:
        return self.sessions.get(self.active_label)

    def get_session_labels(self) -> list[str]:
        return list(self.sessions.keys())

    def apply_to_request(
        self,
        label: str,
        headers: dict[str, str],
        body: Any,
    ) -> tuple[dict[str, str], Any]:
        session = self.sessions.get(label)
        if not session:
            return headers, body

        merged = dict(headers)
        auth_headers = session.build_request_headers()
        merged.update(auth_headers)

        cookie_dict = session.cookies.cookies if session.cookies else {}
        if cookie_dict:
            cookie_str = "; ".join(f"{k}={v}" for k, v in cookie_dict.items())
            merged["Cookie"] = cookie_str

        return merged, body

    def health_check(self, url: str | None = None) -> dict[str, Any]:
        results = {}
        for label, session in self.sessions.items():
            check_url = url or f"https://{session.target_domain}/"
            try:
                import httpx
                h = session.build_request_headers()
                resp = httpx.get(check_url, headers=h, timeout=10, verify=False, follow_redirects=True)
                session.mark_validated(resp.status_code)
                results[label] = {"valid": session.is_valid, "status": resp.status_code}
            except Exception as e:
                results[label] = {"valid": False, "error": str(e)}
        return results

    def to_summary(self) -> dict[str, Any]:
        return self.store.to_summary()
