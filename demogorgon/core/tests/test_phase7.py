"""Tests for Phase 7: Auth + HITL."""

from __future__ import annotations

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock

from demogorgon.core.auth.session import AuthSession, AuthType, AuthStatus
from demogorgon.core.auth.manager import AuthManager
from demogorgon.core.auth.strategies import (
    ApiKeyStrategy,
    BearerTokenStrategy,
    CookieStrategy,
    BasicAuthStrategy,
    OAuthStrategy,
)
from demogorgon.core.hitl.gate import HITLGate, ApprovalLevel
from demogorgon.core.hitl.request import ApprovalRequest, RequestStatus, RequestPriority
from demogorgon.core.hitl.controller import PauseController, PauseReason


def run_async(coro):
    """Run an async function synchronously for testing."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ── AuthSession tests ──────────────────────────────────────────

class TestAuthSession:
    def test_create_api_key(self):
        session = AuthSession(
            name="test_api_key",
            auth_type=AuthType.API_KEY,
            credentials={"key": "sk-123", "header": "X-API-Key"},
        )
        assert session.is_valid()
        headers = session.get_header_injection()
        assert headers["X-API-Key"] == "sk-123"

    def test_create_bearer_token(self):
        session = AuthSession(
            name="test_token",
            auth_type=AuthType.BEARER_TOKEN,
            credentials={"token": "eyJhbGciOi..."},
        )
        headers = session.get_header_injection()
        assert headers["Authorization"] == "Bearer eyJhbGciOi..."

    def test_create_basic_auth(self):
        session = AuthSession(
            name="test_basic",
            auth_type=AuthType.BASIC_AUTH,
            credentials={"username": "admin", "password": "secret"},
        )
        headers = session.get_header_injection()
        assert "Authorization" in headers
        assert headers["Authorization"].startswith("Basic ")

    def test_create_cookie(self):
        session = AuthSession(
            name="test_cookie",
            auth_type=AuthType.COOKIE,
            credentials={"cookies": "session_id=abc123; token=xyz"},
        )
        headers = session.get_header_injection()
        assert "Cookie" in headers
        cookies = session.get_cookie_dict()
        assert cookies["session_id"] == "abc123"
        assert cookies["token"] == "xyz"

    def test_create_custom_headers(self):
        session = AuthSession(
            name="test_custom",
            auth_type=AuthType.CUSTOM_HEADERS,
            credentials={"headers": {"X-Custom": "value"}},
        )
        headers = session.get_header_injection()
        assert headers["X-Custom"] == "value"

    def test_is_valid_expired(self):
        import time
        session = AuthSession(
            name="expired",
            auth_type=AuthType.API_KEY,
            credentials={"key": "key"},
            expires_at=time.time() - 10,
        )
        assert not session.is_valid()
        assert session.status == AuthStatus.EXPIRED

    def test_scopes(self):
        session = AuthSession(
            name="scoped",
            auth_type=AuthType.API_KEY,
            credentials={"key": "key"},
            scopes=["read", "write"],
        )
        assert session.has_scope("read")
        assert session.has_scope("write")
        assert not session.has_scope("admin")

    def test_scopes_empty_any_scope(self):
        session = AuthSession(
            name="no_scopes",
            auth_type=AuthType.API_KEY,
            credentials={"key": "key"},
        )
        assert session.has_scope("anything")

    def test_roundtrip(self):
        session = AuthSession(
            name="test",
            auth_type=AuthType.API_KEY,
            credentials={"key": "k"},
            scopes=["read"],
        )
        d = session.to_dict()
        restored = AuthSession.from_dict(d)
        assert restored.name == "test"
        assert restored.auth_type == AuthType.API_KEY
        assert restored.credentials["key"] == "k"


# ── AuthStrategy tests ─────────────────────────────────────────

class TestAuthStrategies:
    def test_api_key_strategy(self):
        strategy = ApiKeyStrategy()
        session = strategy.create_session(
            {"key": "test-key", "header": "X-Auth"},
            name="my_api_key",
        )
        assert session.auth_type == AuthType.API_KEY
        assert session.credentials["key"] == "test-key"
        assert session.credentials["header"] == "X-Auth"

    def test_bearer_strategy(self):
        strategy = BearerTokenStrategy()
        session = strategy.create_session({"token": "tok"})
        assert session.auth_type == AuthType.BEARER_TOKEN
        assert session.credentials["token"] == "tok"

    def test_cookie_strategy(self):
        strategy = CookieStrategy()
        session = strategy.create_session({"cookies": "a=1;b=2"})
        assert session.auth_type == AuthType.COOKIE

    def test_basic_strategy(self):
        strategy = BasicAuthStrategy()
        session = strategy.create_session({"username": "u", "password": "p"})
        assert session.credentials["username"] == "u"

    def test_oauth_strategy(self):
        strategy = OAuthStrategy()
        session = strategy.create_session({"access_token": "at", "refresh_token": "rt"})
        assert session.auth_type == AuthType.OAUTH2

    def test_validate_empty_api_key(self):
        strategy = ApiKeyStrategy()
        session = strategy.create_session({"key": ""})
        is_valid = run_async(strategy.validate(session, None))
        assert not is_valid
        assert session.status == AuthStatus.INVALID

    def test_validate_valid_api_key(self):
        strategy = ApiKeyStrategy()
        session = strategy.create_session({"key": "valid"})
        is_valid = run_async(strategy.validate(session, None))
        assert is_valid


# ── AuthManager tests ──────────────────────────────────────────

class TestAuthManager:
    def test_create_and_get(self):
        manager = AuthManager()
        sid = manager.create_session(
            AuthType.API_KEY,
            {"key": "test-key"},
            name="test_key",
        )
        session = manager.get_session(sid)
        assert session is not None
        assert session.name == "test_key"

    def test_add_session(self):
        manager = AuthManager()
        session = AuthSession(
            name="custom",
            auth_type=AuthType.BEARER_TOKEN,
            credentials={"token": "t"},
        )
        sid = manager.add_session(session)
        assert manager.get_session(sid) is not None

    def test_remove_session(self):
        manager = AuthManager()
        sid = manager.create_session(AuthType.API_KEY, {"key": "k"})
        assert manager.remove_session(sid)
        assert manager.get_session(sid) is None
        assert not manager.remove_session("nonexistent")

    def test_get_active_sessions(self):
        manager = AuthManager()
        manager.create_session(AuthType.API_KEY, {"key": "k1"})
        manager.create_session(AuthType.API_KEY, {"key": "k2"})
        assert len(manager.get_active_sessions()) == 2

    def test_get_auth_injection(self):
        manager = AuthManager()
        manager.create_session(AuthType.API_KEY, {"key": "k"}, name="key1")
        manager.create_session(AuthType.BEARER_TOKEN, {"token": "t"}, name="token1")
        injection = manager.get_auth_injection()
        assert "X-API-Key" in injection["headers"]
        assert "Authorization" in injection["headers"]

    def test_get_auth_injection_with_scopes(self):
        manager = AuthManager()
        manager.create_session(
            AuthType.API_KEY,
            {"key": "k"},
            scopes=["read"],
        )
        manager.create_session(
            AuthType.BEARER_TOKEN,
            {"token": "t"},
            scopes=["admin"],
        )
        injection = manager.get_auth_injection(scopes=["read"])
        assert "X-API-Key" in injection["headers"]
        assert "Authorization" not in injection["headers"]

    def test_save_load_roundtrip(self, tmp_path):
        manager = AuthManager()
        manager.create_session(AuthType.API_KEY, {"key": "k"}, name="test")
        path = str(tmp_path / "auth.json")
        manager.save(path)

        manager2 = AuthManager()
        manager2.load(path)
        assert len(manager2.get_active_sessions()) == 1

    def test_summary(self):
        manager = AuthManager()
        manager.create_session(AuthType.API_KEY, {"key": "k"})
        summary = manager.get_summary()
        assert summary["total_sessions"] == 1
        assert summary["active_sessions"] == 1

    def test_validate_all(self):
        manager = AuthManager()
        manager.create_session(AuthType.API_KEY, {"key": "k"})
        results = run_async(manager.validate_all())
        assert len(results) == 1
        assert list(results.values())[0] is True


# ── HITLGate tests ─────────────────────────────────────────────

class TestHITLGate:
    def test_default_safe_actions_pass(self):
        gate = HITLGate(approval_level=ApprovalLevel.REQUIRED)
        assert gate.should_allow("observe")
        assert gate.should_allow("scan")
        assert gate.should_allow("recon")

    def test_exploit_blocked(self):
        gate = HITLGate(approval_level=ApprovalLevel.REQUIRED)
        assert not gate.should_allow("exploit")
        assert not gate.should_allow("ssrf")
        assert not gate.should_allow("xss_injection")

    def test_requires_approval_exploit(self):
        gate = HITLGate(approval_level=ApprovalLevel.REQUIRED)
        needs, reason = gate.requires_approval("exploit")
        assert needs is True

    def test_requires_approval_recon(self):
        gate = HITLGate(approval_level=ApprovalLevel.REQUIRED)
        needs, reason = gate.requires_approval("scan")
        assert needs is False

    def test_autonomous_mode(self):
        gate = HITLGate(approval_level=ApprovalLevel.NONE)
        needs, reason = gate.requires_approval("exploit")
        assert needs is False

    def test_exclusive_mode(self):
        gate = HITLGate(approval_level=ApprovalLevel.EXCLUSIVE)
        needs, reason = gate.requires_approval("scan")
        assert needs is True

    def test_custom_blocked_actions(self):
        gate = HITLGate(
            approval_level=ApprovalLevel.REQUIRED,
            blocked_actions={"internal_tool", "dangerous_action"},
        )
        assert not gate.should_allow("internal_tool")
        assert not gate.should_allow("dangerous_action")

    def test_request_approval_fast_track(self):
        gate = HITLGate(approval_level=ApprovalLevel.NONE)
        req = run_async(
            gate.request_approval("scan", "https://example.com", "Scan target")
        )
        assert req.is_approved()

    def test_request_approval_blocked(self):
        gate = HITLGate(
            approval_level=ApprovalLevel.REQUIRED,
            blocked_actions={"exploit"},
        )
        req = run_async(
            gate.request_approval("exploit", "https://example.com", "Exploit target")
        )
        assert req.status == RequestStatus.DENIED

    def test_request_approval_queued(self):
        gate = HITLGate(approval_level=ApprovalLevel.REQUIRED)
        req = run_async(
            gate.request_approval("sql_injection", "https://api.test", "SQLi test")
        )
        assert req.is_pending()
        assert len(gate.pending_requests) == 1

    def test_approve_deny_pending(self):
        gate = HITLGate(approval_level=ApprovalLevel.REQUIRED)
        req = run_async(
            gate.request_approval("sql_injection", "https://api.test", "SQLi test")
        )
        assert gate.approve_request(req.id, notes="Approved for testing")
        assert req.is_approved()

    def test_deny_pending(self):
        gate = HITLGate(approval_level=ApprovalLevel.REQUIRED)
        req = run_async(
            gate.request_approval("sql_injection", "https://api.test", "SQLi test")
        )
        assert gate.deny_request(req.id, reason="Too risky")
        assert req.status == RequestStatus.DENIED

    def test_callback_approval(self):
        gate = HITLGate(approval_level=ApprovalLevel.REQUIRED)

        async def auto_approve(request):
            request.approve("Auto-approved by callback")
            return request

        gate.set_approval_callback(auto_approve)
        req = run_async(
            gate.request_approval("sql_injection", "https://api.test", "SQLi test")
        )
        assert req.is_approved()
        assert req.notes == "Auto-approved by callback"

    def test_stats(self):
        gate = HITLGate(approval_level=ApprovalLevel.REQUIRED)
        stats = gate.get_stats()
        assert stats["approval_level"] == "required"
        assert stats["pending_count"] == 0


# ── PauseController tests ─────────────────────────────────────

class TestPauseController:
    def test_default_not_paused(self):
        controller = PauseController()
        assert not controller.is_paused

    def test_pause_resume(self):
        controller = PauseController()
        controller.pause(PauseReason.HUMAN_REQUEST, message="Need input")
        assert controller.is_paused
        assert controller.pause_reason == PauseReason.HUMAN_REQUEST
        assert controller.pause_message == "Need input"

        controller.resume()
        assert not controller.is_paused

    def test_pause_duration(self):
        controller = PauseController()
        import time
        controller.pause_timestamp = time.time() - 5
        controller.is_paused = True
        controller.pause_reason = PauseReason.RATE_LIMIT
        duration = controller.get_pause_duration()
        assert duration is not None
        assert duration >= 4.5

    def test_not_paused_duration(self):
        controller = PauseController()
        assert controller.get_pause_duration() is None

    def test_history(self):
        controller = PauseController()
        controller.pause(PauseReason.HUMAN_REQUEST)
        controller.resume()
        controller.pause(PauseReason.CHECKPOINT)
        controller.resume()
        history = controller.get_history()
        assert len(history) == 2
        assert history[0]["reason"] == "human_request"

    def test_summary(self):
        controller = PauseController()
        summary = controller.get_summary()
        assert summary["is_paused"] is False
        assert summary["history_count"] == 0


# ── Integration tests ──────────────────────────────────────────

class TestPhase7Integration:
    def test_auth_with_executor_flow(self):
        """Test auth flow with PlanExecutor integration."""
        manager = AuthManager()
        manager.create_session(
            AuthType.BEARER_TOKEN,
            {"token": "test-token"},
            name="api_auth",
        )
        injection = manager.get_auth_injection()
        assert "Authorization" in injection["headers"]
        assert injection["headers"]["Authorization"] == "Bearer test-token"

    def test_hitl_gate_with_loop_flow(self):
        """Test HITL gate integration with research loop."""
        gate = HITLGate(approval_level=ApprovalLevel.REQUIRED)

        # Safe action should pass
        req = run_async(
            gate.request_approval("scan", "https://example.com", "Port scan")
        )
        assert req.is_approved()

        # Dangerous action should be queued
        req = run_async(
            gate.request_approval("sql_injection", "https://api.test", "SQLi test")
        )
        assert req.is_pending()

        # Approve it
        assert gate.approve_request(req.id, notes="Approved")
        assert req.is_approved()

    def test_pause_resume_during_research(self):
        """Test pause/resume during research."""
        controller = PauseController()

        # Simulate research loop
        for _ in range(3):
            if not controller.is_paused:
                pass  # Do work

        controller.pause(PauseReason.HUMAN_REQUEST, "Review findings")
        assert controller.is_paused

        controller.resume()
        assert not controller.is_paused
        assert len(controller.get_history()) == 1
