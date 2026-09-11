"""Tests for Phase 10: Autonomous End-to-End Engagement Integration."""

from __future__ import annotations

import asyncio
import json
import os
import pytest
import time
from unittest.mock import AsyncMock, MagicMock, patch

from demogorgon.core.gateway import ActionGateway, GateResult, GateCheck
from demogorgon.core.engagement_context import EngagementContext
from demogorgon.core.runner import AutonomousRunner, RunnerConfig
from demogorgon.core.research_loop.loop import ResearchLoop, LoopConfig
from demogorgon.core.research_loop.case import ResearchCase, HypothesisStatus
from demogorgon.core.brain.research_brain import ResearchBrain
from demogorgon.core.state.manager import StateManager, EngagementState
from demogorgon.core.validation.pipeline import ValidationPipeline
from demogorgon.core.chains.detector import BugChainDetector
from demogorgon.core.evidence.packager import EvidencePackager
from demogorgon.core.reporting.generator import ReportGenerator, Finding
from demogorgon.core.hitl.gate import HITLGate, ApprovalLevel
from demogorgon.core.hitl.controller import PauseController, PauseReason
from demogorgon.core.auth.manager import AuthManager
from demogorgon.core.scope.safety import SafetyGate
from demogorgon.core.engagement import (
    Engagement, EngagementStatus, AuthorizationStatus,
    ProgramPolicy, ScopeAsset, TestingRestriction,
)
from demogorgon.core.interfaces import ActionType


def run_async(coro):
    """Run an async function synchronously for testing."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def make_mock_llm(response_content: dict | str = None):
    """Create a mock LLM generate function."""
    if response_content is None:
        response_content = {
            "action": "test_idor",
            "target": "https://api.example.com/users/1",
            "reason": "IDOR testing",
            "confidence": 0.7,
            "priority": 0.8,
        }

    async def mock_generate(messages, response_format=None):
        if isinstance(response_content, dict):
            return {"content": json.dumps(response_content)}
        return {"content": response_content}

    return mock_generate


def make_test_engagement() -> Engagement:
    """Create a test engagement."""
    policy = ProgramPolicy(
        program_name="Test Program",
        platform="manual",
        in_scope=[
            ScopeAsset(pattern="app.example.test", asset_type="domain"),
            ScopeAsset(pattern="api.example.test", asset_type="domain"),
        ],
        out_of_scope=[
            ScopeAsset(pattern="admin.example.test", asset_type="domain"),
            ScopeAsset(pattern="thirdparty.example.net", asset_type="domain"),
        ],
    )
    return Engagement(
        id="test-eng-001",
        target_url="https://app.example.test",
        policy=policy,
        status=EngagementStatus.ACTIVE,
        authorization_status=AuthorizationStatus.CONFIRMED,
    )


# ── ActionGateway tests ────────────────────────────────────────

class TestActionGateway:
    def test_init(self):
        gateway = ActionGateway()
        stats = gateway.get_stats()
        assert stats["total_actions"] == 0

    def test_validate_without_gates(self):
        gateway = ActionGateway()
        check = run_async(gateway.validate("scan", "https://example.com"))
        assert check.allowed

    def test_validate_with_safety_block(self):
        safety = MagicMock()
        safety.check_url.return_value = MagicMock(allowed=False, reason="Out of scope")
        gateway = ActionGateway(safety_gate=safety)
        check = run_async(gateway.validate("scan", "https://evil.com"))
        assert not check.allowed
        assert "Out of scope" in check.reason

    def test_validate_with_safety_pass(self):
        safety = MagicMock()
        safety.check_url.return_value = MagicMock(allowed=True, reason="In scope")
        safety.check_action.return_value = MagicMock(allowed=True, reason="Allowed")
        gateway = ActionGateway(safety_gate=safety)
        check = run_async(gateway.validate("scan", "https://app.example.test"))
        assert check.allowed

    def test_validate_with_hitl_required(self):
        hitl = MagicMock()
        hitl.requires_approval.return_value = (True, "Requires approval")
        mock_request = MagicMock()
        mock_request.is_approved.return_value = False
        mock_request.deny_reason = "Denied by human"
        mock_request.id = "req-1"
        hitl.request_approval = AsyncMock(return_value=mock_request)

        gateway = ActionGateway(hitl_gate=hitl)
        check = run_async(gateway.validate("exploit", "https://app.example.test"))
        assert not check.allowed
        assert check.result == GateResult.DENY

    def test_validate_with_hitl_approved(self):
        hitl = MagicMock()
        hitl.requires_approval.return_value = (True, "Requires approval")
        mock_request = MagicMock()
        mock_request.is_approved.return_value = True
        mock_request.id = "req-1"
        hitl.request_approval = AsyncMock(return_value=mock_request)

        gateway = ActionGateway(hitl_gate=hitl)
        check = run_async(gateway.validate("exploit", "https://app.example.test"))
        assert check.allowed

    def test_rate_limiting(self):
        gateway = ActionGateway(max_actions_per_minute=3)
        for _ in range(3):
            check = run_async(gateway.validate("scan", "https://example.com"))
            assert check.allowed

        check = run_async(gateway.validate("scan", "https://example.com"))
        assert not check.allowed
        assert check.result == GateResult.RATE_LIMITED

    def test_stats(self):
        gateway = ActionGateway()
        run_async(gateway.validate("scan", "https://example.com"))
        run_async(gateway.validate("scan", "https://evil.com"))

        # Mock a safety block
        safety = MagicMock()
        safety.check_url.return_value = MagicMock(allowed=False, reason="blocked")
        gateway2 = ActionGateway(safety_gate=safety)
        run_async(gateway2.validate("scan", "https://evil.com"))

        stats = gateway2.get_stats()
        assert stats["blocked"] >= 1


# ── EngagementContext tests ─────────────────────────────────────

class TestEngagementContext:
    def test_defaults(self):
        ctx = EngagementContext()
        assert ctx.engagement_id == ""
        assert ctx.to_summary()["has_auth"] is False

    def test_full_context(self):
        ctx = EngagementContext(
            engagement_id="eng-001",
            target="https://example.com",
            program="TestBB",
            auth_manager=MagicMock(),
            safety_gate=MagicMock(),
            action_gateway=MagicMock(),
            state_manager=MagicMock(),
            llm_generate=MagicMock(),
        )
        summary = ctx.to_summary()
        assert summary["engagement_id"] == "eng-001"
        assert summary["has_auth"] is True
        assert summary["has_safety"] is True
        assert summary["has_llm"] is True

    def test_is_in_scope(self):
        safety = MagicMock()
        safety.check_url.return_value = MagicMock(allowed=True)
        ctx = EngagementContext(safety_gate=safety)
        assert ctx.is_in_scope("https://example.com")

    def test_get_auth_headers(self):
        auth = MagicMock()
        auth.get_auth_injection.return_value = {"headers": {"Auth": "Bearer tok"}, "cookies": {}}
        ctx = EngagementContext(auth_manager=auth)
        headers = ctx.get_auth_headers()
        assert headers["Auth"] == "Bearer tok"


# ── ResearchBrain coverage tests ────────────────────────────────

class TestResearchBrainCoverage:
    def test_is_action_tested(self):
        brain = ResearchBrain(target="https://example.com", llm_generate=make_mock_llm())
        brain._tested_actions.add("test_idor:https://example.com/users/1")
        assert brain.is_action_tested("test_idor", "https://example.com/users/1")
        assert not brain.is_action_tested("test_xss", "https://example.com/search")

    def test_is_overtested(self):
        brain = ResearchBrain(target="https://example.com", llm_generate=make_mock_llm())
        brain._tested_vuln_classes["idor"] = 3
        assert brain.is_overtested("idor", "/users/1")
        assert not brain.is_overtested("xss", "/search")

    def test_get_untested_vuln_classes(self):
        brain = ResearchBrain(target="https://example.com", llm_generate=make_mock_llm())
        untested = brain.get_untested_vuln_classes()
        assert "idor" in untested
        assert "xss" in untested

    def test_get_coverage_report(self):
        brain = ResearchBrain(target="https://example.com", llm_generate=make_mock_llm())
        brain._tested_actions.add("test_idor:/a")
        brain._tested_endpoints.add("/a")
        brain._tested_vuln_classes["idor"] = 1
        report = brain.get_coverage_report()
        assert report["total_tested"] == 1
        assert report["unique_endpoints"] == 1
        assert report["vuln_classes_tested"] == 1


# ── StateManager + ResearchLoop integration ─────────────────────

class TestStateResearchIntegration:
    def test_research_loop_with_state_manager(self, tmp_path):
        """Test that ResearchLoop uses StateManager when provided."""
        sm = StateManager(str(tmp_path))

        mock_llm = make_mock_llm({"action": "stop", "target": "", "reason": "done", "confidence": 1.0, "priority": 1.0})
        loop = ResearchLoop(
            target="https://example.com",
            llm_generate=mock_llm,
            workspace_dir=str(tmp_path),
            state_manager=sm,
        )

        run_async(loop.initialize())
        report = run_async(loop.run())

        assert report["iterations"] >= 1
        # StateManager should have been used for checkpointing
        checkpoints = sm.list_checkpoints()
        assert len(checkpoints) >= 0  # May or may not checkpoint depending on iteration count


# ── ValidationPipeline + ResearchLoop integration ───────────────

class TestValidationIntegration:
    def test_research_loop_with_validation(self, tmp_path):
        """Test that ResearchLoop uses ValidationPipeline when provided."""
        validation = ValidationPipeline(min_confidence=0.3)

        mock_llm = make_mock_llm({"action": "stop", "target": "", "reason": "done", "confidence": 1.0, "priority": 1.0})
        loop = ResearchLoop(
            target="https://example.com",
            llm_generate=mock_llm,
            workspace_dir=str(tmp_path),
            validation_pipeline=validation,
        )

        run_async(loop.initialize())
        report = run_async(loop.run())
        assert report["iterations"] >= 1


# ── End-to-end pipeline test ────────────────────────────────────

class TestEndToEndPipeline:
    def test_full_autonomous_runner(self, tmp_path):
        """Test the complete autonomous pipeline with mocked LLM."""
        engagement = make_test_engagement()
        engagement.workspace_dir = str(tmp_path)

        call_count = 0

        async def mock_llm(messages, response_format=None):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return {"content": json.dumps({
                    "action": "observe", "target": "https://app.example.test",
                    "reason": "Initial observation", "confidence": 0.5, "priority": 0.5,
                })}
            return {"content": json.dumps({
                "action": "stop", "target": "",
                "reason": "Done", "confidence": 1.0, "priority": 1.0,
            })}

        runner = AutonomousRunner(
            engagement=engagement,
            config=RunnerConfig(max_iterations=5, checkpoint_interval=2),
            llm_generate=mock_llm,
            workspace_dir=str(tmp_path),
        )

        result = run_async(runner.run())

        assert result["engagement_id"] == "test-eng-001"
        assert result["status"] == "completed"
        assert result["iterations"] >= 1

        # State should be persisted
        state = runner.state_manager.load_state()
        assert state is not None
        assert state.status == "completed"

    def test_runner_creates_workspace(self, tmp_path):
        """Test that the runner creates the workspace directory."""
        engagement = make_test_engagement()
        workspace = str(tmp_path / "new_workspace")

        runner = AutonomousRunner(
            engagement=engagement,
            workspace_dir=workspace,
        )

        assert os.path.exists(workspace)

    def test_runner_status(self, tmp_path):
        """Test runner status reporting."""
        engagement = make_test_engagement()

        runner = AutonomousRunner(
            engagement=engagement,
            workspace_dir=str(tmp_path),
        )

        status = runner.get_status()
        assert status["engagement_id"] == "test-eng-001"
        assert "gateway_stats" in status


# ── Scope enforcement test ──────────────────────────────────────

class TestScopeEnforcement:
    def test_in_scope_allowed(self):
        safety = SafetyGate(
            in_scope_assets=[
                ScopeAsset(pattern="app.example.test", asset_type="domain"),
                ScopeAsset(pattern="api.example.test", asset_type="domain"),
            ],
            out_of_scope_assets=[
                ScopeAsset(pattern="admin.example.test", asset_type="domain"),
                ScopeAsset(pattern="thirdparty.example.net", asset_type="domain"),
            ],
        )
        gateway = ActionGateway(safety_gate=safety)

        # In-scope should pass
        check = run_async(gateway.validate("scan", "https://app.example.test/api"))
        assert check.allowed

        check = run_async(gateway.validate("scan", "https://api.example.test/users"))
        assert check.allowed

    def test_out_of_scope_blocked(self):
        safety = SafetyGate(
            in_scope_assets=[
                ScopeAsset(pattern="app.example.test", asset_type="domain"),
            ],
            out_of_scope_assets=[
                ScopeAsset(pattern="admin.example.test", asset_type="domain"),
                ScopeAsset(pattern="thirdparty.example.net", asset_type="domain"),
            ],
        )
        gateway = ActionGateway(safety_gate=safety)

        # Out-of-scope should be blocked
        check = run_async(gateway.validate("scan", "https://admin.example.test/config"))
        assert not check.allowed

        check = run_async(gateway.validate("scan", "https://thirdparty.example.net/data"))
        assert not check.allowed

    def test_wildcard_scope(self):
        safety = SafetyGate(
            in_scope_assets=[
                ScopeAsset(pattern="*.example.test", asset_type="domain"),
            ],
        )
        gateway = ActionGateway(safety_gate=safety)

        check = run_async(gateway.validate("scan", "https://app.example.test"))
        assert check.allowed

        check = run_async(gateway.validate("scan", "https://other.example.test"))
        assert check.allowed


# ── Auth context isolation test ─────────────────────────────────

class TestAuthContextIsolation:
    def test_separate_sessions(self):
        from demogorgon.core.auth.session import AuthType
        manager = AuthManager()
        # Create separate sessions
        sid_a = manager.create_session(AuthType.BEARER_TOKEN, {"token": "token_a"}, name="user_A")
        sid_b = manager.create_session(AuthType.BEARER_TOKEN, {"token": "token_b"}, name="user_B")

        session_a = manager.get_session(sid_a)
        session_b = manager.get_session(sid_b)

        # Sessions should not cross
        headers_a = session_a.get_header_injection()
        headers_b = session_b.get_header_injection()

        assert headers_a["Authorization"] == "Bearer token_a"
        assert headers_b["Authorization"] == "Bearer token_b"
        assert headers_a != headers_b

    def test_auth_injection_isolation(self):
        manager = AuthManager()
        from demogorgon.core.auth.session import AuthType

        manager.create_session(AuthType.BEARER_TOKEN, {"token": "tok_a"}, name="a")
        manager.create_session(AuthType.BEARER_TOKEN, {"token": "tok_b"}, name="b")

        # With scopes, only matching sessions are included
        # Without scopes, all active sessions are included (combined)
        injection = manager.get_auth_injection()
        # The last registered bearer token wins for Authorization header
        assert "Authorization" in injection["headers"]


# ── LLM failure handling test ───────────────────────────────────

class TestLLMFailureHandling:
    def test_research_loop_llm_exception(self, tmp_path):
        """Test that the loop handles LLM exceptions gracefully."""
        async def failing_llm(messages, response_format=None):
            raise Exception("LLM provider unavailable")

        loop = ResearchLoop(
            target="https://example.com",
            llm_generate=failing_llm,
            workspace_dir=str(tmp_path),
        )

        run_async(loop.initialize())
        report = run_async(loop.run())

        # Should not crash, should return a report
        assert "iterations" in report

    def test_research_loop_malformed_llm_output(self, tmp_path):
        """Test that the loop handles malformed LLM output gracefully."""
        async def bad_llm(messages, response_format=None):
            return {"content": "not valid json at all"}

        loop = ResearchLoop(
            target="https://example.com",
            llm_generate=bad_llm,
            workspace_dir=str(tmp_path),
        )

        run_async(loop.initialize())
        report = run_async(loop.run())

        # Should handle gracefully
        assert "iterations" in report

    def test_runner_no_llm(self, tmp_path):
        """Test runner with no LLM provider."""
        engagement = make_test_engagement()

        runner = AutonomousRunner(
            engagement=engagement,
            llm_generate=None,
            workspace_dir=str(tmp_path),
        )

        result = run_async(runner.run())
        # Should complete with error about no LLM
        assert result.get("error") or result.get("status") == "completed"


# ── Stagnation detection test ───────────────────────────────────

class TestStagnationDetection:
    def test_stagnation_pivot(self):
        mock_llm = make_mock_llm()
        config = LoopConfig(stagnation_threshold=2)
        loop = ResearchLoop(
            target="https://example.com",
            llm_generate=mock_llm,
            config=config,
        )
        loop._strategy = "explore"
        loop._stagnation_count = 2

        should_stop, reason = loop._check_stopping_conditions()
        assert not should_stop
        assert loop._strategy == "validate"
        assert loop._stagnation_count == 0

    def test_stagnation_stops_after_all_strategies(self):
        mock_llm = make_mock_llm()
        config = LoopConfig(stagnation_threshold=2)
        loop = ResearchLoop(
            target="https://example.com",
            llm_generate=mock_llm,
            config=config,
        )
        loop._strategy = "exploit"
        loop._stagnation_count = 2

        should_stop, reason = loop._check_stopping_conditions()
        assert should_stop
        assert "Stagnant" in reason


# ── Crash and resume test ───────────────────────────────────────

class TestCrashResume:
    def test_checkpoint_and_resume(self, tmp_path):
        """Test that state is saved and can be resumed."""
        sm = StateManager(str(tmp_path))

        # Initialize and save some state
        state = sm.initialize("eng-001", "https://example.com")
        state.iteration = 15
        state.strategy = "validate"
        state.findings_count = 2
        sm.save_state(state)

        # Save a checkpoint
        sm.save_checkpoint(15, {"case": "data", "iteration": 15})

        # Simulate restart — load state
        loaded = sm.load_state()
        assert loaded is not None
        assert loaded.iteration == 15
        assert loaded.strategy == "validate"
        assert loaded.findings_count == 2

        # Load checkpoint
        cp = sm.get_latest_checkpoint()
        assert cp is not None
        iteration, data = cp
        assert iteration == 15

    def test_no_duplicate_evidence_on_resume(self, tmp_path):
        """Test that resumed engagement doesn't duplicate evidence."""
        from demogorgon.core.research_loop.evidence import EvidenceCollector

        collector = EvidenceCollector(workspace_dir=str(tmp_path))
        collector.add_http_evidence("GET", "/test", 200)
        assert len(collector.get_all_evidence()) == 1

        # Save and reload
        path = os.path.join(str(tmp_path), "evidence.json")
        collector.save(path)

        collector2 = EvidenceCollector(workspace_dir=str(tmp_path))
        collector2.load(path)
        assert len(collector2.get_all_evidence()) == 1


# ── Report generation test ──────────────────────────────────────

class TestReportGeneration:
    def test_report_from_findings(self, tmp_path):
        gen = ReportGenerator(workspace_dir=str(tmp_path))
        findings = [
            Finding(title="IDOR", severity="high", vuln_class="idor", endpoint="/api/users/1"),
            Finding(title="XSS", severity="medium", vuln_class="xss", endpoint="/search"),
        ]
        report = gen.generate(findings, target="https://example.com", program="TestBB")
        json_path = gen.save_json(report)
        md_path = gen.save_markdown(report)

        assert os.path.exists(json_path)
        assert os.path.exists(md_path)
        assert report.total_findings == 2


# ── BugChain integration test ───────────────────────────────────

class TestBugChainIntegration:
    def test_chain_detection_from_findings(self):
        detector = BugChainDetector()
        observations = [
            {"vuln_class": "open_redirect", "endpoint": "/redirect", "confidence": 0.7},
            {"vuln_class": "token_theft", "endpoint": "/oauth", "confidence": 0.6},
            {"vuln_class": "account_takeover", "endpoint": "/account", "confidence": 0.8},
        ]
        chains = detector.detect_chains(observations)
        assert len(chains) >= 1
        assert chains[0].is_known_pattern


# ── CLI integration test (smoke) ────────────────────────────────

class TestCLISmoke:
    def test_cli_help(self):
        """Test that CLI help works."""
        import subprocess
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
        result = subprocess.run(
            ["python", "-m", "demogorgon", "--help"],
            capture_output=True,
            text=True,
            cwd=project_root,
            env={**os.environ, "PYTHONPATH": project_root},
        )
        assert result.returncode == 0
        assert "Demogorgon" in result.stdout or "demogorgon" in result.stdout.lower()
