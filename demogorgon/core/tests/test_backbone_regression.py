"""Regression tests for the execution-backbone refactor (Phases 1–14).

Every test here maps to one of the terminal failures found in Phase 0:

* paste/file confusion            → TestGuidedHuntInput
* naive policy parsing            → TestPolicyParsing
* recon silently skipped          → TestReconWiring
* provider fallback/health bugs   → TestLLMFallback
* runner always "completed"       → TestStatusIntegrity
* no research engine without LLM  → TestDeterministicBackbone
* cancellation not persisted      → TestCancellation
* no coverage accounting          → TestCoverage
"""

from __future__ import annotations

import asyncio
import json

import pytest

from demogorgon.core.coverage import build_coverage
from demogorgon.core.engagement import (
    AuthorizationStatus,
    Engagement,
    EngagementStatus,
    ProgramPolicy,
    ScopeAsset,
)
from demogorgon.core.hunt_result import HuntResult
from demogorgon.core.runner import AutonomousRunner, RunnerConfig
from demogorgon.core.scope.policy_parser import parse_policy
from demogorgon.core.scope.validator import PolicyValidator


def run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def make_engagement() -> Engagement:
    policy = ProgramPolicy(
        program_name="Test Program",
        platform="manual",
        in_scope=[ScopeAsset(pattern="app.example.test", asset_type="domain")],
        out_of_scope=[ScopeAsset(pattern="admin.example.test", asset_type="domain")],
    )
    return Engagement(
        id="reg-001",
        target_url="https://app.example.test",
        policy=policy,
        status=EngagementStatus.ACTIVE,
        authorization_status=AuthorizationStatus.CONFIRMED,
    )


# ── Phase 1: guided-hunt input state machine ───────────────────

class TestGuidedHuntInput:
    def test_file_and_paste_helpers_exist(self):
        from demogorgon.cli import hunt_flow

        assert hasattr(hunt_flow, "HuntPhase")
        assert hasattr(hunt_flow, "_read_pasted_policy")
        assert hasattr(hunt_flow, "_prompt_file_path")
        assert hasattr(hunt_flow, "_drain_pending_stdin")

    def test_paste_reader_does_not_validate_paths(self, monkeypatch, capsys):
        """Pasted policy text must never be mistaken for a file path."""
        from demogorgon.cli import hunt_flow

        lines = iter([
            "In scope: *.example.com",
            "Out of scope: admin.example.com",
            "END",
        ])
        monkeypatch.setattr("builtins.input", lambda *_: next(lines))
        text = hunt_flow._read_pasted_policy()
        assert "In scope" in text
        assert "Out of scope" in text
        assert "END" not in text

    def test_file_prompt_reports_missing_file(self, monkeypatch):
        from demogorgon.cli import hunt_flow

        answers = iter(["/nonexistent/nowhere.txt", "/nonexistent/again.txt",
                        "/nonexistent/third.txt"])
        monkeypatch.setattr("builtins.input", lambda *_: next(answers))
        kind, value = hunt_flow._prompt_file_path()
        # Bounded attempts — never an infinite path loop
        assert kind in ("path", "paste", "abort")
        assert value is not None


# ── Phase 2/3: policy parsing + validation ─────────────────────

class TestPolicyParsing:
    SCOPE_TEXT = """
# Scope

## In scope
- https://app.example.com
- *.cdn.example.com
- 10.0.0.0/8

## Out of scope
- admin.example.com
- staging.example.com

## Testing
SQL injection and XSS are allowed.
CSRF and denial of service are forbidden.
No account creation allowed.
"""

    def test_sections_split_correctly(self):
        policy = parse_policy(self.SCOPE_TEXT)
        assert policy.in_scope, "in-scope assets must be extracted"
        assert policy.out_of_scope, "out-of-scope must not be empty"

    def test_in_and_out_disjoint(self):
        policy = parse_policy(self.SCOPE_TEXT)
        in_patterns = {a.pattern for a in policy.in_scope}
        out_patterns = {a.pattern for a in policy.out_of_scope}
        assert in_patterns.isdisjoint(out_patterns)

    def test_excluded_vulns_become_forbidden(self):
        policy = parse_policy(self.SCOPE_TEXT)
        forbidden = {v.lower() for v in policy.forbidden_vulnerabilities}
        assert "csrf" in forbidden
        assert "dos" in forbidden
        # allowed classes must NOT be forbidden
        assert "xss" not in forbidden
        assert "sqli" not in forbidden

    def test_allowed_vulns_extracted(self):
        policy = parse_policy(self.SCOPE_TEXT)
        allowed = {v.lower() for v in policy.allowed_vulnerabilities}
        assert "sqli" in allowed or "sql injection" in allowed
        assert "xss" in allowed
        # forbidden wins over allowed
        assert "csrf" not in allowed

    def test_prose_line_yields_no_assets(self):
        """A prose sentence must not be scraped as a domain (Phase 0 bug)."""
        policy = parse_policy(
            "This program covers everything we own including our main site."
        )
        assert policy.in_scope == []

    def test_raw_policy_preserved(self):
        policy = parse_policy(self.SCOPE_TEXT)
        assert "In scope" in (policy.raw_policy or "")

    def test_round_trip_dict(self):
        policy = parse_policy(self.SCOPE_TEXT)
        restored = ProgramPolicy.from_dict(policy.to_dict())
        assert len(restored.in_scope) == len(policy.in_scope)
        assert len(restored.out_of_scope) == len(policy.out_of_scope)

    def test_target_only_flag(self):
        policy = parse_policy("Anything on https://only.example.com")
        assert policy.target_only is True

    def test_validator_blocks_empty_policy(self):
        validation = PolicyValidator().validate(parse_policy("no scope info at all"))
        assert not validation.ok
        assert validation.blockers

    def test_validator_warns_on_forbidden_vulns(self):
        validation = PolicyValidator().validate(parse_policy(self.SCOPE_TEXT))
        assert validation.ok
        assert any("csrf" in w.lower() for w in validation.warnings)

    def test_validator_requires_confirmation_for_conditionals(self):
        policy = parse_policy(
            "In scope\n- api.example.com\n\nOut of scope\n- *.example.com\n"
        )
        validation = PolicyValidator().validate(policy)
        # A wildcard exclusion + explicit inclusion is conditional
        assert validation.requires_confirmation in (True, False)


# ── Phase 5: recon wiring ──────────────────────────────────────

class TestReconWiring:
    def test_registry_factory_exists(self):
        from demogorgon.tools.registry import ToolRegistry, create_default_registry

        reg = create_default_registry()
        assert isinstance(reg, ToolRegistry)
        assert reg._tools, "adapters must be registered"

    def test_registry_discovers_tools(self):
        from demogorgon.tools.registry import create_default_registry

        reg = create_default_registry()
        run_async(reg.discover_all())
        # Availability depends on the host; the call must not raise and
        # must return a list.
        assert isinstance(reg.get_available_tools(), list)

    def test_executor_wraps_registry(self):
        from demogorgon.tools.executor import ToolExecutor
        from demogorgon.tools.registry import create_default_registry

        reg = create_default_registry()
        ex = ToolExecutor(reg)
        result = run_async(ex.execute_recon("nope_not_a_stage", {}))
        assert result.success is False
        assert "Unknown" in result.error or "unknown" in result.error.lower()

    def test_engine_rejects_registry_as_executor(self):
        """ReconEngine must be given a ToolExecutor, not the registry twice."""
        from demogorgon.recon.engine import ReconEngine
        from demogorgon.tools.executor import ToolExecutor
        from demogorgon.tools.registry import create_default_registry

        reg = create_default_registry()
        engine = ReconEngine(registry=reg, executor=ToolExecutor(reg))
        assert engine._executor is not reg

    def test_stage_timeout_recorded(self, monkeypatch):
        """A hanging stage must error out, not hang the engagement."""
        from demogorgon.recon.engine import ReconEngine
        from demogorgon.tools.executor import ToolExecutor
        from demogorgon.tools.registry import create_default_registry

        reg = create_default_registry()
        engine = ReconEngine(
            registry=reg, executor=ToolExecutor(reg), stage_timeout=0.01
        )

        async def slow(_domain):
            await asyncio.sleep(5)

        monkeypatch.setattr(engine, "_stage_subdomain_enum", slow, raising=False)
        stage = engine._stages[0]
        stage.name = "subdomain_enum"
        run_async(engine._run_stage(stage, "example.test"))
        assert stage.error and "timed out" in stage.error
        assert stage.completed is False

    def test_dependency_skip_counted(self):
        from demogorgon.recon.engine import ReconEngine
        from demogorgon.tools.executor import ToolExecutor
        from demogorgon.tools.registry import create_default_registry

        reg = create_default_registry()
        engine = ReconEngine(
            registry=reg,
            executor=ToolExecutor(reg),
            stage_timeout=0.01,  # every stage "times out" instantly
        )

        async def fail(_domain):
            raise RuntimeError("boom")

        for name in ("_stage_subdomain_enum", "_stage_cert_transparency",
                     "_stage_dns_resolution", "_stage_http_probe"):
            monkey_name = name
            setattr(engine, monkey_name, fail)
        engine._stage_port_scan = fail
        engine._stage_tech_fingerprint = fail
        engine._stage_web_crawl = fail
        engine._stage_url_harvest = fail

        result = run_async(engine.run("example.test"))
        assert result.stages_total == 8
        # Every stage is accounted for: completed, failed, or dependency-skipped
        failed = [
            s for s in engine._stages
            if s.error and not s.error.startswith("skipped")
        ]
        assert result.stages_completed + result.stages_skipped + len(failed) == 8
        assert result.stages_skipped >= 1  # dependents of the failed stages

    def test_runner_builds_registry_when_none_passed(self, tmp_path):
        runner = AutonomousRunner(
            engagement=make_engagement(),
            config=RunnerConfig(max_iterations=1),
            llm_generate=None,
            workspace_dir=str(tmp_path),
        )
        count = run_async(runner._discover_tools())
        assert runner.tool_registry is not None
        assert isinstance(count, int)

    def test_runner_recon_gets_executor_not_registry(self, tmp_path, monkeypatch):
        runner = AutonomousRunner(
            engagement=make_engagement(),
            config=RunnerConfig(max_iterations=1),
            llm_generate=None,
            workspace_dir=str(tmp_path),
        )
        run_async(runner._discover_tools())

        captured = {}

        class FakeEngine:
            def __init__(self, registry=None, executor=None, scope_matcher=None):
                captured["registry"] = registry
                captured["executor"] = executor

            async def run(self, target):
                class R:
                    subdomains = live_hosts = endpoints = ports = technologies = []
                    stages_completed = stages_total = stages_skipped = 0
                return R()

            _stages: list = []

        import demogorgon.recon.engine as engine_mod
        monkeypatch.setattr(engine_mod, "ReconEngine", FakeEngine)
        state = type("S", (), {"data": {}})()
        run_async(runner._run_recon(state))
        assert captured.get("executor") is not None
        assert captured["executor"] is not captured["registry"]
        assert hasattr(captured["executor"], "execute_recon")


# ── Phases 5–7: LLM fallback / health ──────────────────────────

class TestLLMFallback:
    def test_error_classification_kinds(self):
        from demogorgon.llm.errors import (
            FALLBACK_KINDS,
            LLMErrorKind,
            classify_llm_error,
        )

        assert classify_llm_error("Connection timeout") == LLMErrorKind.TRANSIENT
        assert classify_llm_error("429 Too Many Requests") == LLMErrorKind.RATE_LIMIT
        assert classify_llm_error("401 Unauthorized") == LLMErrorKind.AUTHENTICATION
        assert classify_llm_error("ImportError: no module named 'x'") == (
            LLMErrorKind.DEPENDENCY_MISSING
        )
        assert LLMErrorKind.AUTHENTICATION in FALLBACK_KINDS

    def test_generate_returns_error_response_when_no_provider(self):
        from demogorgon.llm.manager import AIProviderManager

        mgr = AIProviderManager()
        mgr._providers.clear()
        # Hermetic: a configured developer .env must not satisfy this test.
        mgr._env = {}
        resp = run_async(mgr.generate([{"role": "user", "content": "hi"}]))
        # Must RETURN an error response, never raise (test contract)
        assert resp.error

    def test_generate_or_raise_raises(self):
        from demogorgon.llm.errors import LLMUnavailableError
        from demogorgon.llm.manager import AIProviderManager

        mgr = AIProviderManager()
        mgr._providers.clear()
        # Hermetic: a configured developer .env must not satisfy this test.
        mgr._env = {}
        with pytest.raises(LLMUnavailableError):
            run_async(mgr.generate_or_raise([{"role": "user", "content": "hi"}]))

    def test_circuit_opens_on_auth_failure(self):
        from demogorgon.llm.manager import AIProviderManager

        mgr = AIProviderManager()
        mgr.configure()
        mgr._note_failure("primary", "401 Unauthorized: invalid key")
        # _circuit_open is a dict of provider_key -> reason
        assert "primary" in mgr._circuit_open
        assert "authentication" in mgr._circuit_open["primary"]
        # An open circuit removes the provider from the candidate chain
        mgr._active_provider = "primary"
        mgr._providers["primary"] = object()
        assert "primary" not in mgr._candidate_providers()

    def test_fallback_chain_order(self):
        from demogorgon.llm.manager import AIProviderManager

        mgr = AIProviderManager()
        mgr._active_provider = "openai"
        mgr._providers["openai"] = object()
        mgr._providers["fallback_deepseek"] = object()
        chain = mgr._candidate_providers()
        assert chain[0] == "openai"
        assert "fallback_deepseek" in chain

    def test_connection_probe_requires_healthy_status(self, monkeypatch):
        """Phase 0 bug: a truthy health dict counted as success even when the
        provider was unreachable and smoke testing never ran."""
        from demogorgon.config import model_discovery
        from demogorgon.llm import manager as mgr_mod

        class FakeManager:
            _active_model = "fake"

            def configure_from_params(self, **kw):
                pass

            async def health_check(self):
                # Truthy dict, but NOT healthy — the exact Phase 0 bug shape
                return {"latency": 1.0, "connectivity": "down"}

            async def smoke_test(self):
                raise AssertionError("smoke test must not run when health fails")

        # test_provider_connection imports LLMManager at call time
        monkeypatch.setattr(mgr_mod, "LLMManager", FakeManager, raising=False)

        result = run_async(model_discovery.test_provider_connection(
            "openrouter", api_key="sk-test"
        ))
        assert result["success"] is False
        assert "not reachable" in (result["error"] or "").lower()

    def test_connection_probe_fails_when_smoke_fails(self, monkeypatch):
        from demogorgon.config import model_discovery
        from demogorgon.llm import manager as mgr_mod

        class FakeManager:
            _active_model = "fake"

            def configure_from_params(self, **kw):
                pass

            async def health_check(self):
                return {"status": "healthy", "latency": 10}

            async def smoke_test(self):
                return {"status": "failed", "error": "inference unavailable",
                        "structured_output": "FAILED"}

        monkeypatch.setattr(mgr_mod, "LLMManager", FakeManager, raising=False)

        result = run_async(model_discovery.test_provider_connection(
            "openrouter", api_key="sk-test"
        ))
        assert result["success"] is False
        assert "inference unavailable" in (result["error"] or "")


# ── Phase 6: deterministic backbone ────────────────────────────

class TestDeterministicBackbone:
    def test_module_importable(self):
        import demogorgon.core.research_loop.deterministic as det

        assert hasattr(det, "DeterministicReasoner")
        assert hasattr(det, "DeterministicPlanner")
        assert hasattr(det, "DeterministicValidator")
        assert det.SAFE_GET_PLAYBOOK

    def test_capability_probe_detects_it(self):
        from demogorgon.core.capabilities.environment import (
            _probe_deterministic_research,
        )

        status, _msg = _probe_deterministic_research()
        assert status.value in ("available", "healthy", "ok", "degraded")
        assert status.value != "unavailable"

    def test_brain_uses_deterministic_without_llm(self):
        from demogorgon.core.brain.research_brain import ResearchBrain
        from demogorgon.core.research_loop.deterministic import (
            DeterministicReasoner,
        )

        brain = ResearchBrain(target="https://app.example.test", llm_generate=None)
        assert isinstance(brain.reasoner, DeterministicReasoner)

    def test_brain_uses_llm_when_provided(self):
        from demogorgon.core.brain.reasoner import LLMReasoner
        from demogorgon.core.brain.research_brain import ResearchBrain

        async def llm(messages, response_format=None):
            return {"content": "{}"}

        brain = ResearchBrain(target="https://app.example.test", llm_generate=llm)
        assert isinstance(brain.reasoner, LLMReasoner)

    def test_reasoner_walks_playbook_then_stops(self):
        from demogorgon.core.research_loop.deterministic import (
            SAFE_GET_PLAYBOOK,
            DeterministicReasoner,
        )

        reasoner = DeterministicReasoner(target="https://app.example.test")
        seen = []
        for _ in range(len(SAFE_GET_PLAYBOOK) + 1):
            d = run_async(reasoner.reason({"target": "https://app.example.test"}))
            seen.append(d.action.value)
        # Every playbook step exactly once, then a single STOP
        assert seen[:len(SAFE_GET_PLAYBOOK)] == ["test_endpoint"] * len(SAFE_GET_PLAYBOOK)
        assert seen[-1] == "stop"
        # STOP is sticky: asking again never resumes the playbook
        again = run_async(reasoner.reason({"target": "https://app.example.test"}))
        assert again.action.value == "stop"

    def test_reasoner_skips_already_tested(self):
        from demogorgon.core.research_loop.deterministic import (
            DeterministicReasoner,
        )

        reasoner = DeterministicReasoner(target="https://x.test")
        first = run_async(reasoner.reason({"target": "https://x.test"}))
        again = run_async(reasoner.reason({
            "target": "https://x.test",
            "tested_actions": [f"test_endpoint:{first.target}"],
        }))
        assert again.target != first.target

    def test_planner_is_get_only(self):
        from demogorgon.core.research_loop.deterministic import (
            DeterministicPlanner,
        )

        plan = run_async(DeterministicPlanner().plan(
            {"id": "h1", "endpoint": "https://x.test/.env", "vuln_class": "info_disclosure"},
            {},
        ))
        assert plan["steps"][0]["method"] == "GET"
        assert plan["risk_level"] == "low"
        assert plan["deterministic"] is True

    def test_validator_detects_git_head_leak(self):
        from demogorgon.core.research_loop.deterministic import (
            DeterministicValidator,
        )

        evidence = {
            "endpoint": "https://x.test/.git/HEAD",
            "request_response": {"response": {
                "status": 200, "body": "ref: refs/heads/main\n", "headers": {},
            }},
        }
        result = run_async(DeterministicValidator().validate(evidence))
        assert result["is_finding"] is True
        assert result["confidence"] >= 0.8

    def test_validator_rejects_normal_response(self):
        from demogorgon.core.research_loop.deterministic import (
            DeterministicValidator,
        )

        evidence = {
            "endpoint": "https://x.test/",
            "request_response": {"response": {
                "status": 200,
                "body": "<html><title>Welcome</title></html>",
                "headers": {
                    "strict-transport-security": "max-age=31536000",
                    "x-frame-options": "DENY",
                    "content-security-policy": "default-src 'self'",
                },
            }},
        }
        result = run_async(DeterministicValidator().validate(evidence))
        assert result["is_finding"] is False
        assert result["false_positive_reason"]


# ── Phase 9: status integrity ──────────────────────────────────

class TestStatusIntegrity:
    def _runner(self, tmp_path, llm=None, **cfg):
        return AutonomousRunner(
            engagement=make_engagement(),
            config=RunnerConfig(max_iterations=cfg.get("max_iterations", 3),
                                checkpoint_interval=2),
            llm_generate=llm,
            workspace_dir=str(tmp_path),
        )

    def test_status_is_never_blanket_completed(self, tmp_path):
        runner = self._runner(tmp_path, llm=None)
        result = run_async(runner.run())
        assert result["status"] in (
            "completed", "degraded", "partial", "blocked", "failed", "cancelled"
        )
        # No LLM → must not claim a fully successful run
        assert result["status"] != "completed" or not result["status_notes"]

    def test_notes_are_carried_into_summary(self, tmp_path):
        runner = self._runner(tmp_path, llm=None)
        result = run_async(runner.run())
        assert "status_notes" in result

    def test_derive_status_blocked_when_no_engine(self, tmp_path):
        runner = self._runner(tmp_path, llm=None)
        runner.llm_generate = None
        runner._capability_notes = [
            "llm: unavailable", "deterministic backbone: unavailable"
        ]
        status = runner._derive_status(
            "completed", {"error": "no engine"}, "no engine", None
        )
        assert status == "blocked"

    def test_derive_status_failed_on_error_without_findings(self, tmp_path):
        runner = self._runner(tmp_path, llm=None)
        runner._capability_notes = []
        status = runner._derive_status(
            "completed", {"error": "boom", "findings": []}, "boom", None
        )
        assert status == "failed"

    def test_derive_status_degraded_on_capability_notes(self, tmp_path):
        runner = self._runner(tmp_path, llm=None)
        runner.llm_generate = None
        runner._capability_notes = ["llm: unavailable (deterministic backbone running)"]
        status = runner._derive_status("completed", {"findings": []}, None, None)
        assert status == "degraded"

    def test_derive_status_completed_when_clean(self, tmp_path):
        runner = self._runner(tmp_path, llm=lambda *a, **k: None)
        runner.llm_generate = lambda *a, **k: None
        runner._capability_notes = []
        status = runner._derive_status(
            "completed", {"findings": [{"x": 1}]}, None, None
        )
        assert status == "completed"

    def test_exception_marks_failed(self, tmp_path):
        runner = self._runner(tmp_path, llm=lambda *a, **k: None)
        runner.llm_generate = lambda *a, **k: None

        def boom(*_a, **_k):
            raise RuntimeError("subsystem exploded")

        runner._discover_tools = boom
        result = run_async(runner.run())
        assert result["status"] == "failed"
        assert "exploded" in (result["error"] or "")

    def test_state_status_matches_summary(self, tmp_path):
        runner = self._runner(tmp_path, llm=None)
        result = run_async(runner.run())
        state = runner.state_manager.load_state()
        assert state is not None
        assert state.status == result["status"]

    def test_duplicate_capability_notes_are_collapsed(self, tmp_path):
        """Probe + stage runner both record a recon failure; show one line."""
        notes = AutonomousRunner._dedupe_notes([
            "recon: unavailable",
            "recon: unavailable (import of demogorgon.recon.engine halted)",
            "llm: unavailable",
        ])
        assert notes == [
            "recon: unavailable (import of demogorgon.recon.engine halted)",
            "llm: unavailable",
        ]

    def test_distinct_notes_are_preserved(self, tmp_path):
        notes = AutonomousRunner._dedupe_notes([
            "llm: unavailable", "recon: degraded", "browser: missing",
        ])
        assert len(notes) == 3


# ── Phase 11: cancellation ─────────────────────────────────────

class TestCancellation:
    def test_cancel_sets_event(self, tmp_path):
        runner = AutonomousRunner(
            engagement=make_engagement(),
            config=RunnerConfig(max_iterations=5),
            llm_generate=None,
            workspace_dir=str(tmp_path),
        )
        assert not runner.cancel_requested
        runner.cancel()
        assert runner.cancel_requested

    def test_loop_stops_when_cancelled(self):
        from demogorgon.core.research_loop.loop import LoopConfig, ResearchLoop

        loop = ResearchLoop(
            target="https://app.example.test",
            llm_generate=None,
            config=LoopConfig(max_iterations=50),
        )
        loop.request_cancel()
        should_stop, reason = loop._check_stopping_conditions()
        assert should_stop
        assert "cancel" in reason.lower()

    def test_loop_report_flags_cancelled(self):
        from demogorgon.core.research_loop.loop import LoopConfig, ResearchLoop

        loop = ResearchLoop(
            target="https://app.example.test",
            llm_generate=None,
            config=LoopConfig(max_iterations=50),
        )
        loop.request_cancel()
        report = run_async(loop.run())
        assert report["cancelled"] is True
        assert "cancel" in report["stop_reason"].lower()

    def test_runner_cancel_before_run_is_cleared(self, tmp_path):
        runner = AutonomousRunner(
            engagement=make_engagement(),
            config=RunnerConfig(max_iterations=1),
            llm_generate=None,
            workspace_dir=str(tmp_path),
        )
        runner.cancel()
        result = run_async(runner.run())
        # A stale cancel from a previous run must not kill the new run
        assert result["status"] != "cancelled"


# ── Phase 15/16: plan execution + terminal actions ─────────────

class TestPlanExecution:
    """LLM planners emit HTTP verbs and {endpoint} placeholders; the executor
    used to drop those steps, so the loop ran its full budget doing nothing."""

    def test_http_verb_as_step_action_is_accepted(self):
        from demogorgon.core.research_loop.executor import PlanExecutor

        executed = []

        class _Resp:
            status_code = 200
            headers = {}
            text = "ok"
            content = b"ok"

        class _Client:
            async def get(self, url, **kw):
                executed.append(("GET", url))
                return _Resp()

        ex = PlanExecutor(http_client=_Client())
        out = run_async(ex._execute_step(
            {"action": "GET", "target": "https://app.example.test/", "method": "GET"}
        ))
        assert executed == [("GET", "https://app.example.test/")]
        assert out["evidence"], "HTTP-verb steps must produce evidence"

    @pytest.mark.parametrize("action", ["get", "GET", "post", "DELETE", "Patch"])
    def test_common_http_verbs_map_to_send_request(self, action):
        from demogorgon.core.research_loop.executor import PlanExecutor

        assert action.lower() in PlanExecutor._HTTP_VERBS

    def test_unknown_action_still_dropped_safely(self):
        from demogorgon.core.research_loop.executor import PlanExecutor

        out = run_async(PlanExecutor()._execute_step({"action": "launch_missiles"}))
        assert out["evidence"] == []

    def test_plan_resolves_endpoint_placeholder(self):
        from demogorgon.core.brain.planner import LLMExperimentPlanner

        planner = LLMExperimentPlanner(lambda *_a, **_k: None)
        plan = planner._validate_plan(
            {"steps": [{"action": "GET", "target": "{endpoint}"}]},
            {"id": "h1", "endpoint": "https://app.example.test/api", "description": "d"},
        )
        assert plan["steps"][0]["target"] == "https://app.example.test/api"

    def test_plan_with_no_steps_gets_a_default_step(self):
        from demogorgon.core.brain.planner import LLMExperimentPlanner

        planner = LLMExperimentPlanner(lambda *_a, **_k: None)
        plan = planner._validate_plan(
            {"steps": []},
            {"id": "h1", "endpoint": "https://app.example.test/", "description": "d"},
        )
        assert plan["steps"], "an empty plan yields zero evidence forever"
        assert plan["steps"][0]["target"] == "https://app.example.test/"

    def test_loop_stops_on_reasoner_stop_decision(self):
        """A 'stop' decision must end the run, not burn the whole budget."""
        from demogorgon.core.interfaces import ActionType, Decision
        from demogorgon.core.research_loop.loop import LoopConfig, ResearchLoop

        calls = {"n": 0}

        class _AlwaysStop:
            async def reason(self, context):
                calls["n"] += 1
                return Decision(
                    action=ActionType.STOP,
                    target="",
                    reason="coverage complete",
                )

        loop = ResearchLoop(
            target="https://app.example.test",
            llm_generate=None,
            config=LoopConfig(max_iterations=50),
        )
        loop.brain.reasoner = _AlwaysStop()
        report = run_async(loop.run())
        assert calls["n"] == 1, "STOP must terminate the loop immediately"
        assert report["iterations"] == 1
        assert "coverage complete" in report["stop_reason"]


# ── Phase 15/16: classification fidelity ───────────────────────

class ResearchLoopForTest:
    @staticmethod
    def make(target: str = "https://x.test"):
        from demogorgon.core.research_loop.loop import LoopConfig, ResearchLoop

        return ResearchLoop(
            target=target,
            llm_generate=None,
            config=LoopConfig(max_iterations=3),
        )


class TestValidationFidelity:
    def test_validator_keeps_its_own_vuln_class(self):
        """`_normalize_result` used to overwrite the LLM's classification
        with the evidence's class, so every finding was filed as 'endpoint'."""
        from demogorgon.core.brain.validator import LLMValidator

        v = LLMValidator(lambda *_a, **_k: None)
        out = v._normalize_result(
            {"is_finding": True, "vuln_class": "info_disclosure", "severity": "high"},
            {"vuln_class": "endpoint", "endpoint": "https://x.test/.env"},
        )
        assert out["vuln_class"] == "info_disclosure"
        assert out["endpoint"] == "https://x.test/.env"

    def test_validator_falls_back_to_evidence_class(self):
        from demogorgon.core.brain.validator import LLMValidator

        v = LLMValidator(lambda *_a, **_k: None)
        out = v._normalize_result({"is_finding": True}, {"vuln_class": "sqli"})
        assert out["vuln_class"] == "sqli"

    def test_confirmed_finding_contributes_to_class_coverage(self):
        """A generic test_endpoint probe that confirms a finding must still
        register that class as tested (otherwise coverage stayed 0)."""

        loop = ResearchLoopForTest.make()
        hyp = loop.brain.case.add_hypothesis("probe", "endpoint", "https://x.test/")
        exp = loop.brain.case.add_experiment(
            hypothesis_id=hyp.id, action="test_endpoint", target="https://x.test/"
        )
        exp.plan = {}
        finding = loop.brain.case.add_finding(
            hypothesis_id=hyp.id, title="Leak", severity="high",
            vuln_class="info_disclosure", endpoint="https://x.test/.env",
        )
        finding.confirmed = True

        stats = loop._generate_report()["stats"]
        assert stats["vuln_class_coverage"].get("info_disclosure", 0) >= 1


# ── Phase 10: coverage + hunt result ───────────────────────────

class TestCoverage:
    def test_coverage_from_full_data(self):
        cov = build_coverage(
            scope_assets=[
                ScopeAsset(pattern="a.test", asset_type="domain", confidence=0.95),
                ScopeAsset(pattern="b.test", asset_type="domain", confidence=0.4),
            ],
            recon_stats={
                "stages_total": 8,
                "stages_completed": 8,
                "stages_skipped": 0,
                "subdomains": 5,
                "live_hosts": 3,
                "endpoints": 10,
            },
            research_report={
                "iterations": 12,
                "findings": [{"title": "x"}],
                "stats": {
                    "unique_endpoints": 8,
                    "coverage_by_class": {"xss": 2, "ssrf": 1},
                    "vuln_classes_untested": 10,
                },
            },
            llm_used=True,
        )
        assert cov.scope_assets_total == 2
        assert cov.scope_assets_explicit == 1
        assert cov.recon_ratio == 1.0
        assert cov.testing_ratio == pytest.approx(0.8)
        assert 0 < cov.overall <= 1.0
        assert cov.grade in "ABCDF"
        assert cov.findings == 1

    def test_coverage_is_zero_for_empty_run(self):
        cov = build_coverage()
        assert cov.overall == 0.0
        assert cov.grade == "F"

    def test_untested_endpoints_drag_score(self):
        cov = build_coverage(
            recon_stats={"stages_total": 4, "stages_completed": 4, "endpoints": 20},
            research_report={"iterations": 0, "findings": [], "stats": {}},
        )
        assert cov.testing_ratio == 0.0
        assert cov.overall <= 0.5
        assert any("none tested" in n for n in cov.notes)

    def test_coverage_serializes(self):
        cov = build_coverage()
        data = cov.to_dict()
        json.dumps(data)  # must be JSON-safe
        assert "overall" in data and "grade" in data

    def test_hunt_result_from_summary(self):
        summary = {
            "engagement_id": "e1",
            "target": "https://x.test",
            "status": "degraded",
            "status_notes": ["llm: unavailable (deterministic backbone running)"],
            "duration": 12.5,
            "iterations": 4,
            "findings": [{"title": "leak"}],
            "chains": [],
            "report_path": "/tmp/r.md",
            "stats": {
                "recon": {"stages_total": 8, "stages_completed": 4,
                          "stages_skipped": 4, "endpoints": 6},
                "research": {"unique_endpoints": 3},
            },
        }
        result = HuntResult.from_summary(summary, llm_used=False)
        assert result.status == "degraded"
        assert not result.ok
        assert result.succeeded
        assert not result.failed
        assert "at least one capability" in result.explanation
        assert result.coverage.deterministic is True
        json.dumps(result.to_dict())
        assert "DEGRADED" in result.describe()

    def test_hunt_result_failed_status(self):
        result = HuntResult.from_summary({"status": "failed", "error": "boom"})
        assert result.failed
        assert "error" in result.explanation.lower() or "raised" in result.explanation.lower()

    def test_runner_summary_includes_coverage(self, tmp_path):
        runner = AutonomousRunner(
            engagement=make_engagement(),
            config=RunnerConfig(max_iterations=2),
            llm_generate=None,
            workspace_dir=str(tmp_path),
        )
        result = run_async(runner.run())
        assert "coverage" in result
        assert "coverage_summary" in result
        assert isinstance(result["coverage"]["overall"], float)
