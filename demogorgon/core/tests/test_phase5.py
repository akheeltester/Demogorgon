"""Tests for Phase 5 components: LLMReasoner, Planner, Validator, ResearchBrain."""

from __future__ import annotations

import asyncio
import json
import pytest

from demogorgon.core.brain.reasoner import LLMReasoner
from demogorgon.core.brain.planner import LLMExperimentPlanner
from demogorgon.core.brain.validator import LLMValidator
from demogorgon.core.brain.research_brain import ResearchBrain
from demogorgon.core.interfaces import Decision, ActionType, Observation
from demogorgon.core.research_loop.case import (
    ResearchCase,
    CaseStatus,
    CaseObservation,
    CaseHypothesis,
    CaseExperiment,
    CaseFinding,
    NextBestAction,
    HypothesisStatus,
)


# ── Mock LLM ──────────────────────────────────────────────────

def make_mock_llm(response_content: dict | str = None):
    """Create a mock LLM generate function."""
    if response_content is None:
        response_content = {
            "action": "test_idor",
            "target": "https://api.example.com/users/1",
            "reason": "IDOR testing on user endpoint",
            "confidence": 0.7,
            "priority": 0.8,
        }

    async def mock_generate(messages, response_format=None):
        if isinstance(response_content, dict):
            return {"content": json.dumps(response_content)}
        return {"content": response_content}

    return mock_generate


def run_async(coro):
    """Run an async function synchronously for testing."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ── LLMReasoner tests ─────────────────────────────────────────

class TestLLMReasoner:
    def test_init(self):
        mock_llm = make_mock_llm()
        reasoner = LLMReasoner(mock_llm)
        assert reasoner._llm == mock_llm

    def test_reason_returns_decision(self):
        mock_llm = make_mock_llm({
            "action": "test_idor",
            "target": "https://api.example.com/users/1",
            "reason": "IDOR testing",
            "confidence": 0.7,
            "priority": 0.8,
        })
        reasoner = LLMReasoner(mock_llm)

        context = {
            "target": "https://example.com",
            "iteration": 1,
            "assets": [],
            "observations": [],
            "hypotheses": [],
            "findings": [],
            "tested_actions": [],
            "available_tools": ["httpx", "nuclei"],
            "scope_status": "in_scope",
        }

        decision = run_async(reasoner.reason(context))
        assert isinstance(decision, Decision)
        assert decision.action == ActionType.TEST_IDOR
        assert decision.target == "https://api.example.com/users/1"
        assert decision.confidence == 0.7

    def test_reason_handles_json_error(self):
        mock_llm = make_mock_llm("not valid json")
        reasoner = LLMReasoner(mock_llm)

        context = {"target": "https://example.com", "iteration": 1}
        decision = run_async(reasoner.reason(context))
        assert isinstance(decision, Decision)
        assert decision.action == ActionType.OBSERVE  # fallback

    def test_reason_handles_llm_exception(self):
        async def failing_llm(messages, response_format=None):
            raise Exception("LLM failed")

        reasoner = LLMReasoner(failing_llm)
        context = {"target": "https://example.com", "iteration": 1}
        decision = run_async(reasoner.reason(context))
        assert isinstance(decision, Decision)
        assert decision.action == ActionType.OBSERVE

    def test_explain(self):
        mock_llm = make_mock_llm({"content": "This tests IDOR on user endpoint"})
        reasoner = LLMReasoner(mock_llm)

        decision = Decision(
            action=ActionType.TEST_IDOR,
            target="https://api.example.com/users/1",
            reason="IDOR testing",
        )
        explanation = run_async(reasoner.explain(decision))
        assert isinstance(explanation, str)
        assert len(explanation) > 0


# ── LLMExperimentPlanner tests ────────────────────────────────

class TestLLMExperimentPlanner:
    def test_init(self):
        mock_llm = make_mock_llm()
        planner = LLMExperimentPlanner(mock_llm)
        assert planner._llm == mock_llm

    def test_plan_returns_valid_structure(self):
        plan_response = {
            "steps": [
                {"step": 1, "action": "send_request", "target": "/api/users/1", "method": "GET"},
                {"step": 2, "action": "send_request", "target": "/api/users/2", "method": "GET"},
            ],
            "preconditions": ["Authenticated session"],
            "expected_outcomes": ["Both return 200 with different data"],
            "safety_checks": ["Rate limit respected"],
            "evidence_to_collect": ["Response bodies"],
            "rollback_steps": [],
            "estimated_duration_seconds": 30,
            "risk_level": "low",
        }
        mock_llm = make_mock_llm(plan_response)
        planner = LLMExperimentPlanner(mock_llm)

        hypothesis = {
            "id": "h1",
            "description": "IDOR on user endpoint",
            "endpoint": "/api/users/{id}",
            "vuln_class": "idor",
        }
        context = {"target": "https://example.com", "available_tools": ["httpx"]}

        plan = run_async(planner.plan(hypothesis, context))
        assert "steps" in plan
        assert "safety_checks" in plan
        assert "hypothesis_id" in plan
        assert len(plan["steps"]) >= 1

    def test_plan_fallback_on_error(self):
        async def failing_llm(messages, response_format=None):
            raise Exception("LLM failed")

        planner = LLMExperimentPlanner(failing_llm)
        hypothesis = {"id": "h1", "description": "Test", "endpoint": "/api/test", "vuln_class": "xss"}
        context = {"target": "https://example.com"}

        plan = run_async(planner.plan(hypothesis, context))
        assert "steps" in plan
        assert "safety_checks" in plan
        assert len(plan["safety_checks"]) > 0


# ── LLMValidator tests ────────────────────────────────────────

class TestLLMValidator:
    def test_init(self):
        mock_llm = make_mock_llm()
        validator = LLMValidator(mock_llm)
        assert validator._llm == mock_llm

    def test_validate_confirms_finding(self):
        validation_response = {
            "is_finding": True,
            "confidence": 0.85,
            "severity": "high",
            "title": "IDOR on user profile endpoint",
            "description": "User ID in URL path can be changed to access other users' data",
            "impact": "Attacker can read any user's profile data",
            "remediation": "Add authorization check on endpoint",
            "false_positive_reason": "",
            "steps_to_reproduce": ["Login as user A", "GET /api/users/B/profile", "View user B's data"],
        }
        mock_llm = make_mock_llm(validation_response)
        validator = LLMValidator(mock_llm)

        evidence = {
            "vuln_class": "idor",
            "endpoint": "/api/users/1/profile",
            "method": "GET",
            "evidence": [{"description": "Got 200 OK with user data"}],
        }

        result = run_async(validator.validate(evidence))
        assert result["is_finding"] is True
        assert result["severity"] == "high"
        assert "IDOR" in result["title"]

    def test_validate_rejects_false_positive(self):
        validation_response = {
            "is_finding": False,
            "confidence": 0.3,
            "severity": "info",
            "title": "",
            "description": "Response is cacheable public data",
            "impact": "",
            "remediation": "",
            "false_positive_reason": "Data is publicly available",
            "steps_to_reproduce": [],
        }
        mock_llm = make_mock_llm(validation_response)
        validator = LLMValidator(mock_llm)

        evidence = {
            "vuln_class": "idor",
            "endpoint": "/api/public/data",
            "method": "GET",
            "evidence": [],
        }

        result = run_async(validator.validate(evidence))
        assert result["is_finding"] is False
        assert result["false_positive_reason"] != ""

    def test_validate_fallback_on_error(self):
        async def failing_llm(messages, response_format=None):
            raise Exception("LLM failed")

        validator = LLMValidator(failing_llm)
        evidence = {"vuln_class": "xss", "endpoint": "/search", "method": "GET"}

        result = run_async(validator.validate(evidence))
        assert result["is_finding"] is False
        assert result["confidence"] <= 0.5


# ── ResearchCase tests ─────────────────────────────────────────

class TestResearchCase:
    def test_create_case(self):
        case = ResearchCase(target="https://example.com")
        assert case.target == "https://example.com"
        assert case.status == CaseStatus.ACTIVE
        assert case.iteration == 0

    def test_add_observation(self):
        case = ResearchCase(target="https://example.com")
        obs = case.add_observation("Found API endpoint", "katana")
        assert len(case.observations) == 1
        assert obs.description == "Found API endpoint"
        assert obs.source == "katana"

    def test_add_hypothesis(self):
        case = ResearchCase(target="https://example.com")
        hyp = case.add_hypothesis("IDOR on /api/users", "idor", "/api/users/{id}")
        assert len(case.hypotheses) == 1
        assert hyp.vuln_class == "idor"
        assert hyp.status == HypothesisStatus.PROPOSED

    def test_add_experiment(self):
        case = ResearchCase(target="https://example.com")
        exp = case.add_experiment("h1", "test_idor", "/api/users/1")
        assert len(case.experiments) == 1
        assert exp.hypothesis_id == "h1"

    def test_add_finding(self):
        case = ResearchCase(target="https://example.com")
        finding = case.add_finding("h1", "IDOR found", "high", "idor", "/api/users/1")
        assert len(case.findings) == 1
        assert finding.severity == "high"
        finding.confirmed = True
        assert len(case.get_confirmed_findings()) == 1

    def test_get_active_hypotheses(self):
        case = ResearchCase(target="https://example.com")
        case.add_hypothesis("Test 1")
        case.add_hypothesis("Test 2")
        case.hypotheses[0].status = HypothesisStatus.TESTING
        case.hypotheses[1].status = HypothesisStatus.CONFIRMED
        active = case.get_active_hypotheses()
        assert len(active) == 1
        assert active[0].status == HypothesisStatus.TESTING

    def test_set_next_action(self):
        case = ResearchCase(target="https://example.com")
        action = NextBestAction(action="test_idor", target="/api/users/1")
        case.set_next_action(action)
        assert case.get_next_action() is not None
        assert case.next_action.action == "test_idor"

    def test_increment_iteration(self):
        case = ResearchCase(target="https://example.com")
        assert case.iteration == 0
        case.increment_iteration()
        assert case.iteration == 1

    def test_to_dict(self):
        case = ResearchCase(target="https://example.com")
        case.add_observation("Test obs", "test")
        d = case.to_dict()
        assert d["target"] == "https://example.com"
        assert len(d["observations"]) == 1

    def test_save_load_roundtrip(self, tmp_path):
        case = ResearchCase(target="https://example.com")
        case.add_observation("Test obs", "test")
        case.add_hypothesis("Test hyp", "xss", "/search")
        path = str(tmp_path / "case.json")
        case.save(path)

        loaded = ResearchCase.load(path)
        assert loaded.target == "https://example.com"
        assert len(loaded.observations) == 1
        assert len(loaded.hypotheses) == 1


# ── ResearchBrain tests ────────────────────────────────────────

class TestResearchBrain:
    def test_init(self):
        mock_llm = make_mock_llm()
        brain = ResearchBrain(
            target="https://example.com",
            llm_generate=mock_llm,
            tools=["httpx", "nuclei"],
        )
        assert brain.target == "https://example.com"
        assert brain.tools == ["httpx", "nuclei"]
        assert brain.case.target == "https://example.com"

    def test_initialize(self):
        mock_llm = make_mock_llm()
        brain = ResearchBrain(target="https://example.com", llm_generate=mock_llm)
        run_async(brain.initialize())
        assert len(brain.case.observations) == 1

    def test_reason_next_action(self):
        mock_llm = make_mock_llm({
            "action": "test_idor",
            "target": "https://api.example.com/users/1",
            "reason": "IDOR testing",
            "confidence": 0.7,
            "priority": 0.8,
        })
        brain = ResearchBrain(target="https://example.com", llm_generate=mock_llm)
        run_async(brain.initialize())

        decision = run_async(brain.reason_next_action())
        assert isinstance(decision, Decision)
        assert decision.action == ActionType.TEST_IDOR
        assert brain.case.next_action is not None

    def test_add_observation(self):
        mock_llm = make_mock_llm()
        brain = ResearchBrain(target="https://example.com", llm_generate=mock_llm)
        obs = brain.add_observation("Found endpoint", "katana")
        assert len(brain.case.observations) >= 1

    def test_add_hypothesis(self):
        mock_llm = make_mock_llm()
        brain = ResearchBrain(target="https://example.com", llm_generate=mock_llm)
        hyp = brain.add_hypothesis("IDOR on /api/users", "idor", "/api/users/{id}")
        assert len(brain.case.hypotheses) == 1
        assert hyp.vuln_class == "idor"

    def test_validate_finding(self):
        validation_response = {
            "is_finding": True,
            "confidence": 0.85,
            "severity": "high",
            "title": "IDOR found",
            "description": "User ID can be changed",
            "impact": "Data leak",
            "remediation": "Add auth check",
            "false_positive_reason": "",
            "steps_to_reproduce": [],
        }
        mock_llm = make_mock_llm(validation_response)
        brain = ResearchBrain(target="https://example.com", llm_generate=mock_llm)

        evidence = {
            "vuln_class": "idor",
            "endpoint": "/api/users/1",
            "method": "GET",
            "evidence": [],
        }

        result = run_async(brain.validate_finding(evidence))
        assert result["is_finding"] is True
        assert len(brain.case.findings) >= 1

    def test_should_stop_max_iterations(self):
        mock_llm = make_mock_llm()
        brain = ResearchBrain(target="https://example.com", llm_generate=mock_llm)
        brain._iteration = 100
        brain._max_iterations = 100
        should_stop, reason = brain.should_stop()
        assert should_stop is True
        assert "Max iterations" in reason

    def test_should_stop_consecutive_failures(self):
        mock_llm = make_mock_llm()
        brain = ResearchBrain(target="https://example.com", llm_generate=mock_llm)
        brain._consecutive_failures = 10
        brain._max_consecutive_failures = 10
        should_stop, reason = brain.should_stop()
        assert should_stop is True
        assert "consecutive failures" in reason

    def test_get_stats(self):
        mock_llm = make_mock_llm()
        brain = ResearchBrain(target="https://example.com", llm_generate=mock_llm)
        brain.add_observation("Test", "test")
        brain.add_hypothesis("Test hyp")
        stats = brain.get_stats()
        assert stats["observations"] >= 1
        assert stats["hypotheses"] >= 1

    def test_get_case_summary(self):
        mock_llm = make_mock_llm()
        brain = ResearchBrain(target="https://example.com", llm_generate=mock_llm)
        brain.add_observation("Test", "test")
        summary = brain.get_case_summary()
        assert "example.com" in summary
        assert "RESEARCH CASE" in summary

    def test_save_load_case(self, tmp_path):
        mock_llm = make_mock_llm()
        brain = ResearchBrain(target="https://example.com", llm_generate=mock_llm)
        brain.add_observation("Test", "test")
        brain.add_hypothesis("Test hyp")

        path = str(tmp_path / "brain_case.json")
        brain.save_case(path)

        brain2 = ResearchBrain(target="https://other.com", llm_generate=mock_llm)
        brain2.load_case(path)
        assert brain2.target == "https://example.com"
        assert len(brain2.case.observations) >= 1


# ── Integration test ───────────────────────────────────────────

class TestPhase5Integration:
    def test_full_brain_cycle(self):
        """Test a complete reason → plan → execute → validate cycle."""
        # Setup brain
        mock_llm = make_mock_llm({
            "action": "test_idor",
            "target": "https://api.example.com/users/1",
            "reason": "IDOR on user endpoint",
            "confidence": 0.7,
            "priority": 0.8,
        })
        brain = ResearchBrain(
            target="https://example.com",
            llm_generate=mock_llm,
            tools=["httpx", "nuclei"],
        )
        run_async(brain.initialize())

        # Reason
        decision = run_async(brain.reason_next_action())
        assert decision.action == ActionType.TEST_IDOR

        # Add hypothesis
        hyp = brain.add_hypothesis(
            "IDOR on /api/users/{id}",
            "idor",
            "/api/users/{id}",
        )

        # Plan
        plan = run_async(brain.plan_experiment(hyp))
        assert "steps" in plan

        # Validate
        validation_response = {
            "is_finding": True,
            "confidence": 0.85,
            "severity": "high",
            "title": "IDOR confirmed",
            "description": "Can access other users' data",
            "impact": "Data leak",
            "remediation": "Add auth check",
            "false_positive_reason": "",
            "steps_to_reproduce": ["GET /api/users/other_id"],
        }
        brain._llm = make_mock_llm(validation_response)
        brain.validator._llm = make_mock_llm(validation_response)

        result = run_async(brain.validate_finding({
            "vuln_class": "idor",
            "endpoint": "/api/users/1",
            "method": "GET",
            "evidence": [],
        }))
        assert result["is_finding"] is True

        # Check stats
        stats = brain.get_stats()
        assert stats["findings"] >= 1
        assert stats["confirmed_findings"] >= 1