"""Tests for Phase 6 components: PlanExecutor, EvidenceCollector, ResearchLoop."""

from __future__ import annotations

import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from demogorgon.core.research_loop.executor import PlanExecutor
from demogorgon.core.research_loop.evidence import EvidenceCollector, EvidenceItem
from demogorgon.core.research_loop.loop import ResearchLoop, LoopConfig
from demogorgon.core.research_loop.case import ResearchCase, HypothesisStatus
from demogorgon.core.interfaces import ActionType


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


# ── EvidenceItem tests ─────────────────────────────────────────

class TestEvidenceItem:
    def test_defaults(self):
        item = EvidenceItem()
        assert item.id
        assert item.type == ""
        assert item.description == ""
        assert item.request == {}
        assert item.response == {}
        assert item.confidence == 0.5

    def test_to_dict(self):
        item = EvidenceItem(
            type="http_request",
            description="Test request",
            request={"method": "GET", "url": "/test"},
            response={"status_code": 200},
            confidence=0.8,
        )
        d = item.to_dict()
        assert d["type"] == "http_request"
        assert d["request"]["method"] == "GET"
        assert d["confidence"] == 0.8

    def test_from_dict(self):
        data = {
            "id": "abc123",
            "type": "observation",
            "description": "Test obs",
            "confidence": 0.6,
        }
        item = EvidenceItem.from_dict(data)
        assert item.id == "abc123"
        assert item.type == "observation"
        assert item.confidence == 0.6


# ── EvidenceCollector tests ────────────────────────────────────

class TestEvidenceCollector:
    def test_add_evidence(self):
        collector = EvidenceCollector()
        item = collector.add_evidence(
            type="http_request",
            description="Test request",
            request={"method": "GET", "url": "/api/users"},
        )
        assert len(collector.get_all_evidence()) == 1
        assert item.type == "http_request"

    def test_add_http_evidence(self):
        collector = EvidenceCollector()
        item = collector.add_http_evidence(
            method="GET",
            url="https://api.example.com/users",
            status_code=200,
            response_body='{"users": []}',
        )
        assert item.request["method"] == "GET"
        assert item.response["status_code"] == 200

    def test_get_evidence_for_endpoint(self):
        collector = EvidenceCollector()
        collector.add_http_evidence("GET", "https://api.example.com/users", 200)
        collector.add_http_evidence("GET", "https://api.example.com/orders", 200)
        evidence = collector.get_evidence_for_endpoint("https://api.example.com/users")
        assert len(evidence) == 1

    def test_get_evidence_by_type(self):
        collector = EvidenceCollector()
        collector.add_evidence(type="http_request", description="Req 1")
        collector.add_evidence(type="observation", description="Obs 1")
        collector.add_evidence(type="http_request", description="Req 2")
        http_evidence = collector.get_evidence_by_type("http_request")
        assert len(http_evidence) == 2

    def test_get_request_response_pairs(self):
        collector = EvidenceCollector()
        collector.add_http_evidence("GET", "/test", 200)
        pairs = collector.get_request_response_pairs()
        assert len(pairs) == 1
        assert pairs[0]["request"]["method"] == "GET"

    def test_package_for_validation(self):
        collector = EvidenceCollector()
        collector.add_http_evidence("GET", "https://api.example.com/users/1", 200)
        package = collector.package_for_validation("idor", "https://api.example.com/users/1")
        assert package["vuln_class"] == "idor"
        assert package["endpoint"] == "https://api.example.com/users/1"
        assert len(package["evidence"]) >= 1

    def test_clear(self):
        collector = EvidenceCollector()
        collector.add_evidence(type="test", description="Test")
        assert len(collector.get_all_evidence()) == 1
        collector.clear()
        assert len(collector.get_all_evidence()) == 0

    def test_get_summary(self):
        collector = EvidenceCollector()
        collector.add_http_evidence("GET", "/a", 200)
        collector.add_http_evidence("GET", "/b", 200)
        summary = collector.get_summary()
        assert summary["total_items"] == 2
        assert summary["endpoints_covered"] == 2

    def test_save_load_roundtrip(self, tmp_path):
        collector = EvidenceCollector()
        collector.add_http_evidence("GET", "/test", 200)
        path = str(tmp_path / "evidence.json")
        collector.save(path)

        collector2 = EvidenceCollector()
        collector2.load(path)
        assert len(collector2.get_all_evidence()) == 1


# ── PlanExecutor tests ─────────────────────────────────────────

class TestPlanExecutor:
    def test_init(self):
        executor = PlanExecutor()
        assert executor._http is None
        assert executor._tools is None

    def test_execute_empty_plan(self):
        executor = PlanExecutor()
        result = run_async(executor.execute({"steps": []}))
        assert result["success"] is True
        assert result["evidence"] == []

    def test_execute_plan_with_steps(self):
        mock_http = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}
        mock_response.text = '{"users": []}'
        mock_response.content = b'{"users": []}'
        mock_http.get = AsyncMock(return_value=mock_response)

        executor = PlanExecutor(http_client=mock_http, rate_limit_delay=0)
        plan = {
            "steps": [
                {"step": 1, "action": "send_request", "target": "https://api.example.com/users", "method": "GET"},
            ],
            "preconditions": [],
        }

        result = run_async(executor.execute(plan))
        assert result["success"] is True
        assert len(result["evidence"]) == 1
        assert result["evidence"][0]["response"]["status_code"] == 200

    def test_execute_plan_with_precondition_failure(self):
        executor = PlanExecutor()
        plan = {
            "steps": [],
            "preconditions": ["Authentication required"],
        }

        # No auth headers, precondition should fail
        result = run_async(executor.execute(plan))
        assert result["success"] is False
        assert "Precondition failed" in result["error"]

    def test_execute_plan_with_auth_precondition(self):
        executor = PlanExecutor(auth_headers={"Authorization": "Bearer token"})
        plan = {
            "steps": [],
            "preconditions": ["Authentication required"],
        }

        result = run_async(executor.execute(plan))
        assert result["success"] is True

    def test_execute_tool_call(self):
        mock_tools = AsyncMock()
        mock_tools.execute_tool = AsyncMock(return_value={"result": "success"})

        executor = PlanExecutor(tool_executor=mock_tools)
        plan = {
            "steps": [
                {"step": 1, "action": "tool", "tool": "nuclei", "tool_action": "scan", "params": {"target": "http://example.com"}},
            ],
        }

        result = run_async(executor.execute(plan))
        assert result["success"] is True
        assert len(result["evidence"]) == 1


# ── LoopConfig tests ───────────────────────────────────────────

class TestLoopConfig:
    def test_defaults(self):
        config = LoopConfig()
        assert config.max_iterations == 100
        assert config.max_consecutive_failures == 10
        assert config.stagnation_threshold == 5

    def test_custom(self):
        config = LoopConfig(max_iterations=50, rate_limit_delay=0.5)
        assert config.max_iterations == 50
        assert config.rate_limit_delay == 0.5


# ── ResearchLoop tests ─────────────────────────────────────────

class TestResearchLoop:
    def test_init(self):
        mock_llm = make_mock_llm()
        loop = ResearchLoop(
            target="https://example.com",
            llm_generate=mock_llm,
            tools=["httpx", "nuclei"],
        )
        assert loop.target == "https://example.com"
        assert loop.brain.target == "https://example.com"

    def test_initialize(self):
        mock_llm = make_mock_llm()
        loop = ResearchLoop(target="https://example.com", llm_generate=mock_llm)
        run_async(loop.initialize())
        assert len(loop.brain.case.observations) >= 1

    def test_get_status(self):
        mock_llm = make_mock_llm()
        loop = ResearchLoop(target="https://example.com", llm_generate=mock_llm)
        status = loop.get_status()
        assert status["target"] == "https://example.com"
        assert status["iteration"] == 0
        assert status["strategy"] == "explore"

    def test_stopping_conditions_max_iterations(self):
        mock_llm = make_mock_llm()
        config = LoopConfig(max_iterations=5)
        loop = ResearchLoop(
            target="https://example.com",
            llm_generate=mock_llm,
            config=config,
        )
        loop._iteration = 5
        should_stop, reason = loop._check_stopping_conditions()
        assert should_stop is True
        assert "Max iterations" in reason

    def test_stopping_conditions_consecutive_failures(self):
        mock_llm = make_mock_llm()
        config = LoopConfig(max_consecutive_failures=3)
        loop = ResearchLoop(
            target="https://example.com",
            llm_generate=mock_llm,
            config=config,
        )
        loop._consecutive_failures = 3
        should_stop, reason = loop._check_stopping_conditions()
        assert should_stop is True
        assert "consecutive failures" in reason

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
        assert should_stop is False
        assert loop._strategy == "validate"
        assert loop._stagnation_count == 0

    def test_generate_report(self):
        mock_llm = make_mock_llm()
        loop = ResearchLoop(target="https://example.com", llm_generate=mock_llm)
        loop._iteration = 5
        report = loop._generate_report()
        assert report["target"] == "https://example.com"
        assert report["iterations"] == 5
        assert "stats" in report
        assert "evidence" in report


# ── Integration test ───────────────────────────────────────────

class TestPhase6Integration:
    def test_full_loop_cycle(self):
        """Test a complete loop cycle with mocked components."""
        # Mock LLM to return stop after first iteration
        call_count = 0

        async def mock_llm(messages, response_format=None):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                # First calls are for reasoning
                return {"content": json.dumps({
                    "action": "stop",
                    "target": "",
                    "reason": "Test complete",
                    "confidence": 1.0,
                    "priority": 1.0,
                })}
            return {"content": json.dumps({
                "is_finding": False,
                "confidence": 0.3,
                "severity": "info",
                "title": "",
                "description": "No finding",
                "impact": "",
                "remediation": "",
                "false_positive_reason": "Test",
                "steps_to_reproduce": [],
            })}

        config = LoopConfig(max_iterations=3)
        loop = ResearchLoop(
            target="https://example.com",
            llm_generate=mock_llm,
            config=config,
        )
        run_async(loop.initialize())

        # Run the loop (should stop quickly due to mock)
        report = run_async(loop.run())

        assert report["target"] == "https://example.com"
        assert report["iterations"] >= 1

    def test_evidence_collection_flow(self):
        """Test evidence collection through the loop."""
        collector = EvidenceCollector()
        collector.add_http_evidence("GET", "https://api.example.com/users/1", 200)
        collector.add_http_evidence("GET", "https://api.example.com/users/2", 200)

        package = collector.package_for_validation("idor", "https://api.example.com/users/1")
        assert package["vuln_class"] == "idor"
        assert len(package["evidence"]) >= 1
        assert "request_response" in package