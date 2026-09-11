"""Tests for ScopeValidator, ResearchConfig, canonical domain models,
ContextBuilder, ExploitConfidenceEngine, Memory persistence, and Checkpoint."""

from __future__ import annotations

import pytest

from demogorgon.core.scope_legacy import ScopeValidator
from demogorgon.core.config import ResearchConfig
from demogorgon.core.context import ContextBuilder
from demogorgon.core.models import (
    Severity, HypothesisStatus, AttackFamily, ObjectState,
    Finding, Hypothesis, Endpoint, BusinessObject, Observation,
    TrustBoundary, AttackOpportunity, Experiment, FindingScore,
    ResearchAction, WorkflowStep, AttackSurface,
)


# ── ScopeValidator tests ────────────────────────────────────────

class TestScopeValidator:
    def test_exact_match(self):
        sv = ScopeValidator("https://example.com")
        assert sv.in_scope("https://example.com") is True

    def test_subdomain_match(self):
        sv = ScopeValidator("https://example.com")
        assert sv.in_scope("https://api.example.com") is True
        assert sv.in_scope("https://deep.sub.example.com") is True

    def test_subdomain_with_path_and_port(self):
        sv = ScopeValidator("https://example.com")
        assert sv.in_scope("https://api.example.com:8080/v1/data") is True

    def test_rejects_substring_match(self):
        sv = ScopeValidator("https://example.com")
        assert sv.in_scope("https://evil-example.com") is False
        assert sv.in_scope("https://notexample.com") is False
        assert sv.in_scope("https://example.com.evil.com") is False

    def test_bare_hostname(self):
        sv = ScopeValidator("https://example.com")
        assert sv.in_scope("api.example.com") is True
        assert sv.in_scope("evil-example.com") is False

    def test_case_insensitive(self):
        sv = ScopeValidator("https://Example.COM")
        assert sv.in_scope("https://API.example.com") is True

    def test_extra_scopes(self):
        sv = ScopeValidator("https://example.com", extra_scopes=["api.other.com"])
        assert sv.in_scope("https://api.other.com") is True
        assert sv.in_scope("https://sub.api.other.com") is True

    def test_excluded_hosts(self):
        sv = ScopeValidator(
            "https://example.com",
            excluded_hosts=["staging.example.com"],
        )
        assert sv.in_scope("https://staging.example.com") is False
        assert sv.in_scope("https://api.example.com") is True

    def test_ip_address_exact(self):
        sv = ScopeValidator("https://192.168.1.1")
        assert sv.in_scope("https://192.168.1.1") is True
        assert sv.in_scope("https://192.168.1.2") is False

    def test_empty_input(self):
        sv = ScopeValidator("https://example.com")
        assert sv.in_scope("") is False

    def test_all_hosts_property(self):
        sv = ScopeValidator("https://example.com", extra_scopes=["api.other.com"])
        assert sv.all_hosts == {"example.com", "api.other.com"}

    def test_target_host_property(self):
        sv = ScopeValidator("https://example.com/path")
        assert sv.target_host == "example.com"

    def test_rejects_root_domain(self):
        sv = ScopeValidator("https://sub.example.com")
        assert sv.in_scope("https://example.com") is False


# ── ResearchConfig tests ────────────────────────────────────────

class TestResearchConfig:
    def test_defaults(self):
        cfg = ResearchConfig()
        assert cfg.max_experiments == 50
        assert cfg.rate_limit_delay == 1.0
        assert cfg.headless is True
        assert cfg.proxy is None
        assert cfg.requests_per_second == 1.0

    def test_requests_per_second_calculation(self):
        cfg = ResearchConfig(rate_limit_delay=2.0)
        assert cfg.requests_per_second == 0.5

    def test_requests_per_second_minimum_floor(self):
        cfg = ResearchConfig(rate_limit_delay=0.0)
        assert cfg.requests_per_second == 10.0

    def test_with_overrides(self):
        cfg = ResearchConfig(target_url="https://example.com", max_experiments=10)
        cfg2 = cfg.with_overrides(max_experiments=100)
        assert cfg2.max_experiments == 100
        assert cfg2.target_url == "https://example.com"

    def test_with_overrides_ignores_unknown(self):
        cfg = ResearchConfig(target_url="https://example.com")
        cfg2 = cfg.with_overrides(unknown_field=42)
        assert cfg2.target_url == "https://example.com"

    def test_extra_scopes_default_empty(self):
        cfg = ResearchConfig()
        assert cfg.extra_scopes == []
        assert cfg.excluded_hosts == []


# ── Canonical Model tests ──────────────────────────────────────

class TestEnums:
    def test_severity_values(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.INFO.value == "info"

    def test_hypothesis_status_values(self):
        assert HypothesisStatus.PENDING.value == "pending"
        assert HypothesisStatus.ESCALATED.value == "escalated"

    def test_attack_family_values(self):
        assert AttackFamily.IDOR.value == "idor"
        assert AttackFamily.CHAIN.value == "chain"
        assert len(AttackFamily) == 16


class TestFinding:
    def test_defaults(self):
        f = Finding(title="XSS in search", severity=Severity.HIGH, vuln_class="xss", endpoint="/search")
        assert f.title == "XSS in search"
        assert f.severity == Severity.HIGH
        assert f.method == "GET"
        assert f.confidence == 0.0

    def test_severity_as_string(self):
        f = Finding(title="Info leak", severity="low", vuln_class="info", endpoint="/version")
        assert f.severity == "low"


class TestHypothesis:
    def test_defaults(self):
        h = Hypothesis(description="Test SQLi on login")
        assert h.description == "Test SQLi on login"
        assert h.status == HypothesisStatus.PENDING
        assert h.is_pending is True
        assert h.is_confirmed is False
        assert h.id  # auto-generated

    def test_confirmed_property(self):
        h = Hypothesis(status="confirmed")
        assert h.is_confirmed is True
        assert h.is_pending is False

    def test_string_status_backward_compat(self):
        h = Hypothesis(status="testing")
        assert h.status == "testing"
        assert h.is_pending is False
        assert h.is_confirmed is False

    def test_attack_family_field(self):
        h = Hypothesis(attack_family=AttackFamily.SSRF)
        assert h.attack_family == AttackFamily.SSRF


class TestEndpoint:
    def test_defaults(self):
        e = Endpoint(url="https://api.example.com/users")
        assert e.url == "https://api.example.com/users"
        assert e.method == "GET"
        assert e.tested is False


class TestBusinessObject:
    def test_sync_identifiers(self):
        bo = BusinessObject(object_type="user", object_id="123")
        assert bo.identifier == "123"
        assert bo.object_id == "123"

    def test_sync_reverse(self):
        bo = BusinessObject(object_type="order", identifier="ORD-456")
        assert bo.object_id == "ORD-456"
        assert bo.identifier == "ORD-456"

    def test_defaults(self):
        bo = BusinessObject()
        assert bo.object_type == ""
        assert bo.state == ObjectState.ACTIVE


class TestTrustBoundary:
    def test_defaults(self):
        tb = TrustBoundary(from_level="user", to_level="admin", boundary_type="role_escalation")
        assert tb.from_level == "user"
        assert tb.to_level == "admin"
        assert tb.bypass_techniques == []
        assert tb.test_generated is False


class TestExperiment:
    def test_defaults(self):
        exp = Experiment(hypothesis_id="h1", executor="sqli")
        assert exp.hypothesis_id == "h1"
        assert exp.status == "pending"
        assert exp.id  # auto-generated


class TestFindingScore:
    def test_defaults(self):
        fs = FindingScore(title="XSS reflected", severity=Severity.HIGH)
        assert fs.title == "XSS reflected"
        assert fs.should_report is False
        assert fs.final_confidence == 0.0


# ── ContextBuilder tests ────────────────────────────────────────

class TestContextBuilder:
    def test_empty_builder(self):
        cb = ContextBuilder(budget=1000)
        assert cb.build() == ""
        assert cb.remaining == 1000

    def test_single_section_fits(self):
        cb = ContextBuilder(budget=200)
        cb.add_section("target", "TARGET: https://example.com", priority=100)
        result = cb.build()
        assert "TARGET: https://example.com" in result

    def test_priority_ordering(self):
        cb = ContextBuilder(budget=150)
        cb.add_section("low", "Low priority content here", priority=10)
        cb.add_section("high", "High priority content here", priority=90)
        result = cb.build()
        # High priority should come first
        high_pos = result.index("High priority")
        low_pos = result.index("Low priority")
        assert high_pos < low_pos

    def test_budget_enforced(self):
        cb = ContextBuilder(budget=100)
        cb.add_section("a", "A" * 60, priority=10)
        cb.add_section("b", "B" * 60, priority=10)
        result = cb.build()
        assert len(result) <= 100 + 80  # budget + summary overhead

    def test_empty_sections_skipped(self):
        cb = ContextBuilder(budget=500)
        cb.add_section("empty", "", priority=100)
        cb.add_section("whitespace", "   ", priority=100)
        cb.add_section("real", "Real content", priority=50)
        result = cb.build()
        assert "Real content" in result
        assert "empty" not in result

    def test_chaining(self):
        cb = ContextBuilder(budget=500)
        result = cb.add_section("a", "AAA", priority=1).add_section("b", "BBB", priority=2).build()
        assert "AAA" in result
        assert "BBB" in result

    def test_no_mid_line_truncation(self):
        cb = ContextBuilder(budget=60)
        cb.add_section("data", "Line one\nLine two\nLine three", priority=10)
        result = cb.build()
        # Should include complete lines, not partial
        for line in result.split("\n"):
            if line.startswith("Line"):
                assert line.endswith(("one", "two", "three"))

    def test_usage_tracking(self):
        cb = ContextBuilder(budget=200)
        cb.add_section("test", "Hello world", priority=10)
        cb.build()
        assert cb.usage_percent > 0
        assert cb.remaining < 200


# ── ExploitConfidenceEngine tests ───────────────────────────────

class TestExploitConfidenceEngine:
    def test_high_severity_idor_with_evidence_reports(self):
        from demogorgon.are.exploit_confidence import ExploitConfidenceEngine
        engine = ExploitConfidenceEngine()
        score = engine.score_finding(
            finding_id="f1",
            title="IDOR in /api/users/{id}",
            severity="high",
            vuln_class="idor",
            endpoint="/api/users/123",
            evidence=[
                {"method": "GET", "url": "/api/users/123", "status": 200},
                {"method": "GET", "url": "/api/users/456", "status": 200},
            ],
            response_status=200,
            response_changed=True,
            has_screenshot=True,
            has_request_response=True,
        )
        assert score.should_report is True
        assert score.final_confidence >= 0.85

    def test_low_severity_info_does_not_report(self):
        from demogorgon.are.exploit_confidence import ExploitConfidenceEngine
        engine = ExploitConfidenceEngine()
        score = engine.score_finding(
            finding_id="f2",
            title="Server header reveals version",
            severity="info",
            vuln_class="info_disclosure",
            endpoint="/",
            evidence=[],
            response_status=200,
        )
        assert score.should_report is False
        assert score.final_confidence < 0.85

    def test_rank_findings(self):
        from demogorgon.are.exploit_confidence import ExploitConfidenceEngine
        engine = ExploitConfidenceEngine()
        s1 = engine.score_finding("f1", "Critical", "critical", "rce", "/exec",
                                   evidence=[{"method": "POST", "url": "/exec", "status": 200}],
                                   response_status=200, has_request_response=True)
        s2 = engine.score_finding("f2", "Low", "low", "info", "/",
                                   evidence=[], response_status=200)
        ranked = engine.rank_findings([s2, s1])
        assert ranked[0].finding_id == "f1"

    def test_reasoning_generated(self):
        from demogorgon.are.exploit_confidence import ExploitConfidenceEngine
        engine = ExploitConfidenceEngine()
        score = engine.score_finding("f1", "Test", "medium", "xss", "/search",
                                     evidence=[{"method": "GET", "url": "/search", "status": 200}],
                                     response_status=200)
        assert score.reasoning != ""
        assert score.evidence_score > 0

    def test_to_dict(self):
        from demogorgon.are.exploit_confidence import ExploitConfidenceEngine
        engine = ExploitConfidenceEngine()
        score = engine.score_finding("f1", "Test", "high", "xss", "/search")
        d = score.to_dict()
        assert d["finding_id"] == "f1"
        assert "final_confidence" in d
        assert "should_report" in d


# ── Memory persistence tests ────────────────────────────────────

class TestMemoryPersistence:
    def test_save_load_roundtrip(self, tmp_path):
        from demogorgon.memory import Memory
        out = str(tmp_path / "test_out")
        mem = Memory("https://example.com", output_dir=out)
        mem.add_endpoint("https://example.com/api/users", method="GET", status_code=200)
        mem.add_endpoint("https://example.com/api/admin", method="POST", status_code=403)
        mem.tech_stack = ["django", "react"]
        mem.current_user = "alice"
        mem.current_role = "admin"
        mem.save()

        loaded = Memory.load("https://example.com", output_dir=out)
        assert loaded is not None
        assert len(loaded.endpoints) == 2
        assert loaded.tech_stack == ["django", "react"]
        assert loaded.current_user == "alice"
        assert loaded.current_role == "admin"

    def test_load_nonexistent_returns_none(self, tmp_path):
        from demogorgon.memory import Memory
        loaded = Memory.load("https://nonexistent.com", output_dir=str(tmp_path / "nope"))
        assert loaded is None

    def test_save_findings_roundtrip(self, tmp_path):
        from demogorgon.memory import Memory
        out = str(tmp_path / "test_out2")
        mem = Memory("https://example.com", output_dir=out)
        mem.add_finding("XSS in search", "high", "xss", "/search", "GET",
                        "Reflected XSS in q parameter", [], "Can steal session cookies",
                        confidence=0.91)
        mem.save()

        loaded = Memory.load("https://example.com", output_dir=out)
        assert loaded is not None
        assert len(loaded.findings) == 1
        assert loaded.findings[0].title == "XSS in search"
        assert loaded.findings[0].confidence == 0.91


# ── Checkpoint tests ────────────────────────────────────────────

class TestCheckpoint:
    def test_save_load_roundtrip(self, tmp_path):
        from demogorgon.tools.checkpoint import Checkpoint
        cp = Checkpoint(checkpoint_dir=str(tmp_path / "cp1"))
        cp.update("experiment_count", 10)
        cp.update("finding_count", 3)
        cp.update("finding_scores", [{"id": "f1", "confidence": 0.91}])
        cp.save_sync()

        cp2 = Checkpoint(checkpoint_dir=str(tmp_path / "cp1"))
        assert cp2.load_sync() is True
        assert cp2.get("experiment_count") == 10
        assert cp2.get("finding_count") == 3
        assert cp2.get("finding_scores")[0]["confidence"] == 0.91

    def test_load_nonexistent_returns_false(self, tmp_path):
        from demogorgon.tools.checkpoint import Checkpoint
        cp = Checkpoint(checkpoint_dir=str(tmp_path / "cp_empty"))
        assert cp.load_sync() is False

    def test_recovery_plan(self, tmp_path):
        from demogorgon.tools.checkpoint import Checkpoint
        cp = Checkpoint(checkpoint_dir=str(tmp_path / "cp2"))
        cp.update("key", "value")
        plan = cp.recovery_plan()
        assert "key" in plan["keys"]
        assert plan["dirty"] is True

    def test_clear(self, tmp_path):
        from demogorgon.tools.checkpoint import Checkpoint
        cp = Checkpoint(checkpoint_dir=str(tmp_path / "cp3"))
        cp.update("key", "value")
        cp.save_sync()
        cp.clear()
        assert cp.get("key") is None
        plan = cp.recovery_plan()
        assert plan["has_checkpoint"] is False


# ── ARE module smoke tests ──────────────────────────────────────

class TestAREModules:
    def test_chain_finder(self):
        from demogorgon.are.chain_finder import ChainFinder
        cf = ChainFinder()
        cf.add_finding({"vuln_class": "idor", "endpoint": "/api/users/1", "severity": "high"})
        cf.add_finding({"vuln_class": "auth_bypass", "endpoint": "/api/admin", "severity": "critical"})
        summary = cf.get_chain_summary()
        assert "total_chains" in summary

    def test_attack_graph(self):
        from demogorgon.are.attack_graph import AttackGraph, Node, NodeType
        ag = AttackGraph()
        ag.add_node(Node(id="e1", name="/api/users", node_type=NodeType.ENDPOINT,
                         properties={"method": "GET"}))
        ag.add_node(Node(id="e2", name="/api/admin", node_type=NodeType.ENDPOINT,
                         properties={"method": "POST"}))
        s = ag.get_summary()
        assert s["total_nodes"] == 2

    def test_knowledge_base_stack_detection(self):
        from demogorgon.are.knowledge_base import KnowledgeBase
        kb = KnowledgeBase()
        stack = kb.detect_stack(
            headers={"server": "nginx", "x-powered-by": "Express"},
            body='<div id="__next">Hello</div>',
        )
        assert "nextjs" in stack or "express" in stack

    def test_mutation_intelligence(self):
        from demogorgon.are.mutation_intelligence import MutationIntelligence
        mi = MutationIntelligence()
        mutations = mi.get_mutations("user_id", "123")
        assert len(mutations) > 0
        assert "123" in mutations

    def test_knowledge_base_attack_plan(self):
        from demogorgon.are.knowledge_base import KnowledgeBase
        kb = KnowledgeBase()
        plan = kb.get_attack_plan(["django"])
        assert "common_vulns" in plan
        assert len(plan["common_vulns"]) > 0


# ── Integration smoke: CLI help ─────────────────────────────────

class TestCLI:
    def test_help_runs(self):
        import subprocess
        result = subprocess.run(
            ["python", "-m", "demogorgon", "--help"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0
        assert "demogorgon" in result.stdout.lower() or "usage" in result.stdout.lower()
