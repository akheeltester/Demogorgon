"""Tests for ScopeValidator, ResearchConfig, and canonical domain models."""

from __future__ import annotations

import pytest

from demogorgon.core.scope import ScopeValidator
from demogorgon.core.config import ResearchConfig
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
