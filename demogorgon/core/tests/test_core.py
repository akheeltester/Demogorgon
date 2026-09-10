"""Tests for ScopeValidator and ResearchConfig."""

from __future__ import annotations

import pytest

from demogorgon.core.scope import ScopeValidator
from demogorgon.core.config import ResearchConfig


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
        # parent domain should NOT match
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
        assert cfg.requests_per_second == 10.0  # 1.0 / 0.1

    def test_with_overrides(self):
        cfg = ResearchConfig(target_url="https://example.com", max_experiments=10)
        cfg2 = cfg.with_overrides(max_experiments=100)
        assert cfg2.max_experiments == 100
        assert cfg2.target_url == "https://example.com"  # unchanged

    def test_with_overrides_ignores_unknown(self):
        cfg = ResearchConfig(target_url="https://example.com")
        cfg2 = cfg.with_overrides(unknown_field=42)
        assert cfg2.target_url == "https://example.com"

    def test_extra_scopes_default_empty(self):
        cfg = ResearchConfig()
        assert cfg.extra_scopes == []
        assert cfg.excluded_hosts == []
