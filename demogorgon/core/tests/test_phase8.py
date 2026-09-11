"""Tests for Phase 8: Evidence + Chains + Validation."""

from __future__ import annotations

import asyncio
import json
import pytest

from demogorgon.core.evidence.types import (
    EvidenceItem,
    EvidenceType,
    EvidenceRequest,
    EvidenceResponse,
)
from demogorgon.core.evidence.packager import EvidencePackager, PackagedEvidence
from demogorgon.core.chains.detector import BugChainDetector, BugChain, ChainStep, ChainLink
from demogorgon.core.validation.pipeline import (
    ValidationPipeline,
    ValidationResult,
    ValidationGate,
)


def run_async(coro):
    """Run an async function synchronously for testing."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ── Evidence types tests ───────────────────────────────────────

class TestEvidenceTypes:
    def test_evidence_request_roundtrip(self):
        req = EvidenceRequest(
            method="GET",
            url="https://api.example.com/users",
            headers={"Authorization": "Bearer tok"},
            body="",
        )
        d = req.to_dict()
        restored = EvidenceRequest.from_dict(d)
        assert restored.method == "GET"
        assert restored.url == "https://api.example.com/users"

    def test_evidence_response_roundtrip(self):
        resp = EvidenceResponse(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body='{"users": []}',
            response_time_ms=150.5,
        )
        d = resp.to_dict()
        restored = EvidenceResponse.from_dict(d)
        assert restored.status_code == 200
        assert restored.body == '{"users": []}'

    def test_evidence_item_roundtrip(self):
        item = EvidenceItem(
            type=EvidenceType.HTTP_REQUEST,
            description="Test request",
            request=EvidenceRequest(method="POST", url="/test"),
            response=EvidenceResponse(status_code=201),
            confidence=0.8,
            tags=["idor", "api"],
        )
        d = item.to_dict()
        restored = EvidenceItem.from_dict(d)
        assert restored.type == EvidenceType.HTTP_REQUEST
        assert restored.confidence == 0.8
        assert "idor" in restored.tags


# ── EvidencePackager tests ─────────────────────────────────────

class TestEvidencePackager:
    def test_package_basic(self):
        packager = EvidencePackager()
        items = [
            EvidenceItem(
                type=EvidenceType.HTTP_REQUEST,
                request=EvidenceRequest(method="GET", url="/api/users/1"),
                response=EvidenceResponse(status_code=200, body='{"id": 1}'),
            )
        ]
        result = packager.package("idor", items, endpoint="/api/users/1")
        assert result.vuln_class == "idor"
        assert len(result.request_response_pairs) == 1
        assert len(result.reproduction_steps) == 1

    def test_package_from_http(self):
        packager = EvidencePackager()
        result = packager.package_from_http(
            vuln_class="xss",
            method="GET",
            url="https://example.com/search?q=<script>alert(1)</script>",
            status_code=200,
            response_body='<script>alert(1)</script>',
        )
        assert result.vuln_class == "xss"
        assert len(result.request_response_pairs) == 1

    def test_package_multiple_items(self):
        packager = EvidencePackager()
        items = [
            EvidenceItem(
                type=EvidenceType.HTTP_REQUEST,
                request=EvidenceRequest(method="GET", url="/users/1"),
                response=EvidenceResponse(status_code=200),
            ),
            EvidenceItem(
                type=EvidenceType.HTTP_REQUEST,
                request=EvidenceRequest(method="GET", url="/users/2"),
                response=EvidenceResponse(status_code=200),
            ),
        ]
        result = packager.package("idor", items, endpoint="/users/1")
        assert len(result.raw_evidence) == 2

    def test_save_load_roundtrip(self, tmp_path):
        packager = EvidencePackager(workspace_dir=str(tmp_path))
        items = [
            EvidenceItem(
                type=EvidenceType.HTTP_REQUEST,
                request=EvidenceRequest(method="GET", url="/test"),
                response=EvidenceResponse(status_code=200),
            )
        ]
        packaged = packager.package("xss", items, endpoint="/test")
        path = packager.save(packaged, str(tmp_path / "test_evidence.json"))
        loaded = packager.load(path)
        assert loaded.vuln_class == "xss"

    def test_get_summary(self):
        packager = EvidencePackager()
        packaged = PackagedEvidence(
            vuln_class="ssrf",
            endpoint="/api/proxy",
            method="GET",
            severity="high",
        )
        summary = packager.get_summary(packaged)
        assert "SSRF" in summary
        assert "/api/proxy" in summary


# ── BugChain tests ─────────────────────────────────────────────

class TestBugChain:
    def test_chain_to_dict(self):
        chain = BugChain(
            name="OAuth Token Theft",
            steps=[
                ChainStep(vuln_class="open_redirect", endpoint="/redirect", description="Open redirect"),
                ChainStep(vuln_class="token_theft", endpoint="/oauth/callback", description="Token theft"),
                ChainStep(vuln_class="account_takeover", endpoint="/account", description="ATO"),
            ],
            links=[
                ChainLink(source_step=0, target_step=1, relationship="enables"),
                ChainLink(source_step=1, target_step=2, relationship="leads_to"),
            ],
            severity="critical",
            confidence=0.8,
        )
        d = chain.to_dict()
        assert len(d["steps"]) == 3
        assert len(d["links"]) == 2
        assert d["severity"] == "critical"

    def test_get_attack_path(self):
        chain = BugChain(
            steps=[
                ChainStep(vuln_class="xss", endpoint="/search", description="XSS"),
                ChainStep(vuln_class="session_hijack", endpoint="/session", description="Session hijack"),
            ],
            links=[
                ChainLink(source_step=0, target_step=1, relationship="enables"),
            ],
        )
        path = chain.get_attack_path()
        assert "xss" in path
        assert "session_hijack" in path

    def test_severity_score(self):
        chain = BugChain(
            steps=[
                ChainStep(vuln_class="a", endpoint="/a", description="A"),
                ChainStep(vuln_class="b", endpoint="/b", description="B"),
                ChainStep(vuln_class="c", endpoint="/c", description="C"),
            ],
            confidence=0.8,
            is_known_pattern=True,
        )
        score = chain.get_severity_score()
        assert score >= 8.0


# ── BugChainDetector tests ─────────────────────────────────────

class TestBugChainDetector:
    def test_detect_known_chain(self):
        detector = BugChainDetector()
        observations = [
            {"vuln_class": "open_redirect", "endpoint": "/redirect", "confidence": 0.7},
            {"vuln_class": "token_theft", "endpoint": "/oauth", "confidence": 0.6},
            {"vuln_class": "account_takeover", "endpoint": "/account", "confidence": 0.8},
        ]
        chains = detector.detect_chains(observations)
        assert len(chains) >= 1
        assert any("OAuth Token Theft" in c.name for c in chains)

    def test_detect_ad_hoc_chain(self):
        detector = BugChainDetector()
        observations = [
            {"vuln_class": "info_disclosure", "endpoint": "/debug", "confidence": 0.7},
            {"vuln_class": "xss", "endpoint": "/search", "confidence": 0.8},
        ]
        chains = detector.detect_chains(observations)
        assert len(chains) >= 1

    def test_no_chain_single_vuln(self):
        detector = BugChainDetector()
        observations = [
            {"vuln_class": "xss", "endpoint": "/search", "confidence": 0.8},
        ]
        chains = detector.detect_chains(observations)
        # Single vuln shouldn't form a chain
        assert all(len(c.steps) >= 2 for c in chains) or len(chains) == 0

    def test_empty_observations(self):
        detector = BugChainDetector()
        chains = detector.detect_chains([])
        assert chains == []

    def test_known_pattern_flag(self):
        detector = BugChainDetector()
        observations = [
            {"vuln_class": "ssrf", "endpoint": "/proxy", "confidence": 0.7},
            {"vuln_class": "info_disclosure", "endpoint": "/internal", "confidence": 0.6},
            {"vuln_class": "rce", "endpoint": "/exec", "confidence": 0.8},
        ]
        chains = detector.detect_chains(observations)
        known = [c for c in chains if c.is_known_pattern]
        assert len(known) >= 1

    def test_custom_patterns(self):
        custom = [("xss", "cookie_theft", "account_takeover", "Custom XSS Chain")]
        detector = BugChainDetector(custom_patterns=custom)
        observations = [
            {"vuln_class": "xss", "endpoint": "/search"},
            {"vuln_class": "cookie_theft", "endpoint": "/cookie"},
            {"vuln_class": "account_takeover", "endpoint": "/account"},
        ]
        chains = detector.detect_chains(observations)
        custom_chains = [c for c in chains if "Custom" in c.name]
        assert len(custom_chains) >= 1


# ── ValidationPipeline tests ───────────────────────────────────

class TestValidationPipeline:
    def test_valid_evidence(self):
        pipeline = ValidationPipeline(min_confidence=0.3)
        evidence = {
            "vuln_class": "idor",
            "endpoint": "https://api.example.com/users/1",
            "request_response_pairs": [
                {
                    "request": {"method": "GET", "url": "/users/1"},
                    "response": {"status_code": 200, "body": '{"id": 1, "name": "test"}'},
                }
            ],
            "reproduction_steps": ["GET /users/1 → 200"],
        }
        result = run_async(pipeline.validate(evidence, confidence=0.7))
        assert result["is_valid"] is True
        assert result["final_confidence"] > 0.5

    def test_fp_detection(self):
        pipeline = ValidationPipeline(min_confidence=0.3)
        evidence = {
            "vuln_class": "xss",
            "endpoint": "/test",
            "request_response_pairs": [
                {
                    "request": {"method": "GET", "url": "/test"},
                    "response": {
                        "status_code": 403,
                        "body": "Access Denied. 403 Forbidden. Rate limit exceeded. Server Error 500.",
                    },
                }
            ],
        }
        result = run_async(pipeline.validate(evidence, confidence=0.5))
        assert len(result["fp_reasons"]) >= 2

    def test_tp_detection(self):
        pipeline = ValidationPipeline(min_confidence=0.3)
        evidence = {
            "vuln_class": "ssrf",
            "endpoint": "/proxy",
            "request_response_pairs": [
                {
                    "request": {"method": "GET", "url": "/proxy?url=http://169.254.169.254/latest/meta-data"},
                    "response": {
                        "status_code": 200,
                        "body": "ami-id: ami-12345\ninstance-id: i-12345\n169.254.169.254",
                    },
                }
            ],
        }
        result = run_async(pipeline.validate(evidence, confidence=0.6))
        assert len(result["tp_indicators"]) >= 1

    def test_low_confidence_blocked(self):
        pipeline = ValidationPipeline(min_confidence=0.5)
        evidence = {
            "vuln_class": "info",
            "endpoint": "/test",
            "request_response_pairs": [],
            "raw_evidence": [],
        }
        result = run_async(pipeline.validate(evidence, confidence=0.1))
        assert result["is_valid"] is False

    def test_severity_recommendation(self):
        pipeline = ValidationPipeline(min_confidence=0.3)
        evidence = {
            "vuln_class": "rce",
            "endpoint": "/exec",
            "request_response_pairs": [
                {
                    "request": {"method": "POST", "url": "/exec"},
                    "response": {"status_code": 200, "body": "root:x:0:0"},
                }
            ],
        }
        result = run_async(pipeline.validate(evidence, confidence=0.9))
        assert result["recommended_severity"] == "critical"

    def test_scope_check(self):
        pipeline = ValidationPipeline(min_confidence=0.3)
        evidence = {
            "vuln_class": "xss",
            "endpoint": "https://other.com/search",
            "request_response_pairs": [
                {"request": {"method": "GET", "url": "/search"}, "response": {"status_code": 200, "body": "xss"}}
            ],
        }
        context = {"scope": ["https://target.com"]}
        result = run_async(pipeline.validate(evidence, confidence=0.7, context=context))
        scope_gate = [g for g in result["gates"] if g["gate"] == "scope"]
        assert scope_gate[0]["passed"] is False

    def test_skip_gates(self):
        pipeline = ValidationPipeline(
            min_confidence=0.3,
            skip_gates=[ValidationGate.SANITY, ValidationGate.CONFIDENCE],
        )
        evidence = {
            "vuln_class": "xss",
            "endpoint": "",
            "request_response_pairs": [],
        }
        result = run_async(pipeline.validate(evidence, confidence=0.1))
        skipped = {g["gate"] for g in result["gates"]}
        assert "sanity" not in skipped
        assert "confidence" not in skipped


# ── Integration tests ──────────────────────────────────────────

class TestPhase8Integration:
    def test_full_validation_flow(self):
        """Test complete evidence → chain → validation flow."""
        # 1. Collect evidence
        packager = EvidencePackager()
        items = [
            EvidenceItem(
                type=EvidenceType.HTTP_REQUEST,
                request=EvidenceRequest(method="GET", url="https://api.example.com/admin/users/1"),
                response=EvidenceResponse(status_code=200, body='{"admin": true}'),
            )
        ]
        packaged = packager.package("idor", items, endpoint="/admin/users/1")

        # 2. Detect chains
        detector = BugChainDetector()
        observations = [
            {"vuln_class": "idor", "endpoint": "/admin/users/1", "confidence": 0.8},
            {"vuln_class": "privilege_escalation", "endpoint": "/admin", "confidence": 0.7},
        ]
        chains = detector.detect_chains(observations)

        # 3. Validate
        pipeline = ValidationPipeline(min_confidence=0.3)
        evidence = packaged.to_dict()
        result = run_async(pipeline.validate(evidence, confidence=0.8))

        assert result["is_valid"] is True
        assert result["final_confidence"] > 0.5

    def test_chain_severity_escalation(self):
        """Test that longer chains have higher severity."""
        detector = BugChainDetector()
        obs = [
            {"vuln_class": "open_redirect", "endpoint": "/redir"},
            {"vuln_class": "token_theft", "endpoint": "/oauth"},
            {"vuln_class": "account_takeover", "endpoint": "/account"},
        ]
        chains = detector.detect_chains(obs)
        if chains:
            assert chains[0].severity in ("high", "critical")
