"""Tests for Phase 9: State + Reporting."""

from __future__ import annotations

import json
import os
import pytest

from demogorgon.core.state.manager import StateManager, EngagementState
from demogorgon.core.reporting.generator import ReportGenerator, Report, Finding


# ── EngagementState tests ──────────────────────────────────────

class TestEngagementState:
    def test_defaults(self):
        state = EngagementState()
        assert state.status == "active"
        assert state.iteration == 0
        assert state.strategy == "explore"

    def test_roundtrip(self):
        state = EngagementState(
            engagement_id="eng-123",
            target="https://example.com",
            iteration=42,
            strategy="validate",
            findings_count=3,
        )
        d = state.to_dict()
        restored = EngagementState.from_dict(d)
        assert restored.engagement_id == "eng-123"
        assert restored.iteration == 42
        assert restored.findings_count == 3


# ── StateManager tests ─────────────────────────────────────────

class TestStateManager:
    def test_initialize(self, tmp_path):
        sm = StateManager(str(tmp_path))
        state = sm.initialize("eng-001", "https://example.com")
        assert state.engagement_id == "eng-001"
        assert state.target == "https://example.com"
        assert os.path.exists(tmp_path / "state.json")
        assert os.path.exists(tmp_path / "checkpoints")
        assert os.path.exists(tmp_path / "evidence")

    def test_save_load_state(self, tmp_path):
        sm = StateManager(str(tmp_path))
        state = sm.initialize("eng-001", "https://example.com")
        state.iteration = 10
        state.findings_count = 2
        sm.save_state(state)

        loaded = sm.load_state()
        assert loaded is not None
        assert loaded.iteration == 10
        assert loaded.findings_count == 2

    def test_load_nonexistent(self, tmp_path):
        sm = StateManager(str(tmp_path))
        assert sm.load_state() is None

    def test_save_load_case(self, tmp_path):
        sm = StateManager(str(tmp_path))
        case_data = {"observations": [], "hypotheses": []}
        sm.save_case(case_data)
        loaded = sm.load_case()
        assert loaded is not None
        assert "observations" in loaded

    def test_save_load_checkpoint(self, tmp_path):
        sm = StateManager(str(tmp_path))
        path = sm.save_checkpoint(5, {"iteration": 5, "data": "test"})
        assert os.path.exists(path)

        loaded = sm.load_checkpoint(5)
        assert loaded is not None
        assert loaded["iteration"] == 5

    def test_get_latest_checkpoint(self, tmp_path):
        sm = StateManager(str(tmp_path))
        sm.save_checkpoint(1, {"iter": 1})
        sm.save_checkpoint(5, {"iter": 5})
        sm.save_checkpoint(3, {"iter": 3})

        result = sm.get_latest_checkpoint()
        assert result is not None
        iteration, data = result
        assert iteration == 5

    def test_list_checkpoints(self, tmp_path):
        sm = StateManager(str(tmp_path))
        sm.save_checkpoint(1, {})
        sm.save_checkpoint(2, {})
        sm.save_checkpoint(3, {})
        iterations = sm.list_checkpoints()
        assert iterations == [1, 2, 3]

    def test_cleanup_checkpoints(self, tmp_path):
        sm = StateManager(str(tmp_path))
        for i in range(10):
            sm.save_checkpoint(i, {})
        removed = sm.cleanup_checkpoints(keep_last=3)
        assert removed == 7
        assert len(sm.list_checkpoints()) == 3

    def test_summary(self, tmp_path):
        sm = StateManager(str(tmp_path))
        sm.initialize("eng-001", "https://example.com")
        sm.save_checkpoint(1, {})
        summary = sm.get_summary()
        assert summary["has_state"] is True
        assert summary["checkpoint_count"] == 1


# ── Finding tests ──────────────────────────────────────────────

class TestFinding:
    def test_finding_to_dict(self):
        finding = Finding(
            title="IDOR on User API",
            severity="high",
            vuln_class="idor",
            endpoint="/api/users/1",
            method="GET",
            description="User data accessible via IDOR",
            reproduction_steps=["GET /api/users/1", "Observe user data"],
        )
        d = finding.to_dict()
        assert d["title"] == "IDOR on User API"
        assert d["severity"] == "high"
        assert len(d["reproduction_steps"]) == 2


# ── Report tests ───────────────────────────────────────────────

class TestReport:
    def test_report_totals(self):
        report = Report(findings=[
            Finding(severity="high"),
            Finding(severity="high"),
            Finding(severity="medium"),
            Finding(severity="low"),
        ])
        assert report.total_findings == 4
        assert report.severity_counts == {"high": 2, "medium": 1, "low": 1}

    def test_report_roundtrip(self):
        report = Report(
            target="https://example.com",
            program="Example Bug Bounty",
            findings=[
                Finding(title="XSS", severity="high", vuln_class="xss"),
            ],
        )
        d = report.to_dict()
        restored = Report.from_dict(d)
        assert restored.target == "https://example.com"
        assert len(restored.findings) == 1

    def test_report_json(self):
        report = Report(
            target="https://example.com",
            findings=[Finding(title="Test", severity="medium")],
        )
        j = report.to_json()
        data = json.loads(j)
        assert data["target"] == "https://example.com"


# ── ReportGenerator tests ──────────────────────────────────────

class TestReportGenerator:
    def test_generate(self):
        gen = ReportGenerator()
        findings = [
            Finding(title="XSS", severity="high", vuln_class="xss", endpoint="/search"),
            Finding(title="IDOR", severity="medium", vuln_class="idor", endpoint="/api/users"),
        ]
        report = gen.generate(findings, target="https://example.com", program="TestBB")
        assert report.total_findings == 2
        assert report.target == "https://example.com"

    def test_save_json(self, tmp_path):
        gen = ReportGenerator(workspace_dir=str(tmp_path))
        findings = [Finding(title="Test", severity="low")]
        report = gen.generate(findings, target="https://example.com")
        path = gen.save_json(report)
        assert os.path.exists(path)
        with open(path) as f:
            data = json.load(f)
        assert data["target"] == "https://example.com"

    def test_save_markdown(self, tmp_path):
        gen = ReportGenerator(workspace_dir=str(tmp_path))
        findings = [
            Finding(
                title="Critical SSRF",
                severity="critical",
                vuln_class="ssrf",
                endpoint="/api/proxy",
                method="GET",
                description="SSRF to cloud metadata",
                impact="Full server compromise",
                remediation="Validate URLs",
                reproduction_steps=["GET /api/proxy?url=http://169.254.169.254"],
            )
        ]
        report = gen.generate(findings, target="https://example.com")
        path = gen.save_markdown(report)
        assert os.path.exists(path)
        with open(path) as f:
            content = f.read()
        assert "Critical SSRF" in content
        assert "SSRF" in content.upper()

    def test_get_summary(self):
        gen = ReportGenerator()
        report = Report(
            target="https://example.com",
            findings=[
                Finding(severity="critical"),
                Finding(severity="high"),
                Finding(severity="high"),
            ],
        )
        summary = gen.get_summary(report)
        assert "3" in summary
        assert "critical" in summary


# ── Integration tests ──────────────────────────────────────────

class TestPhase9Integration:
    def test_full_state_report_flow(self, tmp_path):
        """Test complete state → findings → report flow."""
        # 1. Initialize state
        sm = StateManager(str(tmp_path))
        state = sm.initialize("eng-001", "https://example.com")

        # 2. Simulate research
        state.iteration = 25
        state.findings_count = 2
        state.evidence_count = 10
        sm.save_state(state)

        # 3. Save checkpoint
        sm.save_checkpoint(25, {"case": "data"})

        # 4. Create report
        gen = ReportGenerator(workspace_dir=str(tmp_path))
        findings = [
            Finding(
                title="IDOR on User API",
                severity="high",
                vuln_class="idor",
                endpoint="/api/users/1",
                method="GET",
                description="User data accessible via IDOR",
                impact="Data breach",
                reproduction_steps=["GET /api/users/1"],
            ),
            Finding(
                title="XSS in Search",
                severity="medium",
                vuln_class="xss",
                endpoint="/search",
                method="GET",
            ),
        ]
        report = gen.generate(findings, target="https://example.com")

        # 5. Save reports
        json_path = gen.save_json(report)
        md_path = gen.save_markdown(report)
        assert os.path.exists(json_path)
        assert os.path.exists(md_path)

        # 6. Verify state persistence
        loaded_state = sm.load_state()
        assert loaded_state.iteration == 25
        assert loaded_state.findings_count == 2

        # 7. Verify checkpoints
        checkpoints = sm.list_checkpoints()
        assert 25 in checkpoints
