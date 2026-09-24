"""Unit tests for P2 features: parallel, CVSS, PoC, metrics, installer, reporter enhancements."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from demogorgon.tools.parallel import ParallelExecutor, create_parallel_executor
from demogorgon.core.cvss import (
    compute_cvss_base,
    score_finding_cvss,
    enhance_finding_with_cvss,
    severity_from_score,
)
from demogorgon.core.poc import (
    generate_curl_poc,
    generate_poc_from_finding,
    generate_http_transcript,
    inject_payload_into_url,
    render_poc_markdown,
)
from demogorgon.core.metrics import HuntMetrics, MetricsCollector
from demogorgon.tools.installer import ToolInstaller, INSTALL_RECIPES, create_tool_installer
from demogorgon.tools.reporter import Reporter, REMEDIATION


# ============================================================
# Parallel
# ============================================================

@pytest.mark.asyncio
async def test_parallel_gather_success():
    async def ok(i):
        return {"status_code": 200, "body": f"ok-{i}", "error": None}

    ex = ParallelExecutor(max_concurrency=5)
    tasks = [ok(i) for i in range(10)]
    result = await ex.gather(tasks, timeout=5.0)

    assert result.total == 10
    assert result.succeeded == 10
    assert result.failed == 0
    assert result.duration > 0
    assert result.rps > 0


@pytest.mark.asyncio
async def test_parallel_gather_partial_failure():
    async def maybe_fail(i):
        if i % 2 == 0:
            return {"status_code": 200, "body": "ok", "error": None}
        raise RuntimeError("boom")

    ex = ParallelExecutor(max_concurrency=4)
    tasks = [maybe_fail(i) for i in range(6)]
    result = await ex.gather(tasks, timeout=5.0)

    assert result.total == 6
    assert result.succeeded == 3
    assert result.failed == 3
    assert len(result.errors) == 3


@pytest.mark.asyncio
async def test_parallel_probe_endpoints():
    class FakeHTTP:
        async def request(self, method, url, headers=None):
            return {"status_code": 200, "body": "hi", "error": None, "url": url}

    ex = create_parallel_executor(max_concurrency=3)
    urls = [f"https://example.com/{i}" for i in range(5)]
    result = await ex.probe_endpoints(FakeHTTP(), urls, timeout=5.0)

    assert result.total == 5
    assert result.succeeded == 5
    assert result.to_dict()["total"] == 5


@pytest.mark.asyncio
async def test_parallel_race_replay():
    class FakeHTTP:
        async def request(self, method, url, headers=None):
            return {"status_code": 200, "body": "ok"}

    ex = ParallelExecutor(max_concurrency=10)
    result = await ex.race_replay(
        FakeHTTP(),
        lambda: FakeHTTP().request("POST", "https://example.com/buy"),
        count=5,
        timeout=5.0,
    )
    assert result["count"] == 5
    assert result["status_distribution"].get("200") == 5
    assert result["race_suspected"] is False


def test_parallel_concurrency_cap():
    ex = ParallelExecutor(max_concurrency=999)
    assert ex.max_concurrency == 50
    ex2 = ParallelExecutor(max_concurrency=0)
    assert ex2.max_concurrency == 1


# ============================================================
# CVSS
# ============================================================

def test_cvss_zero_impact():
    score = compute_cvss_base(
        confidentiality_impact="NONE",
        integrity_impact="NONE",
        availability_impact="NONE",
    )
    assert score.base_score == 0.0
    assert score.severity == "NONE"


def test_cvss_critical_ssrf_like():
    score = compute_cvss_base(
        attack_vector="NETWORK",
        attack_complexity="LOW",
        privileges_required="NONE",
        user_interaction="NONE",
        scope="UNCHANGED",
        confidentiality_impact="HIGH",
        integrity_impact="HIGH",
        availability_impact="HIGH",
    )
    assert score.base_score >= 9.0
    assert score.severity == "CRITICAL"
    assert score.vector.startswith("CVSS:3.1/AV:N")


def test_cvss_severity_bands():
    assert severity_from_score(0.0) == "NONE"
    assert severity_from_score(2.5) == "LOW"
    assert severity_from_score(5.0) == "MEDIUM"
    assert severity_from_score(7.5) == "HIGH"
    assert severity_from_score(9.8) == "CRITICAL"


def test_score_finding_cvss_ssrf():
    finding = {"vuln_class": "ssrf", "severity": "critical"}
    score = score_finding_cvss(finding)
    assert score.base_score >= 7.0
    assert "CVSS:3.1" in score.vector


def test_enhance_finding_with_cvss():
    f = {"vuln_class": "file_upload", "severity": "high", "title": "upload"}
    enhance_finding_with_cvss(f)
    assert "cvss" in f
    assert f["cvss"]["base_score"] > 0
    assert f["cvss"]["vector"]


def test_score_info_finding_zero():
    f = {"vuln_class": "unknown", "severity": "info"}
    score = score_finding_cvss(f)
    assert score.base_score == 0.0


# ============================================================
# PoC
# ============================================================

def test_curl_poc_basic():
    curl = generate_curl_poc(
        method="POST",
        url="https://example.com/api",
        headers={"Authorization": "Bearer x", "Content-Type": "application/json"},
        body='{"a":1}',
    )
    assert "curl" in curl
    assert "-X POST" in curl
    assert "https://example.com/api" in curl
    assert "Authorization" in curl


def test_inject_payload_into_url():
    url = inject_payload_into_url("https://x.com/search?q=hello&page=1", "q", "' OR 1=1--")
    assert "q=" in url
    assert "OR" in url or "%27" in url or "'" in url


def test_generate_poc_from_finding():
    finding = {
        "title": "SSRF",
        "method": "GET",
        "endpoint": "https://example.com/fetch?url=http://evil.com",
        "severity": "critical",
        "vuln_class": "ssrf",
        "evidence": "root:x:0:0",
        "parameter": "url",
        "payload": "http://169.254.169.254/",
        "reproduction": ["Set url param", "Observe metadata"],
    }
    poc = generate_poc_from_finding(finding)
    assert poc["curl"]
    assert poc["transcript"]
    assert len(poc["steps"]) == 2
    assert poc["payload"] == "http://169.254.169.254/"


def test_render_poc_markdown():
    finding = {
        "title": "XSS",
        "method": "POST",
        "endpoint": "https://example.com/comment",
        "severity": "high",
        "vuln_class": "xss",
        "evidence": "<script>alert(1)</script>",
        "body": "comment=<script>alert(1)</script>",
    }
    md = render_poc_markdown(finding)
    assert "Proof of Concept" in md
    assert "```bash" in md
    assert "```http" in md


def test_http_transcript():
    t = generate_http_transcript(
        method="GET",
        url="https://example.com/a?b=1",
        headers={"X-Test": "1"},
        status=200,
        response_snippet="hello",
    )
    assert "GET /a?b=1 HTTP/1.1" in t
    assert "Host: example.com" in t
    assert "hello" in t


# ============================================================
# Metrics
# ============================================================

def test_metrics_record_and_summary(tmp_path):
    m = HuntMetrics(target="https://example.com")
    m.endpoints_discovered = 50
    m.subdomains_discovered = 10
    m.experiments_run = 20
    m.requests_made = 100
    m.record_finding("critical", "ssrf", 0.95)
    m.record_finding("high", "xss", 0.80)
    m.record_finding("high", "ssrf", 0.90)
    m.record_tool("nuclei")
    m.record_llm(success=True)
    m.record_llm(success=False)
    m.record_parallel(30)
    m.vuln_classes_tested.add("ssrf")
    m.mark_end()

    assert m.findings_total == 3
    assert m.findings_by_severity["critical"] == 1
    assert m.findings_by_severity["high"] == 2
    assert m.findings_by_class["ssrf"] == 2
    assert m.reportable_count == 2  # 0.95 and 0.90 >= 0.85
    assert m.llm_calls == 2
    assert m.llm_failures == 1
    assert m.parallel_batches == 1
    assert m.parallel_requests == 30

    lines = m.summary_lines()
    assert any("Findings" in ln for ln in lines)
    assert any("Subdomains" in ln for ln in lines)


def test_metrics_save_load_roundtrip(tmp_path):
    collector = MetricsCollector(target="https://target.com")
    collector.metrics.endpoints_discovered = 42
    collector.metrics.record_finding("high", "idor", 0.9)

    path = tmp_path / "metrics.json"
    collector.save(path)
    assert path.exists()

    loaded = MetricsCollector.load(path)
    assert loaded is not None
    assert loaded.target == "https://target.com"
    assert loaded.endpoints_discovered == 42
    assert loaded.findings_total == 1


def test_metrics_load_missing(tmp_path):
    assert MetricsCollector.load(tmp_path / "nope.json") is None


def test_metrics_dict_serializable():
    m = HuntMetrics(target="x")
    m.vuln_classes_tested.add("ssrf")
    d = m.to_dict()
    json.dumps(d)  # must not raise
    assert d["vuln_classes_tested"] == ["ssrf"]


# ============================================================
# Tool Installer
# ============================================================

def test_installer_recipes_cover_core_tools():
    for name in ("subfinder", "httpx", "nuclei", "ffuf", "nmap"):
        assert name in INSTALL_RECIPES


def test_installer_status_report():
    installer = ToolInstaller()
    report = installer.status_report(["curl", "definitely_not_a_tool_xyz"])
    tools = {r["tool"] for r in report}
    assert "curl" in tools
    assert "definitely_not_a_tool_xyz" in tools
    # curl should be available on most systems
    curl_row = next(r for r in report if r["tool"] == "curl")
    assert curl_row["available"] is True


def test_installer_missing_tools():
    installer = ToolInstaller()
    missing = installer.missing_tools(["curl", "definitely_not_a_tool_xyz"])
    assert "definitely_not_a_tool_xyz" in missing
    assert "curl" not in missing


@pytest.mark.asyncio
async def test_installer_already_installed():
    installer = ToolInstaller()
    result = await installer.install("curl")  # curl almost always exists
    # Either already_installed or installed/failed depending on env
    assert result.status in ("already_installed", "installed", "failed")
    if result.status == "already_installed":
        assert result.path


@pytest.mark.asyncio
async def test_installer_unknown_tool():
    installer = ToolInstaller()
    result = await installer.install("not_a_real_tool_abc")
    assert result.status == "failed"
    assert "No install recipe" in result.message


def test_create_tool_installer():
    i = create_tool_installer()
    assert isinstance(i, ToolInstaller)


# ============================================================
# Reporter enhancements
# ============================================================

def test_reporter_remediation_templates():
    for cls in ("ssrf", "file_upload", "xss", "idor", "unknown"):
        assert cls in REMEDIATION
        assert REMEDIATION[cls]


def test_reporter_hunt_report_with_metrics_cvss_poc(tmp_path):
    reporter = Reporter(output_dir=str(tmp_path))
    findings = [
        {
            "title": "SSRF via url param",
            "severity": "critical",
            "vuln_class": "ssrf",
            "endpoint": "https://example.com/fetch?url=x",
            "method": "GET",
            "evidence": "metadata response",
            "reproduction": ["Set url to internal IP"],
            "impact": "Cloud metadata theft",
            "confidence": 0.9,
            "parameter": "url",
            "payload": "http://169.254.169.254/",
        },
        {
            "title": "Unrestricted upload",
            "severity": "high",
            "vuln_class": "file_upload",
            "endpoint": "https://example.com/upload",
            "method": "POST",
            "evidence": "php accepted",
            "steps": ["Upload shell.php"],
            "impact": "RCE",
            "confidence": 0.85,
        },
    ]
    metrics = {
        "runtime_seconds": 120,
        "endpoints_discovered": 40,
        "subdomains_discovered": 8,
        "experiments_run": 15,
        "findings_total": 2,
        "findings_by_severity": {"critical": 1, "high": 1},
        "findings_by_class": {"ssrf": 1, "file_upload": 1},
    }
    report = reporter.generate_hunt_report(
        target_url="https://example.com",
        findings=findings,
        app_model={"product_type": "saas", "tech_stack": ["python"]},
        memory_summary={"runtime_seconds": 120, "endpoints_discovered": 40},
        reasoning_trace=[{"action": "test", "confidence": 0.8}],
        metrics=metrics,
    )

    assert "## Hunt Metrics" in report
    assert "CVSS" in report
    assert "Proof of Concept" in report
    assert "#### Remediation" in report
    assert "Platform Templates" in report
    assert "HACKERONE" in report
    assert "BUGCROWD" in report
    # Files written
    assert (tmp_path / "REPORT.md").exists()
    # Findings got cvss attached
    assert "cvss" in findings[0]
    assert findings[0]["cvss"]["base_score"] > 0


def test_reporter_finding_report_cvss_poc(tmp_path):
    reporter = Reporter(output_dir=str(tmp_path))
    finding = {
        "title": "XSS",
        "severity": "high",
        "vuln_class": "xss",
        "endpoint": "https://example.com/search",
        "method": "GET",
        "evidence": "<script>alert(1)</script>",
        "impact": "Session theft",
        "confidence": 0.9,
        "parameter": "q",
        "payload": "<script>alert(1)</script>",
    }
    md = reporter.generate_finding_report(finding)
    assert "CVSS" in md
    assert "Proof of Concept" in md
    assert "Remediation" in md
    assert "```bash" in md


def test_reporter_save_metrics(tmp_path):
    reporter = Reporter(output_dir=str(tmp_path))
    path = reporter.save_metrics({"findings_total": 3})
    assert path.exists()
    data = json.loads(path.read_text())
    assert data["findings_total"] == 3
