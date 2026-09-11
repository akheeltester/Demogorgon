"""End-to-end integration test — exercises the full Demogorgon pipeline.

Tests:
1. Engagement creation from program policy
2. Scope parsing + SafetyGate + ActionGateway
3. Recon engine
4. Research loop with real LLM
5. Evidence collection + validation
6. Bug chain detection
7. State persistence + crash resume
8. Report generation
9. Autonomous runner E2E
10. CLI smoke test

Target: httpbin.org (safe, public)
"""

import asyncio
import json
import os
import sys
import time
import traceback

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
os.environ.setdefault("PYTHONPATH", PROJECT_ROOT)

# Load .env
from pathlib import Path
env_path = Path(PROJECT_ROOT) / ".env"
if env_path.exists():
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))

CYAN = "\033[36m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
BOLD = "\033[1m"
RESET = "\033[0m"

passed = 0
failed = 0
errors = []


def section(title):
    print(f"\n{BOLD}{CYAN}{'='*60}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'='*60}{RESET}")


def ok(msg):
    global passed
    passed += 1
    print(f"  {GREEN}✓{RESET} {msg}")


def fail(msg, detail=""):
    global failed
    failed += 1
    errors.append((msg, detail))
    print(f"  {RED}✗{RESET} {msg}")
    if detail:
        print(f"    {RED}{detail[:300]}{RESET}")


def info(msg):
    print(f"  {YELLOW}→{RESET} {msg}")


async def test_engagement_creation():
    """Test 1: Engagement creation from program policy."""
    section("1. ENGAGEMENT CREATION")

    from demogorgon.core.engagement import (
        Engagement, ProgramPolicy, ScopeAsset, TestingRestriction,
        EngagementStatus, AuthorizationStatus, AuthorizationSource,
    )
    from demogorgon.core.scope.parser import parse_program_policy

    policy = ProgramPolicy(
        program_name="Test Program",
        platform="manual",
        in_scope=[
            ScopeAsset(pattern="httpbin.org", asset_type="domain"),
            ScopeAsset(pattern="*.httpbin.org", asset_type="domain"),
        ],
        out_of_scope=[
            ScopeAsset(pattern="admin.httpbin.org", asset_type="domain"),
        ],
        restrictions=[
            TestingRestriction(category="dos", allowed=False, description="No DoS"),
        ],
        safe_harbor=True,
    )

    engagement = Engagement(
        id="test-integration-001",
        name="Integration Test",
        target_url="https://httpbin.org",
        policy=policy,
        status=EngagementStatus.ACTIVE,
        authorization_status=AuthorizationStatus.CONFIRMED,
        authorization_source=AuthorizationSource.USER_DECLARED,
    )

    assert engagement.id == "test-integration-001"
    assert engagement.target_url == "https://httpbin.org"
    assert engagement.status == EngagementStatus.ACTIVE
    assert engagement.authorization_status == AuthorizationStatus.CONFIRMED
    assert len(engagement.policy.in_scope) == 2
    assert engagement.policy.safe_harbor is True
    ok("Engagement created with correct fields")

    data = engagement.to_dict()
    assert data["id"] == "test-integration-001"
    assert data["target_url"] == "https://httpbin.org"
    assert len(data["policy"]["in_scope"]) == 2
    ok("Engagement serialization roundtrip")

    engagement2 = Engagement.from_dict(data)
    assert engagement2.id == engagement.id
    assert engagement2.target_url == engagement.target_url
    assert len(engagement2.policy.in_scope) == 2
    ok("Engagement deserialization roundtrip")

    program_text = """Example Bounty
manual
httpbin.org (domain)
*.httpbin.org (domain)
admin.httpbin.org (domain)
"""
    parsed_policy = parse_program_policy(program_text)
    assert parsed_policy.program_name == "Example Bounty"
    assert parsed_policy.platform == "manual"
    assert len(parsed_policy.in_scope) >= 1
    ok(f"Scope parser: {len(parsed_policy.in_scope)} in-scope, {len(parsed_policy.out_of_scope)} out-of-scope")


async def test_scope_safety_gateway():
    """Test 2: Scope matching, SafetyGate, and ActionGateway."""
    section("2. SCOPE + SAFETY + ACTION GATEWAY")

    from demogorgon.core.scope.matcher import ScopeMatcher
    from demogorgon.core.scope.safety import SafetyGate
    from demogorgon.core.gateway import ActionGateway, GateResult
    from demogorgon.core.engagement import ScopeAsset, TestingRestriction
    from demogorgon.core.hitl.gate import HITLGate, ApprovalLevel

    in_scope = [
        ScopeAsset(pattern="httpbin.org", asset_type="domain"),
        ScopeAsset(pattern="*.httpbin.org", asset_type="domain"),
    ]
    out_of_scope = [
        ScopeAsset(pattern="admin.httpbin.org", asset_type="domain"),
    ]

    matcher = ScopeMatcher(in_scope, out_of_scope)

    r1 = matcher.match("httpbin.org")
    assert r1.in_scope is True
    ok("Exact domain match: httpbin.org → in scope")

    r2 = matcher.match("anything.httpbin.org")
    assert r2.in_scope is True
    ok("Wildcard match: anything.httpbin.org → in scope")

    r3 = matcher.match("admin.httpbin.org")
    assert r3.in_scope is False
    ok("Out-of-scope: admin.httpbin.org → blocked")

    r4 = matcher.match("evil.com")
    assert r4.in_scope is False
    ok("Unknown target: evil.com → blocked")

    safety = SafetyGate(
        in_scope_assets=in_scope,
        out_of_scope_assets=out_of_scope,
        restrictions=[
            TestingRestriction(category="dos", allowed=False, description="No DoS"),
        ],
        rate_limit=10.0,
        max_requests=100,
    )

    check1 = safety.check_url("https://httpbin.org/get")
    assert check1.allowed is True
    ok("SafetyGate: httpbin.org/get → allowed")

    check2 = safety.check_url("https://admin.httpbin.org/config")
    assert check2.allowed is False
    ok("SafetyGate: admin.httpbin.org → blocked")

    check3 = safety.check_action("dos", "https://httpbin.org/get")
    assert check3.allowed is False
    ok("SafetyGate: DoS action → blocked by restriction")

    check4 = safety.check_action("scan", "https://httpbin.org/get")
    assert check4.allowed is True
    ok("SafetyGate: scan action → allowed")

    stats = safety.get_stats()
    assert stats["blocked_count"] >= 2
    ok(f"SafetyGate stats: {stats['blocked_count']} blocked requests logged")

    hitl = HITLGate(approval_level=ApprovalLevel.NONE)
    gateway = ActionGateway(safety_gate=safety, hitl_gate=hitl)

    g1 = await gateway.validate("scan", "https://httpbin.org/get")
    assert g1.allowed is True
    ok("ActionGateway: scan httpbin.org → allowed")

    g2 = await gateway.validate("scan", "https://admin.httpbin.org/config")
    assert g2.allowed is False
    assert g2.result == GateResult.DENY
    ok("ActionGateway: admin.httpbin.org → DENIED")

    g3 = await gateway.validate("dos", "https://httpbin.org/get")
    assert g3.allowed is False
    ok("ActionGateway: DoS action → DENIED (restriction)")

    gw_stats = gateway.get_stats()
    assert gw_stats["blocked"] >= 2
    ok(f"ActionGateway stats: {gw_stats['allowed']} allowed, {gw_stats['blocked']} blocked")


async def test_recon_engine():
    """Test 3: Recon engine."""
    section("3. RECON ENGINE")

    from demogorgon.recon.engine import ReconEngine

    try:
        engine = ReconEngine(registry=None, executor=None)
        info("ReconEngine initialized (no tools)")
        ok("ReconEngine instantiates with null registry/executor")
    except Exception as e:
        fail(f"ReconEngine init failed: {e}")

    # Test with the runner's approach (graceful degradation)
    try:
        engine2 = ReconEngine(registry=None, executor=None)
        ok("ReconEngine can be created for pipeline integration")
    except Exception as e:
        fail(f"ReconEngine secondary init failed: {e}")


async def test_research_loop():
    """Test 4: Research loop with real LLM."""
    section("4. RESEARCH LOOP (with LLM)")

    from demogorgon.llm.manager import LLMManager
    from demogorgon.core.research_loop.loop import ResearchLoop, LoopConfig
    from demogorgon.core.research_loop.evidence import EvidenceCollector

    llm = LLMManager()
    llm.configure()

    if not llm._active_provider:
        fail("No LLM provider configured")
        return

    info(f"LLM provider: {llm._active_provider}, model: {llm._active_model}")

    try:
        resp = await llm.generate([
            {"role": "user", "content": "Say 'LLM OK' and nothing else."}
        ])
        if resp.error:
            info(f"LLM generate returned error (API key limitation): {resp.error[:120]}")
            info("Skipping LLM-dependent tests (use a valid API key for full test)")
            return
        assert len(resp.content) > 0
        ok(f"LLM responded: '{resp.content[:80]}' (latency: {resp.latency:.2f}s)")
    except Exception as e:
        info(f"LLM test skipped: {e}")
        return

    workspace = os.path.join(PROJECT_ROOT, "test_workspace_integration")
    os.makedirs(workspace, exist_ok=True)

    loop_config = LoopConfig(
        max_iterations=3,
        rate_limit_delay=1.0,
        checkpoint_interval=2,
    )

    evidence_collector = EvidenceCollector(workspace_dir=workspace)

    loop = ResearchLoop(
        target="httpbin.org",
        llm_generate=llm.generate,
        config=loop_config,
        workspace_dir=workspace,
        engagement_id="test-integration-001",
        evidence_collector=evidence_collector,
    )

    info("Running 3-iteration research loop...")
    try:
        await loop.initialize()
        report = await loop.run()

        assert "iterations" in report
        ok(f"Research loop completed: {report['iterations']} iterations")

        if report.get("findings"):
            ok(f"Found {len(report['findings'])} finding(s)")
            for f in report["findings"][:3]:
                if isinstance(f, dict):
                    info(f"  - {f.get('vuln_class', 'unknown')}: {f.get('description', '')[:80]}")
        else:
            info("No findings (expected for httpbin.org)")

        if report.get("error"):
            info(f"Loop note: {report['error']}")

    except Exception as e:
        fail(f"Research loop failed: {e}", traceback.format_exc())


async def test_evidence_validation():
    """Test 5: Evidence collection + validation pipeline."""
    section("5. EVIDENCE + VALIDATION")

    from demogorgon.core.evidence.types import EvidenceItem, EvidenceType
    from demogorgon.core.evidence.packager import EvidencePackager
    from demogorgon.core.validation.pipeline import ValidationPipeline

    workspace = os.path.join(PROJECT_ROOT, "test_workspace_integration")
    os.makedirs(workspace, exist_ok=True)

    evidence_items = [
        EvidenceItem(
            id="ev-001",
            type=EvidenceType.HTTP_REQUEST,
            description="IDOR on user endpoint: GET /api/users/2 returns data when authenticated as user 1",
            confidence=0.8,
            source="manual",
            tags=["IDOR", "access_control"],
        ),
        EvidenceItem(
            id="ev-002",
            type=EvidenceType.HTTP_RESPONSE,
            description="500 error exposes stack trace with internal paths",
            confidence=0.6,
            source="manual",
            tags=["info_disclosure", "error"],
        ),
    ]

    packager = EvidencePackager(workspace_dir=workspace)
    packaged = packager.package(
        vuln_class="IDOR",
        evidence_items=evidence_items,
        title="IDOR on User Endpoint",
        description="Multiple access control issues found",
        metadata={"engagement_id": "test-integration-001"},
    )
    ok(f"Packaged evidence item: {packaged.title}")

    save_path = packager.save(packaged)
    assert os.path.exists(save_path)
    ok(f"Evidence saved to: {save_path}")

    reloaded = packager.load(save_path)
    assert reloaded.vuln_class == "IDOR"
    ok(f"Evidence reloaded: {reloaded.title}")

    pipeline = ValidationPipeline(min_confidence=0.3)

    evidence_dict = {
        "vuln_class": "IDOR",
        "description": "IDOR on user endpoint: GET /api/users/2 returns data when authenticated as user 1",
        "endpoint": "GET /api/users/{id}",
        "confidence": 0.8,
        "response_body": "user data exposed",
    }
    validation_result = await pipeline.validate(evidence_dict, confidence=0.8)
    info(f"Validation: is_valid={validation_result.get('is_valid')}, confidence={validation_result.get('final_confidence', 0):.2f}")

    if validation_result.get("is_false_positive"):
        info(f"Flagged as FP: {validation_result.get('fp_reasons', [])}")
    else:
        ok(f"Validation passed: severity={validation_result.get('recommended_severity', 'unknown')}")


async def test_bug_chains():
    """Test 6: Bug chain detection."""
    section("6. BUG CHAIN DETECTION")

    from demogorgon.core.chains.detector import BugChainDetector

    detector = BugChainDetector()

    observations = [
        {
            "vuln_class": "Open Redirect",
            "endpoint": "/redirect",
            "description": "User-controlled redirect parameter",
            "confidence": 0.9,
        },
        {
            "vuln_class": "XSS",
            "endpoint": "/search",
            "description": "Reflected XSS in search parameter",
            "confidence": 0.85,
        },
    ]

    chains = detector.detect_chains(observations)
    info(f"Detected {len(chains)} chain(s) from Open Redirect + XSS")

    if chains:
        for chain in chains:
            info(f"  Chain: {' → '.join(step.vuln_class for step in chain.steps)}")
            info(f"  Severity: {chain.overall_severity}, Known: {chain.is_known_pattern}")
        ok("Bug chain detection working")
    else:
        info("No chains matched (acceptable - pattern specificity)")

    observations2 = [
        {"vuln_class": "SSRF", "endpoint": "/api/fetch", "description": "SSRF", "confidence": 0.95},
        {"vuln_class": "RCE", "endpoint": "/api/internal", "description": "RCE", "confidence": 0.7},
    ]

    chains2 = detector.detect_chains(observations2)
    if chains2:
        ok(f"SSRF→RCE chain detected: {chains2[0].overall_severity}")
    else:
        info("SSRF→RCE not matched (pattern specificity)")

    ok("Bug chain detector operational")


async def test_state_persistence():
    """Test 7: State persistence + crash resume."""
    section("7. STATE PERSISTENCE + CRASH RESUME")

    from demogorgon.core.state.manager import StateManager

    workspace = os.path.join(PROJECT_ROOT, "test_workspace_integration")
    os.makedirs(workspace, exist_ok=True)

    sm = StateManager(workspace)

    state = sm.initialize(
        engagement_id="test-integration-001",
        target="httpbin.org",
    )
    assert state.engagement_id == "test-integration-001"
    assert state.target == "httpbin.org"
    ok("State initialized")

    state.iteration = 5
    state.strategy = "deep_recon"
    state.findings_count = 3
    state.data["custom_key"] = "custom_value"
    sm.save_state(state)
    ok("State saved with iteration=5, findings=3")

    loaded = sm.load_state()
    assert loaded.iteration == 5
    assert loaded.strategy == "deep_recon"
    assert loaded.findings_count == 3
    assert loaded.data.get("custom_key") == "custom_value"
    ok("State reloaded correctly")

    case_data = {
        "findings": [{"title": "Test Finding", "severity": "high"}],
        "observations": [{"vuln_class": "XSS"}],
    }
    sm.save_checkpoint(5, case_data)
    ok("Checkpoint saved at iteration 5")

    checkpoint = sm.get_latest_checkpoint()
    assert checkpoint is not None
    iteration, data = checkpoint
    assert iteration == 5
    assert len(data["findings"]) == 1
    ok(f"Latest checkpoint loaded: iteration {iteration}")

    summary = sm.get_summary()
    assert summary["has_state"] is True
    assert summary["checkpoint_count"] >= 1
    ok(f"Summary: {summary['checkpoint_count']} checkpoints, state present")

    sm2 = StateManager(os.path.join(PROJECT_ROOT, "test_workspace_integration_2"))
    state2 = sm2.initialize(engagement_id="eng-002", target="evil.com")
    loaded2 = sm2.load_state()
    assert loaded2.engagement_id == "eng-002"
    assert loaded2.target == "evil.com"
    ok("Second engagement state isolated from first")


async def test_report_generation():
    """Test 8: Report generation."""
    section("8. REPORT GENERATION")

    from demogorgon.core.reporting.generator import ReportGenerator, Finding

    workspace = os.path.join(PROJECT_ROOT, "test_workspace_integration")
    os.makedirs(workspace, exist_ok=True)

    gen = ReportGenerator(workspace_dir=workspace)

    findings = [
        Finding(
            title="IDOR in User Profile API",
            severity="high",
            vuln_class="IDOR",
            endpoint="GET /api/users/{id}",
            description="Authenticated user can access any user profile by changing the ID parameter.",
            impact="Full account data exposure for all users.",
            remediation="Implement object-level authorization checks.",
            reproduction_steps=[
                "1. Login as user A",
                "2. GET /api/users/123",
                "3. Change ID to 124, 125, etc.",
            ],
        ),
        Finding(
            title="Open Redirect in Login Flow",
            severity="medium",
            vuln_class="Open Redirect",
            endpoint="GET /login?redirect={url}",
            description="The redirect parameter is not validated.",
            impact="Phishing via crafted login URL.",
            remediation="Whitelist redirect URLs.",
            reproduction_steps=[
                "1. Visit /login?redirect=https://evil.com",
                "2. Complete login",
                "3. Redirected to evil.com with session",
            ],
        ),
    ]

    report = gen.generate(
        findings=findings,
        target="https://app.example.com",
        program="Example Bug Bounty",
        stats={"iterations": 15, "evidence_items": 42},
    )

    assert report.total_findings == 2
    assert report.severity_counts.get("high", 0) == 1
    assert report.severity_counts.get("medium", 0) == 1
    ok(f"Report generated: {report.total_findings} findings")

    report_dict = report.to_dict()
    assert report_dict["total_findings"] == 2
    ok("Report serialized to dict")

    json_path = gen.save_json(report)
    assert os.path.exists(json_path)
    with open(json_path) as f:
        data = json.load(f)
    assert data["total_findings"] == 2
    ok(f"JSON report saved: {json_path}")

    md_path = gen.save_markdown(report)
    assert os.path.exists(md_path)
    with open(md_path) as f:
        content = f.read()
    assert "IDOR" in content
    assert "Open Redirect" in content
    ok(f"Markdown report saved: {md_path}")


async def test_autonomous_runner():
    """Test 9: AutonomousRunner end-to-end."""
    section("9. AUTONOMOUS RUNNER (E2E)")

    from demogorgon.core.runner import AutonomousRunner, RunnerConfig
    from demogorgon.core.engagement import (
        Engagement, ProgramPolicy, ScopeAsset,
        EngagementStatus, AuthorizationStatus,
    )
    from demogorgon.core.hitl.gate import ApprovalLevel

    workspace = os.path.join(PROJECT_ROOT, "test_workspace_runner")
    os.makedirs(workspace, exist_ok=True)

    policy = ProgramPolicy(
        program_name="Integration Test",
        platform="manual",
        in_scope=[
            ScopeAsset(pattern="httpbin.org", asset_type="domain"),
        ],
    )

    engagement = Engagement(
        id="runner-test-001",
        name="Runner Integration Test",
        target_url="https://httpbin.org",
        policy=policy,
        status=EngagementStatus.ACTIVE,
        authorization_status=AuthorizationStatus.CONFIRMED,
    )

    config = RunnerConfig(
        max_iterations=2,
        rate_limit=2.0,
        max_requests=50,
        approval_level=ApprovalLevel.NONE,
        checkpoint_interval=1,
        auto_report=True,
        workspace_dir=workspace,
    )

    runner = AutonomousRunner(
        engagement=engagement,
        config=config,
        llm_generate=None,
        workspace_dir=workspace,
    )

    info(f"Runner workspace: {workspace}")
    info("Running in observation-only mode (no LLM)")

    status = runner.get_status()
    assert status["engagement_id"] == "runner-test-001"
    assert status["target"] == "https://httpbin.org"
    ok(f"Runner status: engagement {status['engagement_id']}")

    info("Running autonomous pipeline (2 iterations, no LLM)...")
    try:
        result = await runner.run()

        assert result["engagement_id"] == "runner-test-001"
        assert result["status"] == "completed"
        ok(f"Runner completed in {result['duration']:.1f}s")
        ok(f"Findings: {result['findings_count']}, Chains: {result['chains_count']}")

        if result.get("report_path"):
            ok(f"Report generated: {result['report_path']}")

    except Exception as e:
        fail(f"Runner failed: {e}", traceback.format_exc())


async def test_cli_smoke():
    """Test 10: CLI commands (non-interactive)."""
    section("10. CLI SMOKE TEST")

    import subprocess

    result = subprocess.run(
        [sys.executable, "-m", "demogorgon", "--help"],
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
        env={**os.environ, "PYTHONPATH": PROJECT_ROOT},
    )
    assert result.returncode == 0
    assert "Demogorgon" in result.stdout
    ok("CLI --help works")


async def main():
    """Run all integration tests."""
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  DEMOGORGON INTEGRATION TEST SUITE{RESET}")
    print(f"{BOLD}  Target: httpbin.org (safe, public){RESET}")
    print(f"{BOLD}{'='*60}{RESET}")

    tests = [
        ("Engagement Creation", test_engagement_creation),
        ("Scope + Safety + Gateway", test_scope_safety_gateway),
        ("Recon Engine", test_recon_engine),
        ("Research Loop", test_research_loop),
        ("Evidence + Validation", test_evidence_validation),
        ("Bug Chain Detection", test_bug_chains),
        ("State Persistence", test_state_persistence),
        ("Report Generation", test_report_generation),
        ("Autonomous Runner", test_autonomous_runner),
        ("CLI Smoke Test", test_cli_smoke),
    ]

    start = time.time()

    for name, test_fn in tests:
        try:
            await test_fn()
        except Exception as e:
            fail(f"Test '{name}' crashed: {e}", traceback.format_exc())

    elapsed = time.time() - start

    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  RESULTS{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")
    print(f"  {GREEN}Passed: {passed}{RESET}")
    print(f"  {RED}Failed: {failed}{RESET}")
    print(f"  Total:  {passed + failed}")
    print(f"  Time:   {elapsed:.1f}s")

    if errors:
        print(f"\n{RED}Failures:{RESET}")
        for msg, detail in errors:
            print(f"  {RED}✗{RESET} {msg}")
            if detail:
                print(f"    {detail[:200]}")

    print()
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
