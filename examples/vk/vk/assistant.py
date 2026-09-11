"""
VK Bug Bounty — Vulnerability Assessment & Validation Engine
=============================================================
Validates findings against VK's rules, estimates bounty potential,
and provides actionable guidance before submission.

Usage:
    from demogorgon.programs.vk.assistant import VKAssessmentEngine
    engine = VKAssessmentEngine()
    result = engine.assess(finding)
    result.should_submit          # True/False
    result.estimated_bounty      # "MAX" / "HIGH" / "MEDIUM" / "LOW"
    result.action_items          # What to do next
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .scope import VKScope, VKTier, VKVulnCategory, VK_BOUNTY_MATRIX, vk_scope
from .report import VKFinding, VKReportGenerator


class VKVerdict(Enum):
    SUBMIT_NOW = "submit_now"
    NEED_MORE_PROOF = "need_more_proof"
    NEED_CHAIN = "need_chain"
    RECONSIDER = "reconsider"
    DO_NOT_SUBMIT = "do_not_submit"


@dataclass
class VKAssessmentResult:
    """Complete assessment result with actionable recommendations."""
    finding: VKFinding
    verdict: VKVerdict
    should_submit: bool
    estimated_bounty: str               # "MAX" / "HIGH" / "MEDIUM" / "LOW" / "NONE"
    tier: str                           # VK tier name
    bounty_category: str
    confidence: float                   # 0.0 - 1.0
    strengths: list[str] = field(default_factory=list)
    weaknesses: list[str] = field(default_factory=list)
    action_items: list[str] = field(default_factory=list)
    rejection_risks: list[str] = field(default_factory=list)
    similar_vulns: list[str] = field(default_factory=list)  # Known paid examples
    cvss_estimate: Optional[str] = None
    report_warnings: list[str] = field(default_factory=list)


class VKAssessmentEngine:
    """
    Main assessment engine for VK bug bounty findings.

    Validates findings against:
    1. VK scope & exclusion rules
    2. PoC minimality requirements
    3. Impact demonstration requirements
    4. Known duplicate patterns
    5. Bounty potential estimation
    """

    def __init__(self, scope: Optional[VKScope] = None):
        self.scope = scope or vk_scope
        self.report_gen = VKReportGenerator(self.scope)

        # Known duplicate / low-value patterns for VK
        self.known_low_value: list[dict] = [
            {"pattern": "open redirect away.php without token theft", "reason": "Explicitly excluded by VK"},
            {"pattern": "logout csrf", "reason": "Explicitly excluded by VK"},
            {"pattern": "version number disclosure", "reason": "Informational only, excluded"},
            {"pattern": "internal ip disclosure", "reason": "Informational only, excluded"},
            {"pattern": "sourcemap exposure", "reason": "Informational only, excluded"},
            {"pattern": "missing security headers", "reason": "Generic, low impact"},
            {"pattern": "clickjacking on non-sensitive pages", "reason": "Generic, low impact"},
            {"pattern": "self-xss", "reason": "Only affects the reporter"},
            {"pattern": "ssl weak cipher", "reason": "Generic, no direct user impact"},
            {"pattern": "spf/dmarc policy", "reason": "Informational, excluded"},
            {"pattern": "local file inclusion without read", "reason": "Need to demonstrate file read"},
            {"pattern": "ssrf to proxy endpoints", "reason": "Dedicated proxies excluded (*.smailru.net)"},
        ]

        # Known HIGH-VALUE patterns for VK (recently paid)
        self.high_value_patterns: list[dict] = [
            {"pattern": "idor on user messages", "reason": "Private Message Reading = MAX bounty"},
            {"pattern": "idor on user profile with pii", "reason": "PII exposure = HIGH bounty"},
            {"pattern": "stored xss in vk messages", "reason": "Can steal sessions, impact all recipients"},
            {"pattern": "ssrf to internal vk api", "reason": "Cross-service access = MAX bounty"},
            {"pattern": "oauth token leakage", "reason": "Can lead to account takeover"},
            {"pattern": "account takeover via sso", "reason": "VK ID = MAX bounty"},
            {"pattern": "sql injection with data exfil", "reason": "SQL injection = HIGH bounty"},
            {"pattern": "rce on vk server", "reason": "RCE = MAX bounty"},
            {"pattern": "business logic price manipulation", "reason": "Financial impact"},
            {"pattern": "file upload to executable directory", "reason": "Can lead to RCE"},
        ]

    def _check_duplicate_risk(self, finding: VKFinding) -> list[str]:
        """Check if finding matches known duplicate patterns."""
        risks = []
        desc_lower = (finding.description + finding.vuln_type).lower()

        for pattern in self.known_low_value:
            if pattern["pattern"].lower() in desc_lower:
                risks.append(f"⚠️ DUPLICATE RISK: {pattern['reason']}")

        return risks

    def _check_high_value(self, finding: VKFinding) -> list[str]:
        """Check if finding matches known high-value patterns."""
        matches = []
        desc_lower = (finding.description + finding.vuln_type + finding.endpoint or "").lower()

        for pattern in self.high_value_patterns:
            if pattern["pattern"].lower() in desc_lower:
                matches.append(f"✅ HIGH VALUE: {pattern['reason']}")

        return matches

    def _estimate_cvss(self, finding: VKFinding, tier: VKTier) -> str:
        """Estimate CVSS vector based on finding and target tier."""
        # Base metrics
        av = "N"  # Network
        ac = "L"  # Low complexity
        pr = "U"  # No privileges (most vulns)
        ui = "N"  # No user interaction
        s = "C"   # Changed scope (for most auth bypass)

        # Adjust based on vuln type
        vuln = finding.vuln_type.lower()
        if "idor" in vuln or "access control" in vuln:
            pr = "L"  # Requires low privilege
        elif "stored xss" in vuln:
            ui = "R"  # Requires user interaction (click link)
        elif "csrf" in vuln:
            ui = "R"  # Requires user interaction

        # Impact based on tier and vuln
        ci = "H"  # Confidentiality High for VK ID
        ii = "N"  # Integrity None by default
        ai = "N"  # Availability None by default

        if tier == VKTier.TIER_1_VK_ID:
            ci = "H"
            ii = "H"
        elif "rce" in vuln or "code execution" in vuln:
            ci = "H"
            ii = "H"
            ai = "H"
        elif "xss" in vuln:
            ci = "L"
            ii = "L"
        elif "sqli" in vuln or "sql injection" in vuln:
            ci = "H"
            ii = "H"

        return f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{ci}/I:{ii}/A:{ai}"

    def _generate_action_items(self, finding: VKFinding, assessment: VKAssessmentResult) -> list[str]:
        """Generate specific action items to strengthen the submission."""
        items = []

        # Check for missing evidence
        if not finding.screenshots and not finding.video_url:
            items.append("📎 Add screenshots showing the vulnerability (required by VK)")
            items.append("📎 Record a screen recording if the exploit chain is complex")

        # Check PoC
        if not finding.poc_curl and not finding.poc_command:
            items.append("🔧 Add a minimal curl command or command that reproduces the issue")

        # Check impact
        if not finding.impact or "no description" in finding.impact.lower():
            items.append("📊 Write a clear impact statement explaining what an attacker can do")

        # Check steps
        if len(finding.steps_to_reproduce) < 2:
            items.append("📝 Add more detailed reproduction steps (minimum 3-5 steps)")

        # For IDOR: check if you tested write operations
        if "idor" in finding.vuln_type.lower():
            items.append("🔍 Test if the IDOR also allows write/modification (higher impact)")

        # For XSS: check if you demonstrated cookie theft
        if "xss" in finding.vuln_type.lower():
            items.append("🔍 Demonstrate cookie theft or session hijacking in the PoC")

        # For SSRF: check if you hit internal services
        if "ssrf" in finding.vuln_type.lower():
            items.append("🔍 Try to access internal VK services (metadata, internal APIs)")

        # For auth bypass: check if you demonstrated full impact
        if "auth bypass" in finding.vuln_type.lower() or "access control" in finding.vuln_type.lower():
            items.append("🔍 Demonstrate the highest-impact action you can perform after bypass")

        # For open redirect: check if you have token theft
        if "open redirect" in finding.vuln_type.lower():
            items.append("⚠️ VK only pays open redirects if you demonstrate full session token theft")

        return items

    def assess(self, finding: VKFinding) -> VKAssessmentResult:
        """
        Full assessment of a finding for VK submission readiness.
        """
        # Get scope assessment
        scope_result = self.scope.assess_finding(finding.target, finding.vuln_type)

        # Determine tier and category
        tier_name = scope_result.get("vk_tier", "OUT_OF_SCOPE")
        bounty_category = scope_result.get("bounty_category", "unknown")
        eligible = scope_result.get("eligible", False)

        # Check duplicate risk
        duplicate_risks = self._check_duplicate_risk(finding)

        # Check high-value patterns
        high_value_matches = self._check_high_value(finding)

        # Estimate CVSS
        vk_tier = self.scope.tier(finding.target)
        cvss = self._estimate_cvss(finding, vk_tier)

        # Generate strengths
        strengths = []
        if eligible:
            strengths.append(f"✅ Target is in VK scope (Tier: {tier_name})")
        if high_value_matches:
            for m in high_value_matches:
                strengths.append(m)
        if finding.screenshots or finding.video_url:
            strengths.append("✅ Visual evidence provided (screenshots/video)")
        if finding.poc_curl or finding.poc_command:
            strengths.append("✅ Minimal PoC provided")
        if finding.steps_to_reproduce and len(finding.steps_to_reproduce) >= 3:
            strengths.append("✅ Detailed reproduction steps")
        if finding.impact:
            strengths.append("✅ Impact statement provided")

        # Generate weaknesses
        weaknesses = []
        if not eligible:
            weaknesses.append(f"❌ {scope_result.get('rejection_reasons', ['Out of scope'])[0]}")
        if not finding.screenshots and not finding.video_url:
            weaknesses.append("❌ No screenshots or video — VK REQUIRES visual proof")
        if not finding.poc_curl and not finding.poc_command:
            weaknesses.append("❌ No minimal PoC — VK REQUIRES at least a curl command or minimal payload")
        if not finding.steps_to_reproduce:
            weaknesses.append("❌ No reproduction steps")
        if not finding.impact:
            weaknesses.append("❌ No impact statement")
        if duplicate_risks:
            for r in duplicate_risks:
                weaknesses.append(r)

        # Determine verdict
        if not eligible:
            verdict = VKVerdict.DO_NOT_SUBMIT
            should_submit = False
            estimated_bounty = "NONE"
        elif duplicate_risks and not high_value_matches:
            verdict = VKVerdict.RECONSIDER
            should_submit = False
            estimated_bounty = "LOW"
        elif not finding.poc_curl and not finding.poc_command:
            verdict = VKVerdict.NEED_MORE_PROOF
            should_submit = False
            estimated_bounty = "PENDING"
        elif not finding.screenshots and not finding.video_url:
            verdict = VKVerdict.NEED_MORE_PROOF
            should_submit = False
            estimated_bounty = "PENDING"
        elif high_value_matches:
            verdict = VKVerdict.SUBMIT_NOW
            should_submit = True
            if vk_tier == VKTier.TIER_1_VK_ID:
                estimated_bounty = "MAX"
            elif vk_tier == VKTier.TIER_2_VK_COM:
                estimated_bounty = "HIGH"
            else:
                estimated_bounty = "MEDIUM"
        else:
            verdict = VKVerdict.SUBMIT_NOW
            should_submit = True
            estimated_bounty = "MEDIUM"

        # Generate action items
        assessment = VKAssessmentResult(
            finding=finding,
            verdict=verdict,
            should_submit=should_submit,
            estimated_bounty=estimated_bounty,
            tier=tier_name,
            bounty_category=bounty_category,
            confidence=0.8 if should_submit else 0.4,
            strengths=strengths,
            weaknesses=weaknesses,
            action_items=[],
            rejection_risks=[r for r in duplicate_risks if "DUPLICATE" in r],
            cvss_estimate=cvss,
        )

        assessment.action_items = self._generate_action_items(finding, assessment)

        # Get report warnings
        report = self.report_gen.generate(finding)
        assessment.report_warnings = report.submission_warnings

        return assessment

    def assess_raw(
        self,
        vuln_type: str,
        target: str,
        endpoint: str = "",
        description: str = "",
        poc: str = "",
        impact: str = "",
    ) -> VKAssessmentResult:
        """Convenience method for quick assessment without building a VKFinding."""
        finding = VKFinding(
            title=f"{vuln_type} in {target}",
            vuln_type=vuln_type,
            target=target,
            endpoint=endpoint,
            description=description,
            poc_curl=poc,
            impact=impact,
        )
        return self.assess(finding)

    def quick_check(self, vuln_type: str, target: str) -> dict:
        """
        Ultra-quick scope check. Returns minimal info.
        Use this to decide if a finding is worth investigating.
        """
        assessment = self.scope.assess_finding(target, vuln_type)
        return {
            "in_scope": assessment["eligible"],
            "tier": assessment["vk_tier"],
            "bounty_category": assessment.get("bounty_category", "unknown"),
            "max_bounty": assessment.get("max_bounty_qualifies", False),
            "guidance": assessment.get("guidance", ""),
        }

    def format_assessment(self, result: VKAssessmentResult) -> str:
        """Format assessment result as readable text."""
        lines = []
        lines.append(f"{'='*60}")
        lines.append(f"VK ASSESSMENT: {result.finding.vuln_type} in {result.finding.target}")
        lines.append(f"{'='*60}")
        lines.append(f"Verdict:          {result.verdict.value}")
        lines.append(f"Should Submit:    {'YES' if result.should_submit else 'NO'}")
        lines.append(f"Estimated Bounty: {result.estimated_bounty}")
        lines.append(f"VK Tier:          {result.tier}")
        lines.append(f"Bounty Category:  {result.bounty_category}")
        lines.append(f"CVSS Estimate:    {result.cvss_estimate or 'N/A'}")
        lines.append(f"Confidence:       {result.confidence:.0%}")
        lines.append("")

        if result.strengths:
            lines.append("STRENGTHS:")
            for s in result.strengths:
                lines.append(f"  {s}")
            lines.append("")

        if result.weaknesses:
            lines.append("WEAKNESSES:")
            for w in result.weaknesses:
                lines.append(f"  {w}")
            lines.append("")

        if result.action_items:
            lines.append("ACTION ITEMS:")
            for a in result.action_items:
                lines.append(f"  → {a}")
            lines.append("")

        if result.rejection_risks:
            lines.append("REJECTION RISKS:")
            for r in result.rejection_risks:
                lines.append(f"  ⚠️ {r}")
            lines.append("")

        return "\n".join(lines)


# ─── CLI Demo ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    engine = VKAssessmentEngine()

    # Demo findings
    demo_findings = [
        VKFinding(
            title="IDOR in VK ID Profile API",
            vuln_type="IDOR",
            target="id.vk.com",
            endpoint="/api/profile/get",
            description="Can read any user's private profile data by changing user_id",
            steps_to_reproduce=["Login to VK", "Capture profile request", "Change user_id", "Send request"],
            poc_curl='curl -X POST https://id.vk.com/api/profile/get -d "user_id=<VICTIM_ID>"',
            impact="Any user can read private data of any other user",
        ),
        VKFinding(
            title="Open Redirect via away.php",
            vuln_type="Open Redirect",
            target="vk.com",
            endpoint="/away.php",
            description="away.php redirects to any URL without validation",
            steps_to_reproduce=["Visit vk.com/away.php?url=https://evil.com"],
            poc_curl='curl -v "https://vk.com/away.php?url=https://evil.com"',
            impact="User can be redirected to malicious site",
        ),
        VKFinding(
            title="Version Disclosure in API Headers",
            vuln_type="Information Disclosure",
            target="api.vk.com",
            description="API returns X-Powered-By header with version number",
            steps_to_reproduce=["Make request to api.vk.com", "Check response headers"],
            poc_curl='curl -I https://api.vk.com/',
            impact="Internal version number is disclosed",
        ),
        VKFinding(
            title="SSRF via Image Proxy",
            vuln_type="SSRF",
            target="api.vk.com",
            endpoint="/method/photos.get",
            description="Photo proxy endpoint can be used to scan internal network",
            steps_to_reproduce=["Login to VK", "Use photos.get with custom URL parameter", "Observe internal network responses"],
            poc_curl='curl -X POST https://api.vk.com/method/photos.get -d "url=http://169.254.169.254/latest/meta-data/"',
            impact="Can scan and access internal VK infrastructure",
        ),
    ]

    console.rule("[bold red]VK Assessment Engine Demo[/bold red]\n")

    for finding in demo_findings:
        result = engine.assess(finding)
        console.print(engine.format_assessment(result))
        console.print()

    # Quick check demo
    console.rule("\n[bold]Quick Scope Checks[/bold]")
    qtable = Table(title="Quick Checks")
    qtable.add_column("Target", style="cyan")
    qtable.add_column("Vuln Type", style="magenta")
    qtable.add_column("In Scope", style="green")
    qtable.add_column("Tier", style="yellow")
    qtable.add_column("Max Bounty", style="bold")

    checks = [
        ("id.vk.com", "Account Takeover"),
        ("vk.com", "Stored XSS"),
        ("api.vk.com", "SSRF"),
        ("mail.ru", "SQL Injection"),
        ("vk.com/ads", "XSS"),
    ]

    for target, vuln in checks:
        qc = engine.quick_check(vuln, target)
        in_scope = "✅" if qc["in_scope"] else "❌"
        max_b = "🔥" if qc["max_bounty"] else ""
        qtable.add_row(target, vuln, in_scope, qc["tier"], max_b)

    console.print(qtable)
