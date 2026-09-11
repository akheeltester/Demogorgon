"""
VK Bug Bounty — Report Template Generator
==========================================
Generates submission-ready reports conforming to VK's official format.

Usage:
    from demogorgon.programs.vk.report import VKReportGenerator
    gen = VKReportGenerator()
    report = gen.generate(finding)
    gen.save(report, "output/report.md")
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from .scope import VKScope, VKTier, VKVulnCategory, VK_BOUNTY_MATRIX, vk_scope


@dataclass
class VKFinding:
    """Represents a validated finding ready for VK submission."""
    title: str
    vuln_type: str                    # Must match VK's category list
    target: str                       # e.g., "id.vk.com", "api.vk.com"
    endpoint: Optional[str] = None    # e.g., "/api/users/get"
    description: str = ""
    steps_to_reproduce: list[str] = field(default_factory=list)
    poc_curl: str = ""                # Minimal curl command
    poc_command: str = ""             # Minimal command (sleep, cat /etc/passwd, etc.)
    impact: str = ""
    affected_users: str = "all"       # "all", "specific", number
    authentication_required: bool = True
    screenshots: list[str] = field(default_factory=list)  # Filenames
    video_url: Optional[str] = None
    extra_evidence: dict = field(default_factory=dict)
    custom_cvss: Optional[str] = None  # e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    references: list[str] = field(default_factory=list)


@dataclass
class VKReport:
    """Complete VK-formatted report."""
    markdown: str
    title: str
    finding: VKFinding
    assessment: dict
    submission_warnings: list[str] = field(default_factory=list)


class VKReportGenerator:
    """Generates VK-compliant bug bounty reports."""

    def __init__(self, scope: Optional[VKScope] = None):
        self.scope = scope or vk_scope

    def validate_finding(self, finding: VKFinding) -> list[str]:
        """
        Pre-submission validation.
        Returns list of warnings/errors.
        """
        warnings = []

        # 1. Check target scope
        assessment = self.scope.assess_finding(finding.target, finding.vuln_type)
        if not assessment["eligible"]:
            for reason in assessment["rejection_reasons"]:
                warnings.append(f"❌ SCOPE: {reason}")

        # 2. Check PoC is minimal
        if finding.poc_command:
            valid, reason = self.scope.poc_is_minimal(finding.poc_command)
            if not valid:
                warnings.append(f"❌ POC: {reason}")

        if finding.poc_curl:
            valid, reason = self.scope.poc_is_minimal(finding.poc_curl)
            if not valid:
                warnings.append(f"❌ POC: {reason}")

        # 3. Check required fields
        if not finding.steps_to_reproduce:
            warnings.append("❌ STEPS: Missing steps to reproduce")
        if not finding.impact:
            warnings.append("❌ IMPACT: Missing impact statement")
        if not finding.poc_curl and not finding.poc_command:
            warnings.append("❌ POC: No PoC provided — VK requires minimal proof")
        if not finding.screenshots and not finding.video_url:
            warnings.append("⚠️  EVIDENCE: No screenshots/video — VK requires visual proof")

        # 4. Check vuln type is allowed
        if not self.scope.allowed_vuln_type(finding.vuln_type):
            warnings.append(f"❌ TYPE: '{finding.vuln_type}' is excluded from VK bounty — will NOT be paid")

        # 5. Check for generic away.php redirect
        if finding.vuln_type == "Open Redirect" and "away.php" in (finding.endpoint or ""):
            warnings.append(
                "⚠️  AWAY.PHP: Generic open redirects via away.php are NOT paid "
                "unless you demonstrate full session token theft"
            )

        return warnings

    def _generate_title(self, finding: VKFinding) -> str:
        """Generate a clear, concise title following VK format."""
        # VK prefers: [Vuln Type] in [Component] — [Impact]
        parts = [f"[{finding.vuln_type}]"]
        if finding.target:
            parts.append(f"in {finding.target}")
        if finding.endpoint:
            parts.append(f"({finding.endpoint})")
        if finding.impact:
            parts.append(f"— {finding.impact[:60]}")
        return " ".join(parts)

    def _generate_impact_section(self, finding: VKFinding) -> str:
        """Generate impact analysis per VK's criteria."""
        assessment = self.scope.assess_finding(finding.target, finding.vuln_type)
        category = self.scope.bounty_category(finding.vuln_type)

        lines = []
        lines.append(f"**Severity**: {assessment.get('vk_tier', 'Unknown')} target")
        if category:
            bounty_info = VK_BOUNTY_MATRIX.get(category, {})
            lines.append(f"**Bounty Category**: {category.value}")
            lines.append(f"**Max Bounty**: {bounty_info.get('max_bounty', 'Unknown')}")

        lines.append("")
        if finding.impact:
            lines.append(finding.impact)
        else:
            lines.append("Impact assessment required.")

        lines.append("")
        lines.append(f"**Affected Users**: {finding.affected_users}")
        lines.append(f"**Authentication Required**: {'Yes' if finding.authentication_required else 'No'}")

        if assessment.get("max_bounty_qualifies"):
            lines.append("")
            lines.append("**⚠️ MAXIMUM BOUNTY ELIGIBLE** — This finding qualifies for VK's highest payout category.")

        return "\n".join(lines)

    def _generate_steps(self, finding: VKFinding) -> str:
        """Format reproduction steps."""
        lines = []
        for i, step in enumerate(finding.steps_to_reproduce, 1):
            lines.append(f"{i}. {step}")
        return "\n".join(lines)

    def _generate_poc_section(self, finding: VKFinding) -> str:
        """Generate minimal PoC section."""
        sections = []

        if finding.poc_curl:
            sections.append(f"```bash\n{finding.poc_curl}\n```")

        if finding.poc_command:
            sections.append(f"**Minimal command**:\n```\n{finding.poc_command}\n```")

        return "\n\n".join(sections)

    def generate(self, finding: VKFinding) -> VKReport:
        """
        Generate a complete VK-formatted report.
        Returns VKReport with markdown and validation warnings.
        """
        warnings = self.validate_finding(finding)
        assessment = self.scope.assess_finding(finding.target, finding.vuln_type)
        title = self._generate_title(finding)

        # Build markdown report
        md_parts = []

        # Header
        md_parts.append(f"# {title}\n")

        # Metadata
        md_parts.append("## Metadata\n")
        md_parts.append(f"| Field | Value |")
        md_parts.append(f"|-------|-------|")
        md_parts.append(f"| **Target** | `{finding.target}` |")
        if finding.endpoint:
            md_parts.append(f"| **Endpoint** | `{finding.endpoint}` |")
        md_parts.append(f"| **Vulnerability Type** | {finding.vuln_type} |")
        md_parts.append(f"| **VK Tier** | {assessment.get('vk_tier', 'Unknown')} |")
        md_parts.append(f"| **Bounty Category** | {assessment.get('bounty_category', 'unknown')} |")
        md_parts.append(f"| **Date** | {datetime.now().strftime('%Y-%m-%d')} |")
        md_parts.append("")

        # Eligibility Status
        if assessment["eligible"]:
            md_parts.append("## ✅ Scope Status: ELIGIBLE\n")
            if assessment.get("guidance"):
                md_parts.append(f"*{assessment['guidance']}*\n")
        else:
            md_parts.append("## ❌ Scope Status: NOT ELIGIBLE\n")
            for reason in assessment.get("rejection_reasons", []):
                md_parts.append(f"- {reason}")
            md_parts.append("")

        # Description
        md_parts.append("## Description\n")
        md_parts.append(finding.description or "No description provided.\n")

        # Impact Analysis
        md_parts.append("## Impact Analysis\n")
        md_parts.append(self._generate_impact_section(finding))
        md_parts.append("")

        # Steps to Reproduce
        md_parts.append("## Steps to Reproduce\n")
        md_parts.append(self._generate_steps(finding))
        md_parts.append("")

        # PoC
        md_parts.append("## Proof of Concept\n")
        md_parts.append(self._generate_poc_section(finding))
        md_parts.append("")

        # Evidence
        md_parts.append("## Evidence\n")
        if finding.screenshots:
            md_parts.append("**Screenshots**:")
            for s in finding.screenshots:
                md_parts.append(f"- ![{s}]({s})")
            md_parts.append("")
        if finding.video_url:
            md_parts.append(f"**Screen Recording**: {finding.video_url}\n")
        if not finding.screenshots and not finding.video_url:
            md_parts.append("**⚠️ REQUIRED**: Attach clear screenshots or screen recording showing the vulnerability in action.\n")

        # Remediation (optional but appreciated)
        if finding.extra_evidence.get("remediation"):
            md_parts.append("## Suggested Remediation\n")
            md_parts.append(finding.extra_evidence["remediation"])
            md_parts.append("")

        # References
        if finding.references:
            md_parts.append("## References\n")
            for ref in finding.references:
                md_parts.append(f"- {ref}")
            md_parts.append("")

        # Submission Warnings
        if warnings:
            md_parts.append("---\n")
            md_parts.append("## ⚠️ Pre-Submission Checklist\n")
            for w in warnings:
                md_parts.append(f"- {w}")
            md_parts.append("")

        # Footer
        md_parts.append("---\n")
        md_parts.append("*Report generated by Demogorgon VK Bug Bounty Module*")
        md_parts.append(f"*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")

        markdown = "\n".join(md_parts)

        return VKReport(
            markdown=markdown,
            title=title,
            finding=finding,
            assessment=assessment,
            submission_warnings=warnings,
        )

    def save(self, report: VKReport, path: str) -> Path:
        """Save report to file."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(report.markdown, encoding="utf-8")
        return p

    def save_json(self, report: VKReport, path: str) -> Path:
        """Save report as JSON for programmatic consumption."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "title": report.title,
            "finding": {
                "title": report.finding.title,
                "vuln_type": report.finding.vuln_type,
                "target": report.finding.target,
                "endpoint": report.finding.endpoint,
                "description": report.finding.description,
                "steps_to_reproduce": report.finding.steps_to_reproduce,
                "poc_curl": report.finding.poc_curl,
                "poc_command": report.finding.poc_command,
                "impact": report.finding.impact,
                "affected_users": report.finding.affected_users,
                "authentication_required": report.finding.authentication_required,
                "screenshots": report.finding.screenshots,
                "video_url": report.finding.video_url,
            },
            "assessment": report.assessment,
            "submission_warnings": report.submission_warnings,
            "generated_at": datetime.now().isoformat(),
        }
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return p


# ─── CLI Demo ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    from rich.console import Console

    console = Console()
    gen = VKReportGenerator()

    # Demo: IDOR finding on VK ID
    demo_finding = VKFinding(
        title="IDOR in VK ID Profile API",
        vuln_type="IDOR",
        target="id.vk.com",
        endpoint="/api/profile/get",
        description=(
            "The VK ID profile endpoint at /api/profile/get accepts a user_id parameter "
            "without verifying the requesting user's authorization. By changing the user_id "
            "value, any authenticated user can retrieve private profile data of other users "
            "including email, phone number, and full name."
        ),
        steps_to_reproduce=[
            "Authenticate to VK ID and capture the API request to /api/profile/get",
            "Note the user_id parameter in the request body",
            "Change the user_id to any other valid user ID",
            "Send the modified request",
            "Observe that private profile data of the other user is returned",
        ],
        poc_curl=(
            'curl -X POST https://id.vk.com/api/profile/get '
            '-H "Authorization: Bearer <YOUR_TOKEN>" '
            '-d "user_id=<VICTIM_USER_ID>"'
        ),
        poc_command="",
        impact=(
            "Any authenticated VK user can read private profile data (email, phone, full name) "
            "of any other VK user by manipulating the user_id parameter. "
            "This affects all VK users with a VK ID account."
        ),
        affected_users="all",
        authentication_required=True,
        screenshots=["idor_evidence.png"],
    )

    report = gen.generate(demo_finding)

    console.rule("[bold red]VK Report Demo — IDOR Finding[/bold red]")
    console.print(report.markdown)

    if report.submission_warnings:
        console.rule("[bold yellow]Warnings[/bold yellow]")
        for w in report.submission_warnings:
            console.print(f"  {w}")
