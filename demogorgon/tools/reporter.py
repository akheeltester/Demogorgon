"""Reporter — generates Markdown reports with evidence chains, CVSS, and PoC.

Every report answers the 5 required questions:
1. Why was this investigated?
2. What security boundary was crossed?
3. How is it reproduced?
4. What is the impact?
5. What evidence supports it?

Also includes CVSS 3.1 vectors, automated PoC (curl + transcript),
remediation suggestions, and HackerOne/Bugcrowd format templates.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from rich.console import Console

console = Console()

# Remediation templates by vuln class
REMEDIATION: dict[str, str] = {
    "ssrf": (
        "1. Allowlist outbound request destinations (scheme + host + port).\n"
        "2. Block link-local/metadata IPs (169.254.0.0/16, 127.0.0.0/8, 10.0.0.0/8, etc.).\n"
        "3. Disable dangerous URL schemes (file://, gopher://, dict://).\n"
        "4. Follow redirects only within the allowlist; validate each hop.\n"
        "5. Egress-filter at the network layer as defense-in-depth."
    ),
    "file_upload": (
        "1. Store uploads outside the web root; serve via a non-executable handler.\n"
        "2. Validate extension against an allowlist; re-encode/sanitize content.\n"
        "3. Generate random server-side filenames; never trust client filename.\n"
        "4. Scan for malware; strip active content (SVG/HTML polyglots).\n"
        "5. Set Content-Disposition: attachment and restrictive Content-Type on download."
    ),
    "xss": (
        "1. Context-encode all user-controlled output (HTML/JS/URL/attr).\n"
        "2. Use a strict CSP (no unsafe-inline/eval).\n"
        "3. Set HttpOnly + Secure + SameSite on session cookies.\n"
        "4. Prefer framework auto-escaping; avoid innerHTML/eval/document.write."
    ),
    "sqli": (
        "1. Use parameterized queries / prepared statements exclusively.\n"
        "2. Principle of least privilege for DB accounts.\n"
        "3. Centralize input validation; reject unexpected types.\n"
        "4. Enable WAF rules as defense-in-depth only."
    ),
    "idor": (
        "1. Enforce authorization checks on every object access (server-side).\n"
        "2. Use unpredictable identifiers (UUIDs) as defense-in-depth, not as auth.\n"
        "3. Verify ownership scoping in the data layer (tenant/user filters)."
    ),
    "access_control": (
        "1. Default-deny authorization at every trust boundary.\n"
        "2. Centralize policy checks; avoid scattered ad-hoc role checks.\n"
        "3. Add automated tests for horizontal + vertical privilege boundaries."
    ),
    "auth_bypass": (
        "1. Centralize authentication middleware; fail closed.\n"
        "2. Validate token signature, audience, issuer, and expiry on every request.\n"
        "3. Do not trust client-supplied identity headers."
    ),
    "privilege_escalation": (
        "1. Enforce role checks server-side; never trust client role fields.\n"
        "2. Strip privileged fields from mass-assignment endpoints.\n"
        "3. Audit all privilege transitions with logging."
    ),
    "csrf": (
        "1. Require anti-CSRF tokens on all state-changing requests.\n"
        "2. Use SameSite=Lax/Strict cookies.\n"
        "3. Verify Origin/Referer for sensitive endpoints."
    ),
    "cors": (
        "1. Avoid Access-Control-Allow-Origin: * with credentials.\n"
        "2. Allowlist exact origins; never reflect arbitrary Origin.\n"
        "3. Minimize allowed methods/headers."
    ),
    "open_redirect": (
        "1. Allowlist redirect targets (path-relative or known hosts only).\n"
        "2. Reject absolute external URLs in redirect parameters.\n"
        "3. Prefer server-side redirect maps over user-controlled URLs."
    ),
    "ssti": (
        "1. Never render user input as a template.\n"
        "2. Sandbox template engines; disable dangerous filters/globals.\n"
        "3. Prefer logic-less templates (e.g. Mustache) where possible."
    ),
    "xxe": (
        "1. Disable DTDs / external entity resolution in XML parsers.\n"
        "2. Use JSON instead of XML where feasible.\n"
        "3. Apply least-privilege to the parser process."
    ),
    "jwt": (
        "1. Force HS256/RS256 allowlist; reject alg:none.\n"
        "2. Validate iss/aud/exp; use short-lived tokens + refresh.\n"
        "3. Keep signing keys rotated and out of client code."
    ),
    "info_disclosure": (
        "1. Strip stack traces/debug info from production responses.\n"
        "2. Minimize verbose headers (Server, X-Powered-By).\n"
        "3. Centralize error handling."
    ),
    "business_logic": (
        "1. Re-validate business rules server-side on every state change.\n"
        "2. Use idempotency keys for money/quantity operations.\n"
        "3. Add negative tests for price/quantity/step manipulation."
    ),
    "race": (
        "1. Serialize critical sections (locks / DB transactions / idempotency keys).\n"
        "2. Use optimistic concurrency (version columns) for updates.\n"
        "3. Reject concurrent duplicate submissions."
    ),
    "unknown": "Review the finding and apply defense-in-depth controls for the affected component.",
}


class Reporter:
    """Generates Markdown reports for findings."""

    def __init__(self, output_dir: str = "hunt_output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _remediation(vuln_class: str) -> str:
        return REMEDIATION.get((vuln_class or "unknown").lower(), REMEDIATION["unknown"])

    @staticmethod
    def _cvss_block(finding: dict[str, Any]) -> list[str]:
        lines: list[str] = []
        cvss = finding.get("cvss")
        if not cvss:
            try:
                from demogorgon.core.cvss import score_finding_cvss
                cvss = score_finding_cvss(finding).to_dict()
            except Exception:
                return lines
        if cvss and cvss.get("base_score", 0) > 0:
            lines.append(f"**CVSS 3.1:** `{cvss.get('vector', 'N/A')}`  ")
            lines.append(f"**Base Score:** **{cvss.get('base_score', 0)}** ({cvss.get('severity', 'N/A')})")
            lines.append("")
        return lines

    @staticmethod
    def _poc_block(finding: dict[str, Any]) -> list[str]:
        lines: list[str] = []
        poc = finding.get("poc")
        if not poc:
            try:
                from demogorgon.core.poc import generate_poc_from_finding
                poc = generate_poc_from_finding(finding)
            except Exception:
                return lines
        if not poc:
            return lines
        lines.append("#### Proof of Concept")
        lines.append("")
        steps = poc.get("steps") or []
        for i, step in enumerate(steps, 1):
            lines.append(f"{i}. {step}")
        lines.append("")
        if poc.get("curl"):
            lines.append("```bash")
            lines.append(poc["curl"])
            lines.append("```")
            lines.append("")
        if poc.get("transcript"):
            lines.append("```http")
            lines.append(poc["transcript"])
            lines.append("```")
            lines.append("")
        return lines

    @staticmethod
    def _platform_template(finding: dict[str, Any], platform: str = "hackerone") -> list[str]:
        """Render a HackerOne / Bugcrowd style report block for one finding."""
        lines: list[str] = []
        title = finding.get("title", "Unknown")
        severity = finding.get("severity", "info").upper()
        endpoint = finding.get("endpoint", "N/A")
        method = finding.get("method", "GET")
        impact = finding.get("impact", "Impact assessment pending")
        cvss = finding.get("cvss") or {}

        lines.append(f"### [{platform.upper()}] {title}")
        lines.append("")
        lines.append(f"**Severity:** {severity}")
        if cvss.get("vector"):
            lines.append(f"**CVSS:** `{cvss['vector']}` (Base {cvss.get('base_score', 0)})")
        lines.append(f"**Asset:** `{method} {endpoint}`")
        lines.append("")
        lines.append("**Summary**")
        lines.append("")
        lines.append(impact)
        lines.append("")
        return lines

    def generate_hunt_report(
        self,
        target_url: str,
        findings: list[dict[str, Any]],
        app_model: dict[str, Any],
        memory_summary: dict[str, Any],
        reasoning_trace: list[dict[str, Any]],
        metrics: dict[str, Any] | None = None,
    ) -> str:
        """Generate a complete hunt report (with CVSS, PoC, metrics, remediation)."""
        lines = []

        # Ensure findings have CVSS + PoC
        try:
            from demogorgon.core.cvss import enhance_finding_with_cvss
            from demogorgon.core.poc import generate_poc_from_finding
            for f in findings:
                if "cvss" not in f:
                    enhance_finding_with_cvss(f)
                if "poc" not in f:
                    try:
                        f["poc"] = generate_poc_from_finding(f)
                    except Exception:
                        f["poc"] = None
        except Exception:
            pass

        # Header
        lines.append(f"# Demogorgon Hunt Report")
        lines.append(f"")
        lines.append(f"**Target:** {target_url}")
        lines.append(f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**Runtime:** {memory_summary.get('runtime_seconds', 0):.0f}s")
        lines.append(f"**Experiments:** {memory_summary.get('endpoints_tested', 0)}")
        lines.append(f"**Findings:** {len(findings)}")
        lines.append(f"")

        # Metrics (P2)
        if metrics:
            lines.append(f"## Hunt Metrics")
            lines.append(f"")
            for k in (
                "runtime_seconds", "endpoints_discovered", "subdomains_discovered",
                "experiments_run", "requests_made", "parallel_batches",
                "llm_calls", "findings_total", "reportable_count",
                "findings_per_minute", "endpoints_per_minute",
            ):
                if k in metrics:
                    lines.append(f"- **{k.replace('_', ' ').title()}:** {metrics[k]}")
            if metrics.get("findings_by_severity"):
                sev = ", ".join(f"{k}:{v}" for k, v in metrics["findings_by_severity"].items())
                lines.append(f"- **By severity:** {sev}")
            if metrics.get("findings_by_class"):
                cls = ", ".join(f"{k}:{v}" for k, v in metrics["findings_by_class"].items())
                lines.append(f"- **By class:** {cls}")
            lines.append(f"")

        # Executive Summary
        lines.append(f"## Executive Summary")
        lines.append(f"")
        lines.append(f"The autonomous security researcher analyzed {target_url} and discovered "
                     f"{len(findings)} potential vulnerabilities across "
                     f"{memory_summary.get('endpoints_discovered', 0)} endpoints.")
        lines.append(f"")

        # Application Model Summary
        lines.append(f"## Application Model")
        lines.append(f"")
        lines.append(f"- **Product Type:** {app_model.get('product_type', 'unknown')}")
        lines.append(f"- **Description:** {app_model.get('product_description', 'N/A')}")
        lines.append(f"- **Tech Stack:** {', '.join(app_model.get('tech_stack', []))}")
        lines.append(f"- **API Style:** {app_model.get('api_style', 'unknown')}")
        lines.append(f"- **Model Confidence:** {app_model.get('confidence', 0):.0%}")
        lines.append(f"")

        # Roles
        roles = app_model.get("user_roles", [])
        if roles:
            lines.append(f"### User Roles")
            for role in roles:
                lines.append(f"- **{role.get('name', 'unknown')}** (level {role.get('level', 0)}): {role.get('description', '')}")
            lines.append(f"")

        # Business Objects
        objects = app_model.get("business_objects", [])
        if objects:
            lines.append(f"### Business Objects")
            by_type: dict[str, list] = {}
            for obj in objects:
                obj_type = obj.get("object_type", "unknown")
                by_type.setdefault(obj_type, []).append(obj)
            for obj_type, obj_list in by_type.items():
                lines.append(f"- **{obj_type}:** {len(obj_list)} instances")
            lines.append(f"")

        # Trust Boundaries
        boundaries = app_model.get("trust_boundaries", [])
        if boundaries:
            lines.append(f"### Trust Boundaries")
            for b in boundaries:
                lines.append(f"- **{b.get('name', 'unknown')}:** {b.get('from_level', '?')} → {b.get('to_level', '?')} ({b.get('boundary_type', 'unknown')})")
            lines.append(f"")

        # Findings
        if findings:
            lines.append(f"## Findings")
            lines.append(f"")

            # Sort by severity then CVSS
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            def _sort_key(f: dict[str, Any]):
                sev = severity_order.get(f.get("severity", "info"), 5)
                cvss_score = (f.get("cvss") or {}).get("base_score", 0) or 0
                return (sev, -cvss_score)
            sorted_findings = sorted(findings, key=_sort_key)

            for i, finding in enumerate(sorted_findings, 1):
                severity = finding.get("severity", "info").upper()
                lines.append(f"### {i}. [{severity}] {finding.get('title', 'Unknown')}")
                lines.append(f"")
                lines.append(f"**Endpoint:** `{finding.get('method', 'GET')} {finding.get('endpoint', 'N/A')}`")
                lines.append(f"**Vuln Class:** {finding.get('vuln_class', 'unknown')}")
                lines.append(f"**Confidence:** {finding.get('confidence', 0):.0%}")
                lines.append(f"")

                # CVSS
                lines.extend(self._cvss_block(finding))

                # 5-dimension score breakdown (if available)
                score_reasoning = finding.get("score_reasoning")
                if score_reasoning:
                    lines.append(f"**Score Breakdown:**")
                    lines.append(f"- {score_reasoning}")
                    lines.append(f"")

                # Question 1: Why was this investigated?
                lines.append(f"#### Why was this investigated?")
                lines.append(f"")
                reasoning = finding.get("reasoning", "No reasoning provided")
                lines.append(f"{reasoning}")
                lines.append(f"")

                # Question 2: What security boundary was crossed?
                lines.append(f"#### What security boundary was crossed?")
                lines.append(f"")
                boundary = finding.get("boundary_crossed", "Security boundary was crossed")
                lines.append(f"{boundary}")
                lines.append(f"")

                # Question 3: How is it reproduced? (now includes automated PoC)
                lines.append(f"#### How is it reproduced?")
                lines.append(f"")
                reproduction = finding.get("reproduction", [])
                if reproduction:
                    for step in reproduction:
                        lines.append(f"1. {step}")
                else:
                    lines.append(f"See PoC below.")
                lines.append(f"")
                lines.extend(self._poc_block(finding))

                # Question 4: What is the impact?
                lines.append(f"#### What is the impact?")
                lines.append(f"")
                impact = finding.get("impact", "Impact assessment pending")
                lines.append(f"{impact}")
                lines.append(f"")

                # Remediation (P2)
                vc = finding.get("vuln_class", "unknown")
                lines.append(f"#### Remediation")
                lines.append(f"")
                lines.append(self._remediation(vc))
                lines.append(f"")

                # Question 5: What evidence supports it?
                lines.append(f"#### What evidence supports it?")
                lines.append(f"")
                evidence = finding.get("evidence", "")
                if evidence:
                    lines.append(f"```")
                    if isinstance(evidence, list):
                        lines.append(json.dumps(evidence, indent=2, default=str)[:2000])
                    else:
                        lines.append(str(evidence))
                    lines.append(f"```")
                lines.append(f"")

                lines.append(f"---")
                lines.append(f"")
        else:
            lines.append(f"## Findings")
            lines.append(f"")
            lines.append(f"No vulnerabilities were confirmed during this hunt.")
            lines.append(f"")

        # Platform templates (HackerOne / Bugcrowd) for top findings
        if findings:
            lines.append(f"## Platform Templates")
            lines.append(f"")
            top = findings[:3]
            for platform in ("hackerone", "bugcrowd"):
                lines.append(f"### {platform.title()} ready blocks")
                lines.append(f"")
                for f in top:
                    lines.extend(self._platform_template(f, platform))
                    steps = f.get("reproduction") or (f.get("poc") or {}).get("steps") or []
                    if steps:
                        lines.append("**Steps to reproduce:**")
                        for i, s in enumerate(steps, 1):
                            lines.append(f"{i}. {s}")
                        lines.append("")
                lines.append(f"---")
                lines.append(f"")

        # Reasoning Trace Summary
        if reasoning_trace:
            lines.append(f"## Research Process")
            lines.append(f"")
            lines.append(f"The researcher performed {len(reasoning_trace)} reasoning steps:")
            lines.append(f"")
            for i, step in enumerate(reasoning_trace[-10:], 1):
                lines.append(f"{i}. **{step.get('action', 'N/A')}** — Confidence: {step.get('confidence', 0):.0%}")
                if step.get('hypothesis'):
                    lines.append(f"   Hypothesis: {step.get('hypothesis', '')[:100]}")
            lines.append(f"")

        # Write report
        report_path = self.output_dir / "REPORT.md"
        report_path.write_text("\n".join(lines))
        console.print(f"[cyan]Report saved to {report_path}[/cyan]")

        return "\n".join(lines)

    def generate_finding_report(self, finding: dict[str, Any]) -> str:
        """Generate a report for a single finding (HackerOne-ready format)."""
        # Ensure CVSS + PoC
        try:
            from demogorgon.core.cvss import enhance_finding_with_cvss
            from demogorgon.core.poc import generate_poc_from_finding
            if "cvss" not in finding:
                enhance_finding_with_cvss(finding)
            if "poc" not in finding:
                finding["poc"] = generate_poc_from_finding(finding)
        except Exception:
            pass

        lines = []

        severity = finding.get("severity", "info").upper()
        lines.append(f"# [{severity}] {finding.get('title', 'Unknown')}")
        lines.append(f"")
        lines.append(f"## Summary")
        lines.append(f"")
        lines.append(f"{finding.get('impact', 'No impact description')}")
        lines.append(f"")

        # CVSS
        lines.extend(self._cvss_block(finding))

        lines.append(f"## Vulnerability Details")
        lines.append(f"")
        lines.append(f"**Endpoint:** `{finding.get('method', 'GET')} {finding.get('endpoint', 'N/A')}`")
        lines.append(f"**Vuln Class:** {finding.get('vuln_class', 'unknown')}")
        lines.append(f"**Confidence:** {finding.get('confidence', 0):.0%}")
        lines.append(f"")

        score_reasoning = finding.get("score_reasoning")
        if score_reasoning:
            lines.append(f"**Confidence Breakdown:**")
            lines.append(f"- {score_reasoning}")
            lines.append(f"")

        lines.append(f"## Steps to Reproduce")
        lines.append(f"")
        reproduction = finding.get("reproduction", [])
        if reproduction:
            for i, step in enumerate(reproduction, 1):
                lines.append(f"{i}. {step}")
        else:
            lines.append(f"See PoC below.")
        lines.append(f"")

        # PoC
        lines.extend(self._poc_block(finding))

        lines.append(f"## Impact")
        lines.append(f"")
        lines.append(f"{finding.get('impact', 'Impact assessment pending')}")
        lines.append(f"")

        # Remediation
        lines.append(f"## Remediation")
        lines.append(f"")
        lines.append(self._remediation(finding.get("vuln_class", "unknown")))
        lines.append(f"")

        lines.append(f"## Evidence")
        lines.append(f"")
        evidence = finding.get("evidence", "")
        if evidence:
            lines.append(f"```")
            if isinstance(evidence, list):
                lines.append(json.dumps(evidence, indent=2, default=str)[:2000])
            else:
                lines.append(str(evidence))
            lines.append(f"```")
        lines.append(f"")

        return "\n".join(lines)

    def save_findings_json(self, findings: list[dict[str, Any]], filename: str = "findings.json"):
        """Save findings as JSON."""
        path = self.output_dir / filename
        path.write_text(json.dumps(findings, indent=2, default=str))
        console.print(f"[cyan]Findings saved to {path}[/cyan]")

    def save_metrics(self, metrics: dict[str, Any], filename: str = "metrics.json"):
        """Save hunt metrics as JSON."""
        path = self.output_dir / filename
        path.write_text(json.dumps(metrics, indent=2, default=str))
        console.print(f"[cyan]Metrics saved to {path}[/cyan]")
        return path
