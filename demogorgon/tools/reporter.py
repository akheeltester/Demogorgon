"""Reporter — generates Markdown reports with evidence chains.

Every report answers the 5 required questions:
1. Why was this investigated?
2. What security boundary was crossed?
3. How is it reproduced?
4. What is the impact?
5. What evidence supports it?
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from rich.console import Console

console = Console()


class Reporter:
    """Generates Markdown reports for findings."""

    def __init__(self, output_dir: str = "hunt_output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_hunt_report(
        self,
        target_url: str,
        findings: list[dict[str, Any]],
        app_model: dict[str, Any],
        memory_summary: dict[str, Any],
        reasoning_trace: list[dict[str, Any]],
    ) -> str:
        """Generate a complete hunt report."""
        lines = []

        # Header
        lines.append(f"# Demogorgon Hunt Report")
        lines.append(f"")
        lines.append(f"**Target:** {target_url}")
        lines.append(f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**Runtime:** {memory_summary.get('runtime_seconds', 0):.0f}s")
        lines.append(f"**Experiments:** {memory_summary.get('endpoints_tested', 0)}")
        lines.append(f"**Findings:** {len(findings)}")
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

            # Sort by severity
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get("severity", "info"), 5))

            for i, finding in enumerate(sorted_findings, 1):
                severity = finding.get("severity", "info").upper()
                lines.append(f"### {i}. [{severity}] {finding.get('title', 'Unknown')}")
                lines.append(f"")
                lines.append(f"**Endpoint:** `{finding.get('method', 'GET')} {finding.get('endpoint', 'N/A')}`")
                lines.append(f"**Vuln Class:** {finding.get('vuln_class', 'unknown')}")
                lines.append(f"**Confidence:** {finding.get('confidence', 0):.0%}")
                lines.append(f"")

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

                # Question 3: How is it reproduced?
                lines.append(f"#### How is it reproduced?")
                lines.append(f"")
                reproduction = finding.get("reproduction", [])
                if reproduction:
                    for step in reproduction:
                        lines.append(f"1. {step}")
                else:
                    lines.append(f"See evidence below.")
                lines.append(f"")

                # Question 4: What is the impact?
                lines.append(f"#### What is the impact?")
                lines.append(f"")
                impact = finding.get("impact", "Impact assessment pending")
                lines.append(f"{impact}")
                lines.append(f"")

                # Question 5: What evidence supports it?
                lines.append(f"#### What evidence supports it?")
                lines.append(f"")
                evidence = finding.get("evidence", "")
                if evidence:
                    lines.append(f"```")
                    lines.append(f"{evidence}")
                    lines.append(f"```")
                lines.append(f"")

                lines.append(f"---")
                lines.append(f"")
        else:
            lines.append(f"## Findings")
            lines.append(f"")
            lines.append(f"No vulnerabilities were confirmed during this hunt.")
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
        lines = []

        severity = finding.get("severity", "info").upper()
        lines.append(f"# [{severity}] {finding.get('title', 'Unknown')}")
        lines.append(f"")
        lines.append(f"## Summary")
        lines.append(f"")
        lines.append(f"{finding.get('impact', 'No impact description')}")
        lines.append(f"")

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
            lines.append(f"See evidence below.")
        lines.append(f"")

        lines.append(f"## Impact")
        lines.append(f"")
        lines.append(f"{finding.get('impact', 'Impact assessment pending')}")
        lines.append(f"")

        lines.append(f"## Evidence")
        lines.append(f"")
        evidence = finding.get("evidence", "")
        if evidence:
            lines.append(f"```")
            lines.append(f"{evidence}")
            lines.append(f"```")
        lines.append(f"")

        return "\n".join(lines)

    def save_findings_json(self, findings: list[dict[str, Any]], filename: str = "findings.json"):
        """Save findings as JSON."""
        path = self.output_dir / filename
        path.write_text(json.dumps(findings, indent=2, default=str))
        console.print(f"[cyan]Findings saved to {path}[/cyan]")
