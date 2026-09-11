"""ReportGenerator — generates reports from validated findings."""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """A single validated finding for reporting."""
    title: str = ""
    severity: str = "unknown"
    cvss: str = ""
    vuln_class: str = ""
    endpoint: str = ""
    method: str = ""
    description: str = ""
    impact: str = ""
    remediation: str = ""
    reproduction_steps: list[str] = field(default_factory=list)
    request_response_pairs: list[dict[str, Any]] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "cvss": self.cvss,
            "vuln_class": self.vuln_class,
            "endpoint": self.endpoint,
            "method": self.method,
            "description": self.description,
            "impact": self.impact,
            "remediation": self.remediation,
            "reproduction_steps": self.reproduction_steps,
            "request_response_pairs": self.request_response_pairs,
            "references": self.references,
            "metadata": self.metadata,
        }


@dataclass
class Report:
    """A complete report of findings."""
    target: str = ""
    program: str = ""
    generated_at: float = field(default_factory=time.time)
    findings: list[Finding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "program": self.program,
            "generated_at": self.generated_at,
            "total_findings": self.total_findings,
            "severity_counts": self.severity_counts,
            "findings": [f.to_dict() for f in self.findings],
            "stats": self.stats,
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Report:
        return cls(
            target=data.get("target", ""),
            program=data.get("program", ""),
            generated_at=data.get("generated_at", 0),
            findings=[Finding(**f) for f in data.get("findings", [])],
            stats=data.get("stats", {}),
            metadata=data.get("metadata", {}),
        )


class ReportGenerator:
    """Generates reports from validated findings.

    Produces JSON and Markdown reports suitable for submission
    to bug bounty programs.
    """

    def __init__(self, workspace_dir: str = ""):
        self._workspace_dir = workspace_dir

    def generate(
        self,
        findings: list[Finding],
        target: str = "",
        program: str = "",
        stats: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Report:
        """Generate a report from findings."""
        return Report(
            target=target,
            program=program,
            findings=findings,
            stats=stats or {},
            metadata=metadata or {},
        )

    def save_json(self, report: Report, path: str | None = None) -> str:
        """Save report as JSON. Returns the file path."""
        if not path:
            if not self._workspace_dir:
                raise ValueError("No workspace_dir and no path specified")
            path = os.path.join(self._workspace_dir, "report.json")

        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as f:
            f.write(report.to_json())

        logger.info(f"JSON report saved: {path}")
        return path

    def save_markdown(self, report: Report, path: str | None = None) -> str:
        """Save report as Markdown. Returns the file path."""
        if not path:
            if not self._workspace_dir:
                raise ValueError("No workspace_dir and no path specified")
            path = os.path.join(self._workspace_dir, "report.md")

        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        md = self._to_markdown(report)
        with open(path, "w") as f:
            f.write(md)

        logger.info(f"Markdown report saved: {path}")
        return path

    def _to_markdown(self, report: Report) -> str:
        """Convert report to Markdown format."""
        lines = [
            f"# Bug Bounty Report",
            f"",
            f"**Target:** {report.target}",
            f"**Program:** {report.program}" if report.program else "",
            f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(report.generated_at))}",
            f"",
            f"## Summary",
            f"",
            f"**Total Findings:** {report.total_findings}",
            f"",
        ]

        severity_counts = report.severity_counts
        if severity_counts:
            lines.append("| Severity | Count |")
            lines.append("|----------|-------|")
            for sev in ["critical", "high", "medium", "low", "informational"]:
                if sev in severity_counts:
                    lines.append(f"| {sev.capitalize()} | {severity_counts[sev]} |")
            lines.append("")

        if report.findings:
            lines.append("## Findings")
            lines.append("")

            for i, finding in enumerate(report.findings, 1):
                lines.append(f"### {i}. {finding.title}")
                lines.append(f"")
                lines.append(f"- **Severity:** {finding.severity}")
                if finding.cvss:
                    lines.append(f"- **CVSS:** {finding.cvss}")
                lines.append(f"- **Type:** {finding.vuln_class}")
                lines.append(f"- **Endpoint:** `{finding.method} {finding.endpoint}`" if finding.method else f"- **Endpoint:** `{finding.endpoint}`")
                lines.append(f"")

                if finding.description:
                    lines.append(f"**Description:** {finding.description}")
                    lines.append(f"")

                if finding.reproduction_steps:
                    lines.append("**Steps to Reproduce:**")
                    lines.append("")
                    for j, step in enumerate(finding.reproduction_steps, 1):
                        lines.append(f"{j}. {step}")
                    lines.append("")

                if finding.impact:
                    lines.append(f"**Impact:** {finding.impact}")
                    lines.append(f"")

                if finding.remediation:
                    lines.append(f"**Remediation:** {finding.remediation}")
                    lines.append(f"")

                if finding.request_response_pairs:
                    lines.append("<details>")
                    lines.append("<summary>Request/Response</summary>")
                    lines.append("")
                    for pair in finding.request_response_pairs:
                        req = pair.get("request", {})
                        resp = pair.get("response", {})
                        lines.append(f"```http")
                        lines.append(f"{req.get('method', 'GET')} {req.get('url', '/')} HTTP/1.1")
                        for k, v in req.get("headers", {}).items():
                            lines.append(f"{k}: {v}")
                        if req.get("body"):
                            lines.append(f"")
                            lines.append(req["body"])
                        lines.append(f"```")
                        lines.append(f"")
                        lines.append(f"```")
                        lines.append(f"HTTP/1.1 {resp.get('status_code', 200)}")
                        for k, v in resp.get("headers", {}).items():
                            lines.append(f"{k}: {v}")
                        if resp.get("body"):
                            lines.append(f"")
                            body = resp["body"]
                            if len(body) > 500:
                                body = body[:500] + "...(truncated)"
                            lines.append(body)
                        lines.append(f"```")
                        lines.append("")
                    lines.append("</details>")
                    lines.append("")

                lines.append("---")
                lines.append("")

        return "\n".join(lines)

    def get_summary(self, report: Report) -> str:
        """Get a human-readable summary of the report."""
        lines = [
            f"Report: {report.target}",
            f"Findings: {report.total_findings}",
        ]
        severity_counts = report.severity_counts
        for sev in ["critical", "high", "medium", "low", "informational"]:
            if sev in severity_counts:
                lines.append(f"  {sev}: {severity_counts[sev]}")
        return "\n".join(lines)
