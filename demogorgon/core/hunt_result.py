"""HuntResult — the canonical, honest result of a single hunt (Phase 10).

One object per engagement run. It is built from the runner summary and
carries the three things a hunter actually needs after a run:

1. What happened (status + why, in words)
2. What was found (findings, chains, report path)
3. How much was actually covered (HuntCoverage)

Nothing here is inferred or embellished — every field is copied from run
data, and unknown values stay unknown.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .coverage import HuntCoverage, build_coverage

# Human explanation per status — the CLI and report both use this.
STATUS_EXPLANATION = {
    "completed": "Research loop finished normally.",
    "partial": "Run stopped early; results are incomplete.",
    "degraded": "Run produced results, but at least one capability was "
                "missing or failing (e.g. no LLM, recon stage errors).",
    "blocked": "No research engine could run (no LLM provider and the "
               "deterministic backbone was unavailable).",
    "failed": "The run raised an error before producing results.",
    "cancelled": "The run was cancelled by the user; state was saved "
                 "and can be resumed.",
    "unknown": "Status was not reported by the runner.",
}

# Statuses that mean the run did NOT fully succeed.
TERMINAL_FAILURE_STATUSES = {"failed", "blocked"}
PARTIAL_STATUSES = {"partial", "degraded", "cancelled"}


@dataclass
class HuntResult:
    """Canonical result of one engagement run."""

    engagement_id: str = ""
    target: str = ""
    status: str = "unknown"
    error: str = ""
    notes: list[str] = field(default_factory=list)

    duration: float = 0.0
    iterations: int = 0

    findings: list[dict[str, Any]] = field(default_factory=list)
    chains: list[dict[str, Any]] = field(default_factory=list)
    report_path: str = ""

    stats: dict[str, Any] = field(default_factory=dict)
    coverage: HuntCoverage = field(default_factory=HuntCoverage)

    # ── construction ──────────────────────────────────────────────

    @classmethod
    def from_summary(
        cls,
        summary: dict[str, Any],
        *,
        scope_assets: list[Any] | None = None,
        llm_used: bool | None = None,
    ) -> HuntResult:
        """Build a HuntResult from an AutonomousRunner summary dict."""
        stats = summary.get("stats") or {}
        research_report = {
            "iterations": summary.get("iterations", 0),
            "findings": summary.get("findings") or [],
            "stats": stats.get("research") or {},
            "error": summary.get("error") or "",
        }
        if llm_used is None:
            notes = summary.get("status_notes") or []
            llm_used = not any("no llm" in n.lower() or "llm: unavailable" in n.lower()
                               for n in notes)

        coverage = build_coverage(
            scope_assets=scope_assets,
            recon_stats=stats.get("recon") or {},
            research_report=research_report,
            llm_used=bool(llm_used),
        )

        return cls(
            engagement_id=str(summary.get("engagement_id", "")),
            target=str(summary.get("target", "")),
            status=str(summary.get("status", "unknown")).lower(),
            error=str(summary.get("error") or ""),
            notes=list(summary.get("status_notes") or []),
            duration=float(summary.get("duration", 0.0) or 0.0),
            iterations=int(summary.get("iterations", 0) or 0),
            findings=list(summary.get("findings") or []),
            chains=list(summary.get("chains") or []),
            report_path=str(summary.get("report_path") or ""),
            stats=stats,
            coverage=coverage,
        )

    # ── status helpers ────────────────────────────────────────────

    @property
    def ok(self) -> bool:
        """True only when the run completed without degradation."""
        return self.status == "completed"

    @property
    def succeeded(self) -> bool:
        """True when the run produced usable results (even if degraded)."""
        return self.status in ("completed", "degraded", "partial")

    @property
    def failed(self) -> bool:
        return self.status in TERMINAL_FAILURE_STATUSES

    @property
    def explanation(self) -> str:
        return STATUS_EXPLANATION.get(self.status, STATUS_EXPLANATION["unknown"])

    # ── serialization / display ───────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        return {
            "engagement_id": self.engagement_id,
            "target": self.target,
            "status": self.status,
            "status_explanation": self.explanation,
            "error": self.error,
            "notes": list(self.notes),
            "duration": self.duration,
            "iterations": self.iterations,
            "findings_count": len(self.findings),
            "chains_count": len(self.chains),
            "report_path": self.report_path,
            "stats": self.stats,
            "coverage": self.coverage.to_dict(),
        }

    def describe(self) -> str:
        """Multi-line human summary — status first, never 'Complete'."""
        label = self.status.upper()
        lines = [
            f"HUNT {label} — {self.target or self.engagement_id}",
            f"  {self.explanation}",
        ]
        if self.error:
            lines.append(f"  error: {self.error}")
        if self.notes:
            lines.extend(f"  note: {n}" for n in self.notes)
        lines.append(f"  findings: {len(self.findings)}  chains: {len(self.chains)}  "
                     f"iterations: {self.iterations}  duration: {self.duration:.1f}s")
        lines.append(self.coverage.describe())
        if self.report_path:
            lines.append(f"  report: {self.report_path}")
        return "\n".join(lines)
