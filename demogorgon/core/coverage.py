"""Coverage metrics for a hunt — what was actually exercised (Phase 10).

Coverage answers one question honestly: *how much of the attack surface
did we look at, and how much did we test?*  It is deliberately computed
from raw run data (recon counters, research-loop counters, scope assets)
rather than from LLM prose, so a degraded run cannot claim coverage it
did not achieve.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class HuntCoverage:
    """Coverage of a single engagement."""

    # Scope
    scope_assets_total: int = 0
    scope_assets_explicit: int = 0

    # Recon
    recon_stages_total: int = 0
    recon_stages_completed: int = 0
    recon_stages_skipped: int = 0
    subdomains: int = 0
    live_hosts: int = 0
    endpoints_discovered: int = 0

    # Research loop
    iterations: int = 0
    endpoints_tested: int = 0
    vuln_classes_tested: int = 0
    vuln_classes_untested: int = 0
    findings: int = 0

    # Engine
    llm_used: bool = False
    deterministic: bool = False

    notes: list[str] = field(default_factory=list)

    @property
    def recon_ratio(self) -> float:
        if self.recon_stages_total <= 0:
            return 0.0
        return self.recon_stages_completed / self.recon_stages_total

    @property
    def testing_ratio(self) -> float:
        """Fraction of in-scope endpoints that received at least one test."""
        if self.endpoints_discovered <= 0:
            return 0.0
        return min(1.0, self.endpoints_tested / self.endpoints_discovered)

    @property
    def overall(self) -> float:
        """0.0–1.0 headline coverage score.

        Recon completeness and endpoint-testing completeness are weighted
        equally; discovered-but-untested endpoints must drag the score down.
        """
        return round((self.recon_ratio + self.testing_ratio) / 2.0, 3)

    @property
    def grade(self) -> str:
        score = self.overall
        if score >= 0.9:
            return "A"
        if score >= 0.7:
            return "B"
        if score >= 0.5:
            return "C"
        if score >= 0.25:
            return "D"
        return "F"

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope_assets_total": self.scope_assets_total,
            "scope_assets_explicit": self.scope_assets_explicit,
            "recon_stages_total": self.recon_stages_total,
            "recon_stages_completed": self.recon_stages_completed,
            "recon_stages_skipped": self.recon_stages_skipped,
            "recon_ratio": round(self.recon_ratio, 3),
            "subdomains": self.subdomains,
            "live_hosts": self.live_hosts,
            "endpoints_discovered": self.endpoints_discovered,
            "iterations": self.iterations,
            "endpoints_tested": self.endpoints_tested,
            "testing_ratio": round(self.testing_ratio, 3),
            "vuln_classes_tested": self.vuln_classes_tested,
            "vuln_classes_untested": self.vuln_classes_untested,
            "findings": self.findings,
            "llm_used": self.llm_used,
            "deterministic": self.deterministic,
            "overall": self.overall,
            "grade": self.grade,
            "notes": list(self.notes),
        }

    def describe(self) -> str:
        lines = [
            f"Coverage {self.overall:.0%} (grade {self.grade})",
            f"  scope:     {self.scope_assets_explicit}/{self.scope_assets_total} explicit assets",
            f"  recon:     {self.recon_stages_completed}/{self.recon_stages_total} stages "
            f"({self.recon_stages_skipped} skipped)",
            f"  surface:   {self.subdomains} subdomains, {self.live_hosts} hosts, "
            f"{self.endpoints_discovered} endpoints",
            f"  tested:    {self.endpoints_tested} endpoints, "
            f"{self.vuln_classes_tested} vuln classes "
            f"({self.vuln_classes_untested} untested)",
            f"  findings:  {self.findings}",
            f"  engine:    {'llm' if self.llm_used else 'deterministic (no LLM)'}",
        ]
        lines.extend(f"  note:      {n}" for n in self.notes)
        return "\n".join(lines)


def build_coverage(
    *,
    scope_assets: list[Any] | None = None,
    recon_stats: dict[str, Any] | None = None,
    research_report: dict[str, Any] | None = None,
    llm_used: bool = False,
) -> HuntCoverage:
    """Assemble coverage from the raw artifacts of a run.

    All inputs are optional so coverage can be built even from a run that
    died early — the result then honestly reads as ~0 rather than raising.
    """
    cov = HuntCoverage(llm_used=llm_used, deterministic=not llm_used)

    # Scope
    for asset in scope_assets or []:
        cov.scope_assets_total += 1
        explicit = getattr(asset, "is_explicit", None)
        if explicit is None:
            confidence = getattr(asset, "confidence", 0.0) or 0.0
            explicit = confidence >= 0.85
        if explicit:
            cov.scope_assets_explicit += 1

    # Recon
    rs = recon_stats or {}
    cov.recon_stages_total = int(rs.get("stages_total", 0) or 0)
    cov.recon_stages_completed = int(rs.get("stages_completed", 0) or 0)
    cov.recon_stages_skipped = int(rs.get("stages_skipped", 0) or 0)
    cov.subdomains = int(rs.get("subdomains", 0) or 0)
    cov.live_hosts = int(rs.get("live_hosts", 0) or 0)
    cov.endpoints_discovered = int(rs.get("endpoints", 0) or 0)

    stage_errors = rs.get("stage_errors") or {}
    if stage_errors:
        failed = [k for k, v in stage_errors.items() if not str(v).startswith("skipped")]
        if failed:
            cov.notes.append(f"recon stage errors: {', '.join(failed)}")

    # Research loop
    rep = research_report or {}
    cov.iterations = int(rep.get("iterations", 0) or 0)
    cov.findings = len(rep.get("findings") or [])
    stats = rep.get("stats") or {}
    # ResearchLoop.get_stats() reports tested_endpoints/tested_actions and
    # vuln_class_coverage; older summaries used unique_endpoints.
    cov.endpoints_tested = int(
        stats.get("tested_endpoints")
        or stats.get("unique_endpoints")
        or stats.get("endpoints_tested")
        or 0
    )
    coverage_by_class = stats.get("vuln_class_coverage") or (
        stats.get("coverage_by_class") or {}
    )
    cov.vuln_classes_tested = len(coverage_by_class) or int(
        stats.get("vuln_classes_tested", 0) or 0
    )
    untested = stats.get("vuln_classes_untested")
    if untested is None:
        untested = stats.get("vuln_classes_untested_count", 0)
    cov.vuln_classes_untested = int(untested or 0)

    # Recon may report 0 endpoints (e.g. probe stages failed) while the
    # research loop still tested URLs it built itself — never let the
    # tested count exceed an artificial denominator of 0.
    if cov.endpoints_discovered < cov.endpoints_tested:
        cov.endpoints_discovered = cov.endpoints_tested

    # If recon discovered endpoints but the research loop reports zero
    # tested, testing_ratio stays 0 — that is the truth of the run.
    if rep.get("error"):
        cov.notes.append(f"research loop error: {rep['error']}")
    if cov.endpoints_discovered and not cov.endpoints_tested:
        cov.notes.append("endpoints discovered but none tested")

    return cov
