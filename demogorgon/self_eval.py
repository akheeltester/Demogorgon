"""Self-Evaluation Engine — tracks progress and detects stagnation.

Every 20 experiments, evaluate:
1. Coverage — what endpoints/vuln classes remain untested?
2. Repeated Actions — am I testing the same thing?
3. Untested Trust Boundaries — which boundaries haven't been probed?
4. Untested Workflows — which workflows haven't been exercised?
5. Stagnation — is the average score declining?
6. Strategy Pivot — if stagnant, change approach.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class EvalResult:
    """Result of a single evaluation."""
    knowledge_gain: float = 0.0
    coverage_gain: float = 0.0
    hypothesis_confidence_delta: float = 0.0
    evidence_quality: float = 0.0
    business_impact: float = 0.0
    overall_score: float = 0.0
    recommendation: str = ""
    reasoning: str = ""


@dataclass
class SelfEvalReport:
    """Comprehensive self-evaluation report."""
    experiment_count: int = 0
    finding_count: int = 0
    endpoints_tested: int = 0
    endpoints_discovered: int = 0
    vuln_classes_tested: set[str] = field(default_factory=set)
    vuln_classes_found: set[str] = field(default_factory=set)
    duplicate_actions: int = 0
    stagnation_count: int = 0
    strategy: str = "explore"
    untested_vuln_classes: list[str] = field(default_factory=list)
    untested_endpoints: int = 0
    untested_workflows: list[str] = field(default_factory=list)
    untested_trust_boundaries: int = 0
    average_score: float = 0.0
    should_change_strategy: bool = False
    recommendation: str = ""

    def to_dict(self) -> dict:
        return {
            "experiment_count": self.experiment_count,
            "finding_count": self.finding_count,
            "endpoints_tested": self.endpoints_tested,
            "endpoints_discovered": self.endpoints_discovered,
            "vuln_classes_tested": list(self.vuln_classes_tested),
            "vuln_classes_found": list(self.vuln_classes_found),
            "duplicate_actions": self.duplicate_actions,
            "stagnation_count": self.stagnation_count,
            "strategy": self.strategy,
            "untested_vuln_classes": self.untested_vuln_classes,
            "untested_endpoints": self.untested_endpoints,
            "untested_workflows": self.untested_workflows,
            "untested_trust_boundaries": self.untested_trust_boundaries,
            "average_score": self.average_score,
            "should_change_strategy": self.should_change_strategy,
            "recommendation": self.recommendation,
        }


class SelfEvaluator:
    """Evaluates progress and detects stagnation."""

    ALL_VULN_CLASSES = {
        "idor", "xss", "sqli", "ssrf", "cors", "auth_bypass",
        "jwt", "privesc", "race", "info_disclosure", "csrf",
        "file_upload", "ssti", "xxe", "open_redirect", "business_logic",
    }

    def __init__(self):
        self._history: list[EvalResult] = []
        self._known_endpoints: set[str] = set()
        self._known_vuln_classes: set[str] = set()
        self._finding_count = 0
        self._last_finding_at = 0

    def evaluate(
        self,
        experiment_result: dict[str, Any],
        hypothesis: dict[str, Any],
        is_finding: bool,
        endpoint: str,
        vuln_class: str,
        evidence: str,
    ) -> EvalResult:
        """Evaluate a single experiment result."""
        result = EvalResult()

        # Coverage gain
        if endpoint not in self._known_endpoints:
            result.coverage_gain = 0.3
            self._known_endpoints.add(endpoint)
        else:
            result.coverage_gain = 0.0

        # Knowledge gain
        if vuln_class not in self._known_vuln_classes:
            result.knowledge_gain = 0.4
            self._known_vuln_classes.add(vuln_class)
        elif is_finding:
            result.knowledge_gain = 0.2
        else:
            result.knowledge_gain = 0.0

        # Finding-specific metrics
        if is_finding:
            self._finding_count += 1
            result.evidence_quality = self._assess_evidence_quality(evidence)
            result.business_impact = self._assess_business_impact(vuln_class, endpoint)
            result.hypothesis_confidence_delta = 0.3
        else:
            result.evidence_quality = 0.1
            result.business_impact = 0.0
            result.hypothesis_confidence_delta = -0.2

        # Overall score
        result.overall_score = (
            result.knowledge_gain * 0.25
            + result.coverage_gain * 0.25
            + result.evidence_quality * 0.25
            + result.business_impact * 0.25
        )

        result.recommendation = self._generate_recommendation(result)
        result.reasoning = self._generate_reasoning(result, is_finding, vuln_class)

        self._history.append(result)
        return result

    def should_change_strategy(self) -> bool:
        """Check if strategy should change based on recent performance."""
        if len(self._history) < 3:
            return False
        recent = self._history[-3:]
        avg_score = sum(r.overall_score for r in recent) / len(recent)
        return avg_score < 0.1

    def get_progress_summary(self) -> dict[str, Any]:
        """Get a summary of progress."""
        if not self._history:
            return {"total_evaluations": 0}
        return {
            "total_evaluations": len(self._history),
            "average_score": sum(r.overall_score for r in self._history) / len(self._history),
            "endpoints_discovered": len(self._known_endpoints),
            "vuln_classes_discovered": len(self._known_vuln_classes),
            "findings": self._finding_count,
            "should_change_strategy": self.should_change_strategy(),
        }

    def generate_report(
        self,
        experiment_count: int,
        endpoints_tested: int,
        endpoints_discovered: int,
        tested_actions: set[str],
        failed_hypotheses: set[str],
        strategy: str,
        stagnation_count: int,
        app_model: Any | None = None,
    ) -> SelfEvalReport:
        """Generate a comprehensive self-evaluation report."""
        report = SelfEvalReport()
        report.experiment_count = experiment_count
        report.finding_count = self._finding_count
        report.endpoints_tested = endpoints_tested
        report.endpoints_discovered = endpoints_discovered
        report.vuln_classes_tested = set(self._known_vuln_classes)
        report.duplicate_actions = len(tested_actions)
        report.stagnation_count = stagnation_count
        report.strategy = strategy

        # Find untested vuln classes
        report.untested_vuln_classes = list(self.ALL_VULN_CLASSES - self._known_vuln_classes)

        # Find untested endpoints
        report.untested_endpoints = endpoints_discovered - endpoints_tested

        # Find untested workflows
        if app_model:
            report.untested_workflows = app_model.get_untested_workflows(tested_actions)
            report.untested_trust_boundaries = len(
                app_model.get_untested_trust_boundaries(tested_actions)
            )

        # Calculate average score
        if self._history:
            report.average_score = sum(r.overall_score for r in self._history[-5:]) / min(5, len(self._history))

        # Determine if strategy should change
        report.should_change_strategy = self.should_change_strategy()

        # Generate recommendation
        if report.should_change_strategy:
            report.recommendation = "STRATEGY CHANGE: Performance is stagnant. Pivot to different approach."
        elif report.untested_vuln_classes:
            report.recommendation = f"COVER GAPS: Test untested classes: {', '.join(report.untested_vuln_classes[:3])}"
        elif report.untested_endpoints > 10:
            report.recommendation = f"EXPLORE: {report.untested_endpoints} endpoints remain untested"
        elif report.finding_count > 0:
            report.recommendation = "VALIDATE: Focus on validating and chaining existing findings"
        else:
            report.recommendation = "CONTINUE: Maintain current approach"

        return report

    def _assess_evidence_quality(self, evidence: str) -> float:
        """Assess the quality of evidence."""
        if not evidence:
            return 0.0
        score = 0.3
        if "Access-Control-Allow-Origin" in evidence:
            score = 0.9
        elif "200" in evidence or "201" in evidence:
            score = 0.7
        elif "403" in evidence or "401" in evidence:
            score = 0.5
        if len(evidence) > 100:
            score = min(score + 0.1, 1.0)
        return score

    def _assess_business_impact(self, vuln_class: str, endpoint: str) -> float:
        """Assess business impact of a finding."""
        high_impact = {
            "rce": 1.0, "sqli": 0.9, "ssrf": 0.85, "auth_bypass": 0.9,
            "jwt": 0.8, "privesc": 0.85, "idor": 0.7,
        }
        medium_impact = {
            "xss": 0.6, "cors": 0.65, "csrf": 0.55, "race": 0.6,
            "info_disclosure": 0.5, "open_redirect": 0.45,
        }
        score = high_impact.get(vuln_class, medium_impact.get(vuln_class, 0.3))

        sensitive_endpoints = ["admin", "payment", "salary", "pii", "health"]
        for ep in sensitive_endpoints:
            if ep in endpoint.lower():
                score = min(score + 0.15, 1.0)
                break
        return score

    def _generate_recommendation(self, result: EvalResult) -> str:
        """Generate a recommendation based on the result."""
        if result.overall_score >= 0.7:
            return "Continue current approach — high value findings"
        elif result.overall_score >= 0.4:
            return "Moderate progress — consider exploring adjacent endpoints"
        elif result.overall_score >= 0.2:
            return "Low progress — try different vulnerability class"
        else:
            return "Stagnant — change strategy entirely"

    def _generate_reasoning(self, result: EvalResult, is_finding: bool, vuln_class: str) -> str:
        """Generate reasoning for the evaluation."""
        if is_finding:
            return f"Found {vuln_class} vulnerability. Evidence quality: {result.evidence_quality:.0%}. Business impact: {result.business_impact:.0%}."
        else:
            return f"No {vuln_class} vulnerability found. Hypothesis refuted. Try different approach."
