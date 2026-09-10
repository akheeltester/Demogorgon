"""Self-Evaluation — calculates progress after every experiment.

Knowledge Gain: Did we learn something new?
Coverage Gain: Did we test a new endpoint/vuln class?
Hypothesis Confidence: Did evidence support or refute the hypothesis?
Evidence Quality: Is the evidence strong enough to report?
Business Impact: What's the impact if this vulnerability is real?
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class EvalResult:
    knowledge_gain: float = 0.0
    coverage_gain: float = 0.0
    hypothesis_confidence_delta: float = 0.0
    evidence_quality: float = 0.0
    business_impact: float = 0.0
    overall_score: float = 0.0
    recommendation: str = ""
    reasoning: str = ""

    def to_dict(self) -> dict:
        return {
            "knowledge_gain": self.knowledge_gain,
            "coverage_gain": self.coverage_gain,
            "hypothesis_confidence_delta": self.hypothesis_confidence_delta,
            "evidence_quality": self.evidence_quality,
            "business_impact": self.business_impact,
            "overall_score": self.overall_score,
            "recommendation": self.recommendation,
            "reasoning": self.reasoning,
        }


class SelfEvaluator:
    """Evaluates progress after every experiment."""

    def __init__(self):
        self._history: list[EvalResult] = []
        self._known_endpoints: set[str] = set()
        self._known_vuln_classes: set[str] = set()
        self._finding_count = 0

    def evaluate(
        self,
        experiment_result: dict[str, Any],
        hypothesis: dict[str, Any],
        is_finding: bool,
        endpoint: str,
        vuln_class: str,
        evidence: str,
    ) -> EvalResult:
        result = EvalResult()

        if endpoint not in self._known_endpoints:
            result.coverage_gain = 0.3
            self._known_endpoints.add(endpoint)
        else:
            result.coverage_gain = 0.0

        if vuln_class not in self._known_vuln_classes:
            result.knowledge_gain = 0.4
            self._known_vuln_classes.add(vuln_class)
        elif is_finding:
            result.knowledge_gain = 0.2
        else:
            result.knowledge_gain = 0.0

        if is_finding:
            self._finding_count += 1
            result.evidence_quality = self._assess_evidence_quality(evidence)
            result.business_impact = self._assess_business_impact(
                vuln_class, endpoint
            )
            result.hypothesis_confidence_delta = 0.3
        else:
            result.evidence_quality = 0.1
            result.business_impact = 0.0
            result.hypothesis_confidence_delta = -0.2

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
        if len(self._history) < 3:
            return False
        recent = self._history[-3:]
        avg_score = sum(r.overall_score for r in recent) / len(recent)
        return avg_score < 0.1

    def get_progress_summary(self) -> dict[str, Any]:
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

    def _assess_evidence_quality(self, evidence: str) -> float:
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
        if result.overall_score >= 0.7:
            return "Continue current approach — high value findings"
        elif result.overall_score >= 0.4:
            return "Moderate progress — consider exploring adjacent endpoints"
        elif result.overall_score >= 0.2:
            return "Low progress — try different vulnerability class"
        else:
            return "Stagnant — change strategy entirely"

    def _generate_reasoning(
        self, result: EvalResult, is_finding: bool, vuln_class: str
    ) -> str:
        if is_finding:
            return f"Found {vuln_class} vulnerability. Evidence quality: {result.evidence_quality:.0%}. Business impact: {result.business_impact:.0%}."
        else:
            return f"No {vuln_class} vulnerability found. Hypothesis refuted. Try different approach."
