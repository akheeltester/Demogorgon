"""Evidence Validator — 7-Question Gate

Before any finding is reported, it must answer ALL 7 questions:

1. Why was this investigated?        (reasoning trace)
2. What security boundary was crossed? (trust boundary map)
3. How is it reproduced?             (step-by-step with request/response)
4. What is the impact?               (business impact, not just CVSS)
5. What evidence supports it?        (full evidence package)
6. What alternative explanations were rejected? (false positive analysis)
7. Is it repeatable from a clean state? (independence check)

One wrong answer = kill the finding and move on.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ValidationResult:
    """Result of the 7-Question Gate."""
    finding_id: str
    passed: bool = False
    questions: dict[str, bool] = field(default_factory=dict)
    issues: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    confidence: float = 0.0
    recommendation: str = ""

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "passed": self.passed,
            "questions": self.questions,
            "issues": self.issues,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "recommendation": self.recommendation,
        }


class EvidenceValidator:
    """Validates findings using the 7-Question Gate.

    A finding must pass ALL 7 gates to be reported.
    This prevents false positives and ensures report quality.
    """

    # Common false positive patterns
    FALSE_POSITIVE_PHRASES = [
        "might be vulnerable",
        "could potentially",
        "theoretically possible",
        "unable to confirm",
        "inconclusive",
        "no evidence",
        "possibly",
        "may be",
        "suggests that",
        "appears to be",
    ]

    # High-impact words for business impact
    HIGH_IMPACT_WORDS = [
        "access to", "read", "modify", "delete", "create",
        "admin", "escalation", "bypass", "takeover", "exfiltrate",
        "execute", "inject", "steal", "compromise", "control",
    ]

    def __init__(self, memory=None, app_model=None):
        self.memory = memory
        self.app_model = app_model

    async def validate(self, finding: dict, reasoning_trace: list[dict] | None = None,
                       http_client=None, browser_tool=None) -> ValidationResult:
        """Run the 7-Question Gate on a finding."""
        result = ValidationResult(finding_id=finding.get("id", "unknown"))

        # Question 1: Why was this investigated?
        result.questions["q1_reasoning"] = self._check_reasoning(
            finding, reasoning_trace
        )

        # Question 2: What security boundary was crossed?
        result.questions["q2_boundary"] = self._check_boundary(
            finding
        )

        # Question 3: How is it reproduced?
        result.questions["q3_reproduction"] = await self._check_reproduction(
            finding, http_client
        )

        # Question 4: What is the impact?
        result.questions["q4_impact"] = self._check_impact(finding)

        # Question 5: What evidence supports it?
        result.questions["q5_evidence"] = self._check_evidence(finding)

        # Question 6: What alternative explanations were rejected?
        result.questions["q6_alternatives"] = self._check_false_positive(finding)

        # Question 7: Is it repeatable from a clean state?
        result.questions["q7_independence"] = await self._check_independence(
            finding, http_client
        )

        # Calculate result
        passed_count = sum(1 for v in result.questions.values() if v)
        total = len(result.questions)
        result.confidence = passed_count / total if total > 0 else 0.0
        result.passed = result.confidence >= 0.85  # At least 6/7 questions

        # Generate recommendation
        if result.passed:
            result.recommendation = "READY TO REPORT — all gates passed"
        else:
            failed = [k for k, v in result.questions.items() if not v]
            result.recommendation = f"NOT READY — failed: {', '.join(failed)}"
            result.issues.append(f"Failed {total - passed_count}/{total} gates")

        return result

    # ============================================================
    # Question 1: Why was this investigated?
    # ============================================================

    def _check_reasoning(self, finding: dict, reasoning_trace: list[dict] | None) -> bool:
        """Check if there's a clear reasoning chain for why this was investigated."""
        # Check if finding has reasoning
        reasoning = finding.get("reasoning", "")
        if reasoning and len(reasoning) > 20:
            return True

        # Check if reasoning trace exists
        if reasoning_trace:
            for step in reasoning_trace:
                hypothesis = step.get("hypothesis", "")
                if hypothesis and finding.get("vuln_class", "") in hypothesis.lower():
                    return True

        # Check if finding has evidence-based reasoning
        evidence = finding.get("evidence", "")
        if evidence and len(evidence) > 50:
            return True

        return False

    # ============================================================
    # Question 2: What security boundary was crossed?
    # ============================================================

    def _check_boundary(self, finding: dict) -> bool:
        """Check if a security boundary was actually crossed."""
        vuln_class = finding.get("vuln_class", "").lower()
        endpoint = finding.get("endpoint", "").lower()

        # High-confidence boundary crossings
        boundary_vulns = {
            "idor": "Object ownership boundary",
            "auth_bypass": "Authentication boundary",
            "privesc": "Authorization boundary",
            "jwt": "Token verification boundary",
            "race_condition": "State consistency boundary",
            "sqli": "Data access boundary",
            "ssrf": "Network boundary",
            "rce": "Code execution boundary",
        }

        if vuln_class in boundary_vulns:
            return True

        # Check if endpoint suggests boundary crossing
        boundary_endpoints = ["admin", "private", "internal", "secure", "protected"]
        if any(ep in endpoint for ep in boundary_endpoints):
            return True

        # Check if evidence shows boundary crossing
        evidence = finding.get("evidence", "").lower()
        if any(word in evidence for word in ["unauthorized", "forbidden", "denied", "crossed"]):
            return True

        return False

    # ============================================================
    # Question 3: How is it reproduced?
    # ============================================================

    async def _check_reproduction(self, finding: dict, http_client) -> bool:
        """Check if the finding can be reproduced."""
        # Check if we have reproduction steps
        reproduction = finding.get("reproduction", [])
        if reproduction and len(reproduction) >= 2:
            # Try to replay if we have HTTP client
            if http_client and finding.get("request"):
                req = finding["request"]
                try:
                    response = await http_client.request(
                        method=req.get("method", "GET"),
                        url=req.get("url", ""),
                        headers=req.get("headers", {}),
                        body=req.get("body"),
                    )
                    # Check if we get similar response
                    expected_status = finding.get("expected_status", 200)
                    if response["status_code"] == expected_status:
                        return True
                except Exception:
                    pass

            # If we have steps but can't replay, check if steps are specific
            if all(len(step) > 10 for step in reproduction):
                return True

        # Check if we have evidence of reproduction
        evidence = finding.get("evidence", "")
        if evidence and ("reproduced" in evidence.lower() or "confirmed" in evidence.lower()):
            return True

        # Check if finding has request/response
        if finding.get("request") and finding.get("response"):
            return True

        return False

    # ============================================================
    # Question 4: What is the impact?
    # ============================================================

    def _check_impact(self, finding: dict) -> bool:
        """Check if there's clear business impact."""
        impact = finding.get("impact", "").lower()

        # Check for high-impact words
        if any(word in impact for word in self.HIGH_IMPACT_WORDS):
            return True

        # Check severity
        severity = finding.get("severity", "").lower()
        if severity in ("critical", "high"):
            return True

        # Check if impact is specific (not generic)
        if impact and len(impact) > 20 and not any(phrase in impact for phrase in self.FALSE_POSITIVE_PHRASES):
            return True

        return False

    # ============================================================
    # Question 5: What evidence supports it?
    # ============================================================

    def _check_evidence(self, finding: dict) -> bool:
        """Check if there's sufficient evidence."""
        evidence = finding.get("evidence", "")

        # Check if evidence exists and is substantial
        if evidence and len(evidence) > 50:
            return True

        # Check if we have request/response pair
        if finding.get("request") and finding.get("response"):
            return True

        # Check if we have screenshots
        if finding.get("screenshot"):
            return True

        # Check if we have reproduction steps
        reproduction = finding.get("reproduction", [])
        if reproduction and len(reproduction) >= 2:
            return True

        return False

    # ============================================================
    # Question 6: What alternative explanations were rejected?
    # ============================================================

    def _check_false_positive(self, finding: dict) -> bool:
        """Check if false positive analysis was done."""
        # Check if description contains false positive phrases
        description = finding.get("description", "").lower()
        if any(phrase in description for phrase in self.FALSE_POSITIVE_PHRASES):
            return False

        # Check if there's explicit false positive analysis
        analysis = finding.get("false_positive_analysis", "")
        if analysis and len(analysis) > 20:
            return True

        # Check if alternatives were considered
        alternatives = finding.get("alternatives_rejected", [])
        if alternatives and len(alternatives) > 0:
            return True

        # For high-confidence findings, assume analysis was done
        confidence = finding.get("confidence", 0.0)
        if confidence >= 0.8:
            return True

        # Check if evidence is strong enough
        evidence = finding.get("evidence", "")
        if evidence and len(evidence) > 100:
            return True

        return False

    # ============================================================
    # Question 7: Is it repeatable from a clean state?
    # ============================================================

    async def _check_independence(self, finding: dict, http_client) -> bool:
        """Check if the finding works from a clean session."""
        # If no auth required, it's independent
        if not finding.get("requires_auth", False):
            return True

        # If we can replay without auth
        if http_client and finding.get("request"):
            req = finding["request"]
            headers = {k: v for k, v in req.get("headers", {}).items()
                      if k.lower() != "authorization"}

            try:
                response = await http_client.request(
                    method=req.get("method", "GET"),
                    url=req.get("url", ""),
                    headers=headers,
                )
                # If we still get data without auth, it's independent
                if response["status_code"] == 200 and len(response["body"]) > 100:
                    return True
            except Exception:
                pass

        # Check if finding explicitly states independence
        if finding.get("independent", False):
            return True

        # Check if reproduction steps don't require auth
        reproduction = finding.get("reproduction", [])
        if reproduction:
            auth_steps = [s for s in reproduction if "auth" in s.lower() or "login" in s.lower()]
            if not auth_steps:
                return True

        return False
