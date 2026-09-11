"""ValidationPipeline — automated and manual validation gates for findings."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Awaitable

logger = logging.getLogger(__name__)


class ValidationGate(Enum):
    """Validation gates a finding must pass."""
    SANITY = "sanity"                    # Basic sanity checks
    CONFIDENCE = "confidence"            # Confidence threshold
    EVIDENCE_COMPLETENESS = "evidence"   # Evidence is complete
    FALSE_POSITIVE = "false_positive"    # Not a false positive
    REPRODUCIBILITY = "reproducibility"  # Can be reproduced
    IMPACT = "impact"                    # Impact is meaningful
    SCOPE = "scope"                      # Within engagement scope
    HUMAN_REVIEW = "human_review"        # Human has reviewed


# Common false positive patterns
FP_PATTERNS: list[tuple[str, str]] = [
    (r"Access Denied|403 Forbidden", "Access denied response"),
    (r"Rate limit|Too many requests|429", "Rate limiting response"),
    (r"Server Error|500|502|503|504", "Server error (not user-controlled)"),
    (r"Not Found|404", "Endpoint does not exist"),
    (r"Method Not Allowed|405", "HTTP method not supported"),
    (r"CSRF token|csrf_middleware", "CSRF protection detected"),
    (r"Content Security Policy|CSP", "CSP header present"),
    (r"X-Frame-Options|DENY|SAMEORIGIN", "Clickjacking protection"),
    (r"HTTPOnly|HttpOnly", "HttpOnly flag on cookie"),
    (r"Secure flag|Secure;", "Secure flag on cookie"),
    (r"SameSite|samesite", "SameSite cookie attribute"),
]

# Common indicators of real vulnerabilities
TRUE_POSITIVE_PATTERNS: list[tuple[str, float]] = [
    (r"root:x:0:0|daemon:x:", 0.9),       # /etc/passwd content
    (r"AKIA[0-9A-Z]{16}", 0.85),          # AWS access key
    (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----", 0.9),  # Private key
    (r"jwt.*eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]", 0.7),  # JWT token leaked
    (r"admin.*password|password.*admin", 0.8),  # Admin credentials
    (r"SELECT.*FROM.*WHERE|INSERT INTO|UPDATE.*SET", 0.85),  # SQL error output
    (r"<script>alert\(|<img[^>]+onerror", 0.9),  # XSS payload reflected
    (r"127\.0\.0\.1|localhost|169\.254\.169\.254", 0.8),  # Internal/SSRF target reached
]


@dataclass
class ValidationResult:
    """Result of a validation gate check."""
    gate: ValidationGate
    passed: bool
    confidence_adjustment: float = 0.0
    reason: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "gate": self.gate.value,
            "passed": self.passed,
            "confidence_adjustment": self.confidence_adjustment,
            "reason": self.reason,
            "details": self.details,
        }


class ValidationPipeline:
    """Automated validation pipeline for findings.

    Runs a series of validation gates on evidence to determine
    if a finding is likely a true positive and what severity it
    should be.
    """

    def __init__(
        self,
        min_confidence: float = 0.5,
        skip_gates: list[ValidationGate] | None = None,
        custom_validators: list[Callable[..., Awaitable[ValidationResult]]] | None = None,
    ):
        self._min_confidence = min_confidence
        self._skip_gates = set(skip_gates or [])
        self._custom_validators = custom_validators or []

    async def validate(
        self,
        evidence: dict[str, Any],
        confidence: float = 0.5,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Run all validation gates on evidence.

        Returns:
            {
                "is_valid": bool,
                "final_confidence": float,
                "gates": [ValidationResult],
                "is_false_positive": bool,
                "fp_reasons": [str],
                "tp_indicators": [str],
                "recommended_severity": str,
            }
        """
        gates_results: list[ValidationResult] = []
        current_confidence = confidence
        fp_reasons: list[str] = []
        tp_indicators: list[str] = []

        # 1. Sanity gate
        if ValidationGate.SANITY not in self._skip_gates:
            result = self._check_sanity(evidence)
            gates_results.append(result)
            if not result.passed:
                return self._build_result(
                    False, current_confidence, gates_results,
                    fp_reasons, tp_indicators,
                )

        # 2. Confidence gate
        if ValidationGate.CONFIDENCE not in self._skip_gates:
            result = self._check_confidence(current_confidence)
            gates_results.append(result)
            if not result.passed:
                return self._build_result(
                    False, current_confidence, gates_results,
                    fp_reasons, tp_indicators,
                )

        # 3. Evidence completeness
        if ValidationGate.EVIDENCE_COMPLETENESS not in self._skip_gates:
            result = self._check_evidence_completeness(evidence)
            gates_results.append(result)
            current_confidence += result.confidence_adjustment

        # 4. False positive detection
        if ValidationGate.FALSE_POSITIVE not in self._skip_gates:
            result = self._check_false_positive(evidence)
            gates_results.append(result)
            current_confidence += result.confidence_adjustment
            if result.details.get("fp_reasons"):
                fp_reasons.extend(result.details["fp_reasons"])

        # 5. True positive indicators
        tp_result = self._check_true_positive(evidence)
        if tp_result:
            tp_indicators.extend(tp_result)
            current_confidence += 0.2

        # 6. Impact check
        if ValidationGate.IMPACT not in self._skip_gates:
            result = self._check_impact(evidence)
            gates_results.append(result)
            current_confidence += result.confidence_adjustment

        # 7. Scope check
        if ValidationGate.SCOPE not in self._skip_gates:
            result = self._check_scope(evidence, context)
            gates_results.append(result)
            if not result.passed:
                logger.warning("Finding is outside engagement scope")

        # 8. Custom validators
        for validator in self._custom_validators:
            try:
                result = await validator(evidence)
                gates_results.append(result)
                current_confidence += result.confidence_adjustment
            except Exception as e:
                logger.error(f"Custom validator failed: {e}")

        # Clamp confidence
        current_confidence = max(0.0, min(1.0, current_confidence))

        # Determine if valid
        all_critical_passed = all(
            r.passed for r in gates_results
            if r.gate in (ValidationGate.SANITY, ValidationGate.CONFIDENCE)
        )
        is_fp = len(fp_reasons) > 2 or current_confidence < 0.2

        # Recommended severity
        severity = self._recommend_severity(current_confidence, evidence, tp_indicators)

        return {
            "is_valid": all_critical_passed and not is_fp,
            "final_confidence": current_confidence,
            "gates": [r.to_dict() for r in gates_results],
            "is_false_positive": is_fp,
            "fp_reasons": fp_reasons,
            "tp_indicators": tp_indicators,
            "recommended_severity": severity,
        }

    def _check_sanity(self, evidence: dict[str, Any]) -> ValidationResult:
        """Basic sanity checks on evidence."""
        has_endpoint = bool(evidence.get("endpoint"))
        has_evidence = bool(evidence.get("request_response_pairs") or evidence.get("raw_evidence"))

        passed = has_endpoint and has_evidence
        reason = ""
        if not has_endpoint:
            reason = "No endpoint specified"
        elif not has_evidence:
            reason = "No evidence items provided"

        return ValidationResult(
            gate=ValidationGate.SANITY,
            passed=passed,
            reason=reason,
        )

    def _check_confidence(self, confidence: float) -> ValidationResult:
        """Check if confidence meets minimum threshold."""
        passed = confidence >= self._min_confidence
        return ValidationResult(
            gate=ValidationGate.CONFIDENCE,
            passed=passed,
            reason=f"Confidence {confidence:.2f} {'>=' if passed else '<'} {self._min_confidence}",
        )

    def _check_evidence_completeness(self, evidence: dict[str, Any]) -> ValidationResult:
        """Check if evidence is complete enough."""
        pairs = evidence.get("request_response_pairs", [])
        raw = evidence.get("raw_evidence", [])

        completeness = 0.0
        details = {}

        if pairs:
            completeness += 0.4
            details["has_pairs"] = True
        if raw:
            completeness += 0.3
            details["has_raw"] = True
        if evidence.get("reproduction_steps"):
            completeness += 0.3
            details["has_steps"] = True

        passed = completeness >= 0.3
        adjustment = 0.1 if completeness >= 0.6 else 0.0

        return ValidationResult(
            gate=ValidationGate.EVIDENCE_COMPLETENESS,
            passed=passed,
            confidence_adjustment=adjustment,
            reason=f"Evidence completeness: {completeness:.0%}",
            details=details,
        )

    def _check_false_positive(self, evidence: dict[str, Any]) -> ValidationResult:
        """Check for false positive indicators."""
        fp_reasons = []

        # Check response body for FP patterns
        for pair in evidence.get("request_response_pairs", []):
            response_body = pair.get("response", {}).get("body", "")
            response_status = pair.get("response", {}).get("status_code", 0)

            for pattern, reason in FP_PATTERNS:
                if re.search(pattern, response_body, re.IGNORECASE):
                    fp_reasons.append(reason)

            # 4xx responses are often not vulnerabilities
            if 400 <= response_status < 500:
                fp_reasons.append(f"Client error response ({response_status})")

        # Deduplicate
        fp_reasons = list(dict.fromkeys(fp_reasons))

        is_fp = len(fp_reasons) >= 3
        adjustment = -0.3 if len(fp_reasons) >= 2 else (-0.1 if fp_reasons else 0)

        return ValidationResult(
            gate=ValidationGate.FALSE_POSITIVE,
            passed=not is_fp,
            confidence_adjustment=adjustment,
            reason=f"{len(fp_reasons)} FP indicators found" if fp_reasons else "No FP indicators",
            details={"fp_reasons": fp_reasons},
        )

    def _check_true_positive(self, evidence: dict[str, Any]) -> list[str] | None:
        """Check for true positive indicators."""
        indicators = []

        for pair in evidence.get("request_response_pairs", []):
            response_body = pair.get("response", {}).get("body", "")
            for pattern, confidence in TRUE_POSITIVE_PATTERNS:
                if re.search(pattern, response_body, re.IGNORECASE):
                    indicators.append(pattern)

        return indicators if indicators else None

    def _check_impact(self, evidence: dict[str, Any]) -> ValidationResult:
        """Check if impact is meaningful."""
        # Check for high-impact indicators
        high_impact = False
        details = {}

        for pair in evidence.get("request_response_pairs", []):
            response_body = pair.get("response", {}).get("body", "")
            # Data exfiltration indicators
            if any(x in response_body.lower() for x in ["password", "secret", "token", "key"]):
                high_impact = True
                details["data_exposure"] = True

        vuln_class = evidence.get("vuln_class", "")
        high_impact_classes = {"rce", "command_injection", "sqli", "ssrf", "account_takeover"}
        if vuln_class in high_impact_classes:
            high_impact = True
            details["high_impact_class"] = True

        adjustment = 0.2 if high_impact else 0.0
        return ValidationResult(
            gate=ValidationGate.IMPACT,
            passed=True,  # Impact gate doesn't block, just adjusts
            confidence_adjustment=adjustment,
            details=details,
        )

    def _check_scope(
        self,
        evidence: dict[str, Any],
        context: dict[str, Any] | None,
    ) -> ValidationResult:
        """Check if finding is within engagement scope."""
        if not context:
            return ValidationResult(
                gate=ValidationGate.SCOPE,
                passed=True,
                reason="No scope context provided, assuming in-scope",
            )

        scope = context.get("scope", [])
        endpoint = evidence.get("endpoint", "")

        if not scope:
            return ValidationResult(
                gate=ValidationGate.SCOPE,
                passed=True,
                reason="No scope defined, assuming in-scope",
            )

        for scope_entry in scope:
            if isinstance(scope_entry, str) and scope_entry in endpoint:
                return ValidationResult(
                    gate=ValidationGate.SCOPE,
                    passed=True,
                    reason=f"Endpoint matches scope: {scope_entry}",
                )

        return ValidationResult(
            gate=ValidationGate.SCOPE,
            passed=False,
            reason="Endpoint not in scope",
        )

    def _recommend_severity(
        self,
        confidence: float,
        evidence: dict[str, Any],
        tp_indicators: list[str],
    ) -> str:
        """Recommend severity based on confidence and evidence."""
        if confidence >= 0.9 and tp_indicators:
            return "critical"
        if confidence >= 0.7:
            return "high"
        if confidence >= 0.5:
            return "medium"
        if confidence >= 0.3:
            return "low"
        return "informational"

    def _build_result(
        self,
        is_valid: bool,
        confidence: float,
        gates: list[ValidationResult],
        fp_reasons: list[str],
        tp_indicators: list[str],
    ) -> dict[str, Any]:
        """Build a validation result dict."""
        return {
            "is_valid": is_valid,
            "final_confidence": confidence,
            "gates": [r.to_dict() for r in gates],
            "is_false_positive": not is_valid,
            "fp_reasons": fp_reasons,
            "tp_indicators": tp_indicators,
            "recommended_severity": "informational" if not is_valid else "low",
        }
