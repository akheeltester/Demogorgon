"""LLM Validator — validates findings with LLM reasoning.

Implements the Validator interface. Uses LLM to analyze evidence
and determine if it constitutes a real security finding.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from ..interfaces import Validator

logger = logging.getLogger(__name__)

VALIDATOR_SYSTEM_PROMPT = """You are a security finding validator for an autonomous bug bounty hunter.

Your job: analyze evidence and determine if it constitutes a REAL security finding.

CRITICAL RULES:
1. "Could potentially" is NOT a bug — prove it works or drop it
2. Theoretical bugs without practical impact are NOT findings
3. Information disclosure alone is usually informational, not a vulnerability
4. You must demonstrate actual harm: stolen money, leaked PII, account takeover, or code execution
5. False positives waste triage time — be conservative

RESPOND WITH VALID JSON:
{
    "is_finding": true/false,
    "confidence": 0.0 to 1.0,
    "severity": "critical|high|medium|low|info",
    "title": "Concise descriptive title",
    "description": "What was found and why it matters",
    "impact": "What an attacker could do",
    "remediation": "How to fix it",
    "false_positive_reason": "Why this might NOT be a real finding (if applicable)",
    "cvss_estimate": "CVSS 3.1 vector string if applicable",
    "steps_to_reproduce": ["step 1", "step 2", ...]
}
"""

VALIDATOR_PROMPT = """Analyze this evidence and determine if it's a real security finding.

CLAIMED VULNERABILITY: {vuln_class}
ENDPOINT: {endpoint}
METHOD: {method}

EVIDENCE:
{evidence}

REQUEST/RESPONSE:
{request_response}

CONTEXT:
{context}

Analyze the evidence carefully:
1. Does the evidence PROVE the vulnerability exists? (not just suggest)
2. What is the actual impact on real users?
3. Is this a false positive? What could explain the behavior legitimately?
4. Can this be reproduced reliably?
5. What severity rating is appropriate?

Respond with JSON only."""


class LLMValidator(Validator):
    """LLM-powered finding validator.

    Usage:
        validator = LLMValidator(llm_generate)
        result = await validator.validate(evidence)
    """

    def __init__(self, llm_generate: Any):
        """Initialize with an LLM generate function."""
        self._llm = llm_generate

    async def validate(self, evidence: dict[str, Any]) -> dict[str, Any]:
        """Validate evidence and determine if it's a finding."""
        prompt = VALIDATOR_PROMPT.format(
            vuln_class=evidence.get("vuln_class", "Unknown"),
            endpoint=evidence.get("endpoint", "Unknown"),
            method=evidence.get("method", "GET"),
            evidence=self._format_evidence(evidence.get("evidence", [])),
            request_response=self._format_request_response(evidence),
            context=self._format_context(evidence.get("context", {})),
        )

        messages = [
            {"role": "system", "content": VALIDATOR_SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]

        try:
            response = await self._llm(messages, response_format={"type": "json_object"})
            content = response.get("content", "{}") if isinstance(response, dict) else str(response)
            result = json.loads(content)
            return self._normalize_result(result, evidence)
        except (json.JSONDecodeError, KeyError, TypeError, Exception) as e:
            logger.warning(f"Failed to parse validator response: {e}")
            return self._fallback_result(evidence)

    def _format_evidence(self, evidence: list) -> str:
        """Format evidence list for the prompt."""
        if not evidence:
            return "No evidence collected"

        lines = []
        for i, item in enumerate(evidence[:10], 1):
            if isinstance(item, dict):
                lines.append(f"{i}. {item.get('description', str(item)[:200])}")
            else:
                lines.append(f"{i}. {str(item)[:200]}")
        return "\n".join(lines)

    def _format_request_response(self, evidence: dict[str, Any]) -> str:
        """Format request/response data."""
        req_resp = evidence.get("request_response", {})
        if not req_resp:
            # Try to extract from evidence list
            for item in evidence.get("evidence", []):
                if isinstance(item, dict) and "request" in item:
                    req_resp = item
                    break

        if not req_resp:
            return "No request/response data"

        lines = []
        if "request" in req_resp:
            req = req_resp["request"]
            if isinstance(req, dict):
                lines.append(f"REQUEST: {req.get('method', 'GET')} {req.get('url', '')}")
                for k, v in req.get("headers", {}).items():
                    lines.append(f"  {k}: {v}")
                if "body" in req:
                    lines.append(f"  BODY: {str(req['body'])[:500]}")

        if "response" in req_resp:
            resp = req_resp["response"]
            if isinstance(resp, dict):
                lines.append(f"RESPONSE: {resp.get('status_code', '?')}")
                for k, v in resp.get("headers", {}).items():
                    lines.append(f"  {k}: {v}")
                body = str(resp.get("body", ""))[:1000]
                lines.append(f"  BODY: {body}")

        return "\n".join(lines) if lines else "No request/response data"

    def _format_context(self, context: Any) -> str:
        """Format context for the prompt."""
        if not context:
            return "No additional context"
        if isinstance(context, str):
            return context
        if isinstance(context, dict):
            lines = []
            for k, v in context.items():
                lines.append(f"{k}: {str(v)[:200]}")
            return "\n".join(lines)
        return str(context)[:500]

    def _normalize_result(self, result: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
        """Normalize the validation result."""
        result.setdefault("is_finding", False)
        result.setdefault("confidence", 0.5)
        result.setdefault("severity", "info")
        result.setdefault("title", "")
        result.setdefault("description", "")
        result.setdefault("impact", "")
        result.setdefault("remediation", "")
        result.setdefault("false_positive_reason", "")
        result.setdefault("cvss_estimate", "")
        result.setdefault("steps_to_reproduce", [])

        # Add metadata
        result["vuln_class"] = evidence.get("vuln_class", "unknown")
        result["endpoint"] = evidence.get("endpoint", "unknown")
        result["method"] = evidence.get("method", "GET")

        return result

    def _fallback_result(self, evidence: dict[str, Any]) -> dict[str, Any]:
        """Create a conservative fallback result when LLM fails."""
        return {
            "is_finding": False,
            "confidence": 0.3,
            "severity": "info",
            "title": "",
            "description": "Unable to validate — LLM parsing failed",
            "impact": "",
            "remediation": "",
            "false_positive_reason": "LLM validation failed, treat as inconclusive",
            "cvss_estimate": "",
            "steps_to_reproduce": [],
            "vuln_class": evidence.get("vuln_class", "unknown"),
            "endpoint": evidence.get("endpoint", "unknown"),
            "method": evidence.get("method", "GET"),
        }
