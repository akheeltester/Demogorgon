"""Chain Finder — discovers multi-step attack chains.

Chain: IDOR + auth bypass → ATO. SSRF → cloud metadata → RCE.
XSS → session hijack → account takeover. Open redirect → OAuth theft.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ChainStep:
    step_id: str
    vuln_class: str
    endpoint: str
    param: str = ""
    evidence: str = ""
    severity: str = "medium"
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "step_id": self.step_id,
            "vuln_class": self.vuln_class,
            "endpoint": self.endpoint,
            "param": self.param,
            "evidence": self.evidence,
            "severity": self.severity,
            "description": self.description,
        }


@dataclass
class Chain:
    chain_id: str
    steps: list[ChainStep]
    final_impact: str
    confidence: float = 0.0
    severity: str = "medium"
    title: str = ""
    description: str = ""
    chain_type: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "chain_id": self.chain_id,
            "steps": [s.to_dict() for s in self.steps],
            "final_impact": self.final_impact,
            "confidence": self.confidence,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "chain_type": self.chain_type,
        }


KNOWN_CHAINS = {
    "idor_auth_bypass": {
        "steps": ["idor", "auth_bypass"],
        "impact": "Full account takeover via IDOR + authentication bypass",
        "severity": "critical",
        "title": "IDOR + Authentication Bypass → Account Takeover",
    },
    "ssrf_cloud_metadata": {
        "steps": ["ssrf", "cloud_metadata"],
        "impact": "Cloud credential theft via SSRF to metadata endpoint",
        "severity": "critical",
        "title": "SSRF → Cloud Metadata → Credential Theft",
    },
    "xss_session_hijack": {
        "steps": ["xss", "session_hijack"],
        "impact": "Session hijacking via XSS stealing auth tokens",
        "severity": "critical",
        "title": "XSS → Session Hijack → Account Takeover",
    },
    "open_redirect_oauth": {
        "steps": ["open_redirect", "oauth_theft"],
        "impact": "OAuth token theft via open redirect",
        "severity": "critical",
        "title": "Open Redirect → OAuth Token Theft",
    },
    "idor_privesc": {
        "steps": ["idor", "privesc"],
        "impact": "Privilege escalation via IDOR to admin endpoints",
        "severity": "high",
        "title": "IDOR → Privilege Escalation → Admin Access",
    },
    "ssrf_sqli": {
        "steps": ["ssrf", "sqli"],
        "impact": "Blind SQL injection via SSRF to internal database",
        "severity": "critical",
        "title": "SSRF → Internal SQL Injection → Data Exfiltration",
    },
    "xss_csrf": {
        "steps": ["xss", "csrf"],
        "impact": "CSRF token extraction via XSS for state-changing actions",
        "severity": "high",
        "title": "XSS → CSRF Token Theft → Account Modification",
    },
    "cors_idor": {
        "steps": ["cors_misconfig", "idor"],
        "impact": "Cross-origin data theft via CORS misconfiguration + IDOR",
        "severity": "high",
        "title": "CORS Misconfiguration + IDOR → PII Exfiltration",
    },
    "jwt_forgery": {
        "steps": ["jwt_misconfig", "auth_bypass"],
        "impact": "Full authentication bypass via JWT algorithm confusion",
        "severity": "critical",
        "title": "JWT Algorithm Confusion → Authentication Bypass",
    },
    "file_upload_rce": {
        "steps": ["file_upload", "rce"],
        "impact": "Remote code execution via unrestricted file upload",
        "severity": "critical",
        "title": "Unrestricted File Upload → RCE",
    },
    "race_condition_doublespend": {
        "steps": ["race_condition", "double_spend"],
        "impact": "Financial gain via race condition double-spending",
        "severity": "high",
        "title": "Race Condition → Double-Spend → Financial Loss",
    },
    "graphql_idor": {
        "steps": ["graphql_introspection", "idor"],
        "impact": "Mass data exposure via GraphQL introspection + IDOR",
        "severity": "high",
        "title": "GraphQL Introspection + IDOR → Mass Data Exposure",
    },
}


class ChainFinder:
    """Discovers multi-step attack chains from individual findings."""

    def __init__(self):
        self.chains: list[Chain] = []
        self._findings: list[dict[str, Any]] = []
        self._chain_counter = 0

    def add_finding(self, finding: dict[str, Any]) -> None:
        self._findings.append(finding)
        self._check_new_chains(finding)

    def _check_new_chains(self, new_finding: dict[str, Any]) -> None:
        new_class = new_finding.get("vuln_class", "").lower()

        for existing in self._findings:
            if existing is new_finding:
                continue
            existing_class = existing.get("vuln_class", "").lower()
            combined = sorted([existing_class, new_class])

            for chain_def in KNOWN_CHAINS.values():
                if sorted(chain_def["steps"]) == combined:
                    self._create_chain(chain_def, existing, new_finding)

    def _create_chain(self, chain_def: dict, finding1: dict, finding2: dict) -> None:
        self._chain_counter += 1
        chain = Chain(
            chain_id=f"chain_{self._chain_counter}",
            steps=[
                ChainStep(
                    step_id="step_1",
                    vuln_class=finding1.get("vuln_class", "unknown"),
                    endpoint=finding1.get("endpoint", "unknown"),
                    param=finding1.get("param", ""),
                    evidence=finding1.get("evidence", ""),
                    severity=finding1.get("severity", "medium"),
                    description=f"{finding1.get('vuln_class', 'vuln')} at {finding1.get('endpoint', 'unknown')}",
                ),
                ChainStep(
                    step_id="step_2",
                    vuln_class=finding2.get("vuln_class", "unknown"),
                    endpoint=finding2.get("endpoint", "unknown"),
                    param=finding2.get("param", ""),
                    evidence=finding2.get("evidence", ""),
                    severity=finding2.get("severity", "medium"),
                    description=f"{finding2.get('vuln_class', 'vuln')} at {finding2.get('endpoint', 'unknown')}",
                ),
            ],
            final_impact=chain_def["impact"],
            severity=chain_def["severity"],
            title=chain_def["title"],
            chain_type="_".join(sorted(chain_def["steps"])),
        )
        chain.confidence = self._calculate_chain_confidence(chain)
        self.chains.append(chain)

    def discover_chains(self) -> list[Chain]:
        """Try to discover all possible chains from current findings."""
        self.chains.clear()
        self._chain_counter = 0

        for i, f1 in enumerate(self._findings):
            for f2 in self._findings[i+1:]:
                self._check_chain_pair(f1, f2)

        return self.chains

    def _check_chain_pair(self, f1: dict, f2: dict) -> None:
        c1 = f1.get("vuln_class", "").lower()
        c2 = f2.get("vuln_class", "").lower()
        pair = sorted([c1, c2])

        for chain_def in KNOWN_CHAINS.values():
            if sorted(chain_def["steps"]) == pair:
                self._create_chain(chain_def, f1, f2)

    def _calculate_chain_confidence(self, chain: Chain) -> float:
        if len(chain.steps) < 2:
            return 0.0

        step_confidences = []
        for step in chain.steps:
            severity_scores = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3, "info": 0.1}
            step_confidences.append(severity_scores.get(step.severity.lower(), 0.5))

        chain_confidence = sum(step_confidences) / len(step_confidences)

        if len(chain.steps) >= 3:
            chain_confidence *= 0.8

        if chain.confidence >= 0.85:
            chain.confidence = 1.0

        return min(chain_confidence, 1.0)

    def get_reportable_chains(self) -> list[Chain]:
        return [c for c in self.chains if c.confidence >= 0.7 and c.severity in ("critical", "high")]

    def get_chain_summary(self) -> dict[str, Any]:
        return {
            "total_chains": len(self.chains),
            "reportable": len(self.get_reportable_chains()),
            "by_severity": {
                "critical": len([c for c in self.chains if c.severity == "critical"]),
                "high": len([c for c in self.chains if c.severity == "high"]),
                "medium": len([c for c in self.chains if c.severity == "medium"]),
            },
            "by_type": {},
        }

    def to_dict(self) -> dict:
        summary = self.get_chain_summary()
        summary["chains"] = [c.to_dict() for c in self.chains]
        return summary
