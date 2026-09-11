"""BugChainDetector — detects multi-step vulnerability chains.

Many impactful bugs are chains of simpler vulnerabilities:
- Open Redirect → OAuth Token Theft → Account Takeover
- SSRF → Internal Service → RCE
- IDOR → Privilege Escalation → Data Exfiltration

This module detects and scores potential chains from observations.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class ChainLinkType(Enum):
    """Types of links in a bug chain."""
    OPEN_REDIRECT = "open_redirect"
    SSRF = "ssrf"
    IDOR = "idor"
    XSS = "xss"
    CSRF = "csrf"
    INFO_DISCLOSURE = "info_disclosure"
    AUTH_BYPASS = "auth_bypass"
    SQLI = "sqli"
    FILE_UPLOAD = "file_upload"
    COMMAND_INJECTION = "command_injection"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    TOKEN_THEFT = "token_theft"
    SESSION_HIJACK = "session_hijack"
    CREDENTIAL_EXPOSURE = "credential_exposure"
    MISCONFIGURATION = "misconfiguration"


# Known chain patterns: (source, intermediate, sink) → chain name
KNOWN_CHAINS: list[tuple[str, str, str, str]] = [
    ("open_redirect", "token_theft", "account_takeover", "OAuth Token Theft via Open Redirect"),
    ("ssrf", "info_disclosure", "rce", "SSRF to RCE via Internal Service"),
    ("idor", "privilege_escalation", "data_exfiltration", "IDOR to Privilege Escalation"),
    ("xss", "session_hijack", "account_takeover", "XSS to Session Hijack"),
    ("csrf", "token_theft", "account_takeover", "CSRF to Account Takeover"),
    ("info_disclosure", "credential_exposure", "account_takeover", "Credential Exposure via Info Disclosure"),
    ("file_upload", "command_injection", "rce", "File Upload to RCE"),
    ("auth_bypass", "privilege_escalation", "data_exfiltration", "Auth Bypass to Privilege Escalation"),
]


@dataclass
class ChainStep:
    """A single step in a vulnerability chain."""
    vuln_class: str
    endpoint: str
    description: str
    evidence_id: str = ""
    confidence: float = 0.5
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "vuln_class": self.vuln_class,
            "endpoint": self.endpoint,
            "description": self.description,
            "evidence_id": self.evidence_id,
            "confidence": self.confidence,
            "data": self.data,
        }


@dataclass
class ChainLink:
    """A link between two steps in a chain."""
    source_step: int
    target_step: int
    relationship: str  # e.g., "enables", "leads_to", "exploits"
    description: str = ""
    confidence: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_step": self.source_step,
            "target_step": self.target_step,
            "relationship": self.relationship,
            "description": self.description,
            "confidence": self.confidence,
        }


@dataclass
class BugChain:
    """A complete vulnerability chain with steps and links."""
    name: str = ""
    description: str = ""
    steps: list[ChainStep] = field(default_factory=list)
    links: list[ChainLink] = field(default_factory=list)
    severity: str = "unknown"
    confidence: float = 0.0
    impact: str = ""
    is_known_pattern: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "steps": [s.to_dict() for s in self.steps],
            "links": [l.to_dict() for l in self.links],
            "severity": self.severity,
            "confidence": self.confidence,
            "impact": self.impact,
            "is_known_pattern": self.is_known_pattern,
        }

    def get_attack_path(self) -> str:
        """Get human-readable attack path."""
        if not self.steps:
            return "No steps"
        path_parts = []
        for i, step in enumerate(self.steps):
            path_parts.append(f"{step.vuln_class} @ {step.endpoint}")
            if i < len(self.links):
                path_parts.append(f"  → [{self.links[i].relationship}] →")
        return " ".join(path_parts)

    def get_severity_score(self) -> float:
        """Estimate severity based on chain length and confidence."""
        base = len(self.steps) * 2.0
        confidence_boost = self.confidence * 3.0
        known_pattern_boost = 2.0 if self.is_known_pattern else 0.0
        return min(10.0, base + confidence_boost + known_pattern_boost)


class BugChainDetector:
    """Detects multi-step vulnerability chains from observations.

    Takes a list of observations/findings and identifies potential
    bug chains that combine multiple vulnerabilities for higher impact.
    """

    # Severity escalation per chain step count
    SEVERITY_BY_LENGTH = {
        2: "medium",
        3: "high",
        4: "critical",
    }

    def __init__(self, custom_patterns: list[tuple[str, str, str, str]] | None = None):
        self._patterns = list(KNOWN_CHAINS)
        if custom_patterns:
            self._patterns.extend(custom_patterns)

    def detect_chains(
        self,
        observations: list[dict[str, Any]],
    ) -> list[BugChain]:
        """Detect potential bug chains from a list of observations.

        Each observation should have:
        - vuln_class: str
        - endpoint: str
        - description: str (optional)
        - evidence_id: str (optional)
        """
        # Group observations by vuln_class
        by_class: dict[str, list[dict[str, Any]]] = {}
        for obs in observations:
            vc = obs.get("vuln_class", "")
            if vc:
                by_class.setdefault(vc, []).append(obs)

        chains: list[BugChain] = []

        # Check known patterns
        for source_class, mid_class, sink_class, chain_name in self._patterns:
            if source_class in by_class and sink_class in by_class:
                chain = self._build_chain(
                    chain_name,
                    source_class, by_class[source_class],
                    mid_class, by_class.get(mid_class, []),
                    sink_class, by_class[sink_class],
                )
                if chain:
                    chains.append(chain)

        # Check for ad-hoc chains (any 2+ step combinations)
        if len(by_class) >= 2:
            ad_hoc = self._detect_ad_hoc_chains(by_class)
            chains.extend(ad_hoc)

        # Deduplicate and sort by severity
        chains = self._deduplicate_chains(chains)
        chains.sort(key=lambda c: c.get_severity_score(), reverse=True)

        return chains

    def _build_chain(
        self,
        chain_name: str,
        source_class: str,
        source_obs: list[dict[str, Any]],
        mid_class: str,
        mid_obs: list[dict[str, Any]],
        sink_class: str,
        sink_obs: list[dict[str, Any]],
    ) -> BugChain | None:
        """Build a BugChain from known pattern components."""
        steps = []
        links = []

        # Source step
        src = source_obs[0]
        steps.append(ChainStep(
            vuln_class=source_class,
            endpoint=src.get("endpoint", ""),
            description=src.get("description", f"{source_class} vulnerability"),
            evidence_id=src.get("evidence_id", ""),
            confidence=src.get("confidence", 0.5),
        ))

        # Intermediate step (if pattern has one and observations exist)
        if mid_obs:
            mid = mid_obs[0]
            steps.append(ChainStep(
                vuln_class=mid_class,
                endpoint=mid.get("endpoint", ""),
                description=mid.get("description", f"{mid_class} vulnerability"),
                evidence_id=mid.get("evidence_id", ""),
                confidence=mid.get("confidence", 0.5),
            ))
            links.append(ChainLink(
                source_step=0,
                target_step=1,
                relationship="enables",
                description=f"{source_class} enables {mid_class}",
                confidence=0.6,
            ))
            next_step = 1
        else:
            next_step = 0

        # Sink step
        snk = sink_obs[0]
        sink_idx = next_step + 1
        steps.append(ChainStep(
            vuln_class=sink_class,
            endpoint=snk.get("endpoint", ""),
            description=snk.get("description", f"{sink_class} vulnerability"),
            evidence_id=snk.get("evidence_id", ""),
            confidence=snk.get("confidence", 0.5),
        ))
        links.append(ChainLink(
            source_step=next_step,
            target_step=sink_idx,
            relationship="leads_to",
            description=f"{steps[next_step].vuln_class} leads to {sink_class}",
            confidence=0.6,
        ))

        severity = self.SEVERITY_BY_LENGTH.get(len(steps), "critical")
        avg_confidence = sum(s.confidence for s in steps) / len(steps) if steps else 0

        return BugChain(
            name=chain_name,
            description=f"Chain: {' → '.join(s.vuln_class for s in steps)}",
            steps=steps,
            links=links,
            severity=severity,
            confidence=avg_confidence,
            impact=self._estimate_impact(steps),
            is_known_pattern=True,
        )

    def _detect_ad_hoc_chains(
        self,
        by_class: dict[str, list[dict[str, Any]]],
    ) -> list[BugChain]:
        """Detect ad-hoc chains from any combination of vuln classes."""
        chains = []
        classes = list(by_class.keys())

        # Simple 2-step chains
        for i in range(len(classes)):
            for j in range(i + 1, len(classes)):
                c1, c2 = classes[i], classes[j]
                # Determine order based on typical attack flow
                if self._is_logical_chain(c1, c2):
                    steps = [
                        ChainStep(
                            vuln_class=c1,
                            endpoint=by_class[c1][0].get("endpoint", ""),
                            description=by_class[c1][0].get("description", ""),
                            confidence=by_class[c1][0].get("confidence", 0.5),
                        ),
                        ChainStep(
                            vuln_class=c2,
                            endpoint=by_class[c2][0].get("endpoint", ""),
                            description=by_class[c2][0].get("description", ""),
                            confidence=by_class[c2][0].get("confidence", 0.5),
                        ),
                    ]
                    links = [
                        ChainLink(
                            source_step=0,
                            target_step=1,
                            relationship="enables",
                            confidence=0.4,
                        )
                    ]
                    chains.append(BugChain(
                        name=f"{c1} → {c2}",
                        description=f"Ad-hoc chain: {c1} enables {c2}",
                        steps=steps,
                        links=links,
                        severity="medium",
                        confidence=(steps[0].confidence + steps[1].confidence) / 2,
                        impact=self._estimate_impact(steps),
                        is_known_pattern=False,
                    ))

        return chains

    def _is_logical_chain(self, first: str, second: str) -> bool:
        """Check if first → second is a logical attack chain."""
        # Typical chain ordering
        chain_order = {
            "info_disclosure": 0,
            "open_redirect": 1,
            "idor": 2,
            "xss": 3,
            "csrf": 4,
            "ssrf": 5,
            "auth_bypass": 6,
            "privilege_escalation": 7,
            "command_injection": 8,
        }
        return chain_order.get(first, 5) < chain_order.get(second, 5)

    def _estimate_impact(self, steps: list[ChainStep]) -> str:
        """Estimate impact based on chain steps."""
        step_classes = {s.vuln_class for s in steps}

        if "account_takeover" in step_classes or "command_injection" in step_classes:
            return "Critical — full system compromise possible"
        if "privilege_escalation" in step_classes and "data_exfiltration" in step_classes:
            return "High — sensitive data access with elevated privileges"
        if len(steps) >= 3:
            return "High — multi-step attack chain with compounding impact"
        return "Medium — combined vulnerability impact"

    def _deduplicate_chains(self, chains: list[BugChain]) -> list[BugChain]:
        """Remove duplicate chains."""
        seen: set[str] = set()
        unique = []
        for chain in chains:
            key = " → ".join(s.vuln_class for s in chain.steps)
            if key not in seen:
                seen.add(key)
                unique.append(chain)
        return unique
