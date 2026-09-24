"""CVSS 3.1 scoring for findings.

Pure-python CVSS v3.1 base metric calculator. No external deps.
Severity derived from base score (NIST bands).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# CVSS 3.1 attack vector/complexity/privileges/user-interaction/scope/CIA options
ATTACK_VECTOR = {"NETWORK": 0.85, "ADJACENT": 0.62, "LOCAL": 0.55, "PHYSICAL": 0.2}
ATTACK_COMPLEXITY = {"LOW": 0.77, "HIGH": 0.44}
PRIVILEGES_REQUIRED = {"NONE": 0.85, "LOW": 0.62, "HIGH": 0.27}
USER_INTERACTION = {"NONE": 0.85, "REQUIRED": 0.62}
SCOPE = {"UNCHANGED": 1.0, "CHANGED": 1.08}
IMPACT = {"HIGH": 0.56, "LOW": 0.22, "NONE": 0.0}

# Severity bands
SEVERITY_FROM_SCORE = [
    (0.0, 0.0, "NONE"),
    (0.1, 3.9, "LOW"),
    (4.0, 6.9, "MEDIUM"),
    (7.0, 8.9, "HIGH"),
    (9.0, 10.0, "CRITICAL"),
]


@dataclass
class CVSSScore:
    """Computed CVSS 3.1 base score."""
    base_score: float = 0.0
    severity: str = "NONE"
    vector: str = ""
    metrics: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "base_score": self.base_score,
            "severity": self.severity,
            "vector": self.vector,
            "metrics": self.metrics,
        }


def severity_from_score(score: float) -> str:
    for lo, hi, name in SEVERITY_FROM_SCORE:
        if lo <= score <= hi:
            return name
    return "NONE"


def _round_up(value: float) -> float:
    """CVSS 3.1 Roundup: smallest number to 1 decimal >= input."""
    import math
    if value == 0:
        return 0.0
    return math.ceil(value * 10) / 10.0


def compute_cvss_base(
    attack_vector: str = "NETWORK",
    attack_complexity: str = "LOW",
    privileges_required: str = "NONE",
    user_interaction: str = "NONE",
    scope: str = "UNCHANGED",
    confidentiality_impact: str = "LOW",
    integrity_impact: str = "NONE",
    availability_impact: str = "NONE",
) -> CVSSScore:
    """Compute CVSS 3.1 base score from metric values."""
    av = ATTACK_VECTOR.get(attack_vector.upper(), 0.85)
    ac = ATTACK_COMPLEXITY.get(attack_complexity.upper(), 0.77)
    pr = PRIVILEGES_REQUIRED.get(privileges_required.upper(), 0.85)
    ui = USER_INTERACTION.get(user_interaction.upper(), 0.85)
    sc = SCOPE.get(scope.upper(), 1.0)
    c = IMPACT.get(confidentiality_impact.upper(), 0.0)
    i = IMPACT.get(integrity_impact.upper(), 0.0)
    a = IMPACT.get(availability_impact.upper(), 0.0)

    # Impact sub-score
    if scope.upper() == "UNCHANGED":
        iss = 1 - ((1 - c) * (1 - i) * (1 - a))
        impact = 6.42 * iss
    else:
        iss = 1 - ((1 - c) * (1 - i) * (1 - a))
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    # Exploitability sub-score
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        base = 0.0
    elif scope.upper() == "UNCHANGED":
        base = min(impact + exploitability, 10.0)
    else:
        base = min(sc * (impact + exploitability), 10.0)

    base = _round_up(base)
    sev = severity_from_score(base)

    vector = (
        f"CVSS:3.1/AV:{attack_vector.upper()}/AC:{attack_complexity.upper()}"
        f"/PR:{privileges_required.upper()}/UI:{user_interaction.upper()}"
        f"/S:{scope.upper()}/C:{confidentiality_impact.upper()}"
        f"/I:{integrity_impact.upper()}/A:{availability_impact.upper()}"
    )

    return CVSSScore(
        base_score=base,
        severity=sev,
        vector=vector,
        metrics={
            "AV": attack_vector.upper(),
            "AC": attack_complexity.upper(),
            "PR": privileges_required.upper(),
            "UI": user_interaction.upper(),
            "S": scope.upper(),
            "C": confidentiality_impact.upper(),
            "I": integrity_impact.upper(),
            "A": availability_impact.upper(),
        },
    )


# Heuristic: infer CVSS metrics from vuln_class + our severity label
_VULN_CLASS_DEFAULTS: dict[str, dict[str, str]] = {
    "ssrf": {
        "confidentiality_impact": "HIGH",
        "integrity_impact": "LOW",
        "availability_impact": "NONE",
        "privileges_required": "NONE",
    },
    "file_upload": {
        "confidentiality_impact": "HIGH",
        "integrity_impact": "HIGH",
        "availability_impact": "HIGH",
        "privileges_required": "NONE",
        "scope": "CHANGED",
    },
    "rce": {
        "confidentiality_impact": "HIGH",
        "integrity_impact": "HIGH",
        "availability_impact": "HIGH",
        "scope": "CHANGED",
    },
    "sqli": {
        "confidentiality_impact": "HIGH",
        "integrity_impact": "HIGH",
        "availability_impact": "LOW",
        "privileges_required": "NONE",
    },
    "xss": {
        "confidentiality_impact": "LOW",
        "integrity_impact": "LOW",
        "availability_impact": "NONE",
        "user_interaction": "REQUIRED",
    },
    "idor": {
        "confidentiality_impact": "HIGH",
        "integrity_impact": "LOW",
        "availability_impact": "NONE",
        "privileges_required": "LOW",
    },
    "access_control": {
        "confidentiality_impact": "HIGH",
        "integrity_impact": "HIGH",
        "availability_impact": "NONE",
    },
    "auth_bypass": {
        "confidentiality_impact": "HIGH",
        "integrity_impact": "HIGH",
        "availability_impact": "NONE",
        "scope": "CHANGED",
    },
    "privilege_escalation": {
        "confidentiality_impact": "HIGH",
        "integrity_impact": "HIGH",
        "availability_impact": "HIGH",
        "scope": "CHANGED",
    },
    "ssti": {
        "confidentiality_impact": "HIGH",
        "integrity_impact": "HIGH",
        "availability_impact": "HIGH",
        "scope": "CHANGED",
    },
    "xxe": {
        "confidentiality_impact": "HIGH",
        "integrity_impact": "LOW",
        "availability_impact": "LOW",
    },
    "open_redirect": {
        "confidentiality_impact": "NONE",
        "integrity_impact": "LOW",
        "availability_impact": "NONE",
        "user_interaction": "REQUIRED",
    },
    "cors": {
        "confidentiality_impact": "LOW",
        "integrity_impact": "NONE",
        "availability_impact": "NONE",
    },
    "csrf": {
        "confidentiality_impact": "LOW",
        "integrity_impact": "LOW",
        "availability_impact": "NONE",
        "user_interaction": "REQUIRED",
    },
    "info_disclosure": {
        "confidentiality_impact": "LOW",
        "integrity_impact": "NONE",
        "availability_impact": "NONE",
    },
    "jwt": {
        "confidentiality_impact": "HIGH",
        "integrity_impact": "HIGH",
        "availability_impact": "NONE",
        "scope": "CHANGED",
    },
    "business_logic": {
        "confidentiality_impact": "LOW",
        "integrity_impact": "HIGH",
        "availability_impact": "NONE",
    },
    "race": {
        "confidentiality_impact": "LOW",
        "integrity_impact": "HIGH",
        "availability_impact": "LOW",
    },
}


def score_finding_cvss(finding: dict[str, Any]) -> CVSSScore:
    """Score a finding dict with CVSS 3.1 based on vuln_class + severity."""
    vuln_class = (finding.get("vuln_class") or finding.get("type") or "").lower()
    our_sev = (finding.get("severity") or "info").lower()

    defaults = dict(_VULN_CLASS_DEFAULTS.get(vuln_class, {}))

    # Adjust CIA impact caps based on our severity label if not set by class
    sev_cia = {
        "critical": ("HIGH", "HIGH", "HIGH"),
        "high": ("HIGH", "HIGH", "LOW"),
        "medium": ("LOW", "LOW", "NONE"),
        "low": ("LOW", "NONE", "NONE"),
        "info": ("NONE", "NONE", "NONE"),
    }
    if "confidentiality_impact" not in defaults:
        c, i, a = sev_cia.get(our_sev, ("LOW", "NONE", "NONE"))
        defaults["confidentiality_impact"] = c
        defaults["integrity_impact"] = i
        defaults["availability_impact"] = a

    # Info findings → score 0
    if our_sev == "info" and vuln_class not in _VULN_CLASS_DEFAULTS:
        return CVSSScore(base_score=0.0, severity="NONE", vector="", metrics={})

    return compute_cvss_base(**defaults)


def enhance_finding_with_cvss(finding: dict[str, Any]) -> dict[str, Any]:
    """Return finding dict with cvss field populated."""
    score = score_finding_cvss(finding)
    finding["cvss"] = score.to_dict()
    return finding
