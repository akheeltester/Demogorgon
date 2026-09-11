"""ResearchCase — persistent reasoning trail for autonomous research.

A ResearchCase captures the complete reasoning history of an investigation:
- What was observed
- What hypotheses were formed
- What experiments were run
- What evidence was collected
- What was validated
- What the next best action is

This enables resumability and explains WHY the system believes what it believes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
import json
import uuid


class CaseStatus(Enum):
    """Status of a research case."""
    ACTIVE = "active"
    PAUSED = "paused"  # HITL required
    COMPLETED = "completed"
    ABANDONED = "abandoned"
    BLOCKED = "blocked"


class HypothesisStatus(Enum):
    """Status of a hypothesis within a case."""
    PROPOSED = "proposed"
    TESTING = "testing"
    CONFIRMED = "confirmed"
    DISPROVED = "disproved"
    INCONCLUSIVE = "inconclusive"
    DEFERRED = "deferred"


@dataclass
class CaseObservation:
    """An observation recorded in the case."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    description: str = ""
    source: str = ""  # tool or module
    data: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.5
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "description": self.description,
            "source": self.source,
            "data": self.data,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
        }


@dataclass
class CaseHypothesis:
    """A hypothesis within a research case."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    description: str = ""
    vuln_class: str = ""
    endpoint: str = ""
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    confidence: float = 0.3
    supporting_observations: list[str] = field(default_factory=list)  # observation IDs
    experiments_run: list[str] = field(default_factory=list)  # experiment IDs
    evidence_for: list[str] = field(default_factory=list)
    evidence_against: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "description": self.description,
            "vuln_class": self.vuln_class,
            "endpoint": self.endpoint,
            "status": self.status.value,
            "confidence": self.confidence,
            "supporting_observations": self.supporting_observations,
            "experiments_run": self.experiments_run,
            "evidence_for": self.evidence_for,
            "evidence_against": self.evidence_against,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass
class CaseExperiment:
    """An experiment executed within a research case."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    hypothesis_id: str = ""
    action: str = ""
    target: str = ""
    tool: str = ""
    plan: dict[str, Any] = field(default_factory=dict)
    result: dict[str, Any] = field(default_factory=dict)
    observations: list[str] = field(default_factory=list)  # observation IDs
    evidence: list[str] = field(default_factory=list)
    success: bool = False
    error: str = ""
    duration: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "hypothesis_id": self.hypothesis_id,
            "action": self.action,
            "target": self.target,
            "tool": self.tool,
            "plan": self.plan,
            "result": self.result,
            "observations": self.observations,
            "evidence": self.evidence,
            "success": self.success,
            "error": self.error,
            "duration": self.duration,
            "timestamp": self.timestamp,
        }


@dataclass
class CaseFinding:
    """A validated finding within a research case."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    hypothesis_id: str = ""
    title: str = ""
    severity: str = "medium"
    vuln_class: str = ""
    endpoint: str = ""
    description: str = ""
    impact: str = ""
    remediation: str = ""
    confidence: float = 0.5
    evidence: list[str] = field(default_factory=list)  # experiment IDs
    steps_to_reproduce: list[str] = field(default_factory=list)
    confirmed: bool = False
    reported: bool = False
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "hypothesis_id": self.hypothesis_id,
            "title": self.title,
            "severity": self.severity,
            "vuln_class": self.vuln_class,
            "endpoint": self.endpoint,
            "description": self.description,
            "impact": self.impact,
            "remediation": self.remediation,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "steps_to_reproduce": self.steps_to_reproduce,
            "confirmed": self.confirmed,
            "reported": self.reported,
            "timestamp": self.timestamp,
        }


@dataclass
class NextBestAction:
    """The next best action to take."""
    action: str = ""
    target: str = ""
    reason: str = ""
    confidence: float = 0.5
    priority: float = 0.5
    hypothesis_id: str = ""
    tool_hint: str = ""
    params: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "target": self.target,
            "reason": self.reason,
            "confidence": self.confidence,
            "priority": self.priority,
            "hypothesis_id": self.hypothesis_id,
            "tool_hint": self.tool_hint,
            "params": self.params,
        }


@dataclass
class ResearchCase:
    """A complete research case with full reasoning trail.

    This is the core object that enables:
    - Resumability (can pause and continue later)
    - Explainability (can explain why we believe what we believe)
    - Accountability (full audit trail of actions)
    - Learning (patterns across cases)
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    engagement_id: str = ""
    target: str = ""
    status: CaseStatus = CaseStatus.ACTIVE

    # State
    observations: list[CaseObservation] = field(default_factory=list)
    hypotheses: list[CaseHypothesis] = field(default_factory=list)
    experiments: list[CaseExperiment] = field(default_factory=list)
    findings: list[CaseFinding] = field(default_factory=list)

    # Next action
    next_action: NextBestAction | None = None

    # Metadata
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    iteration: int = 0

    # Summary stats
    assets_discovered: int = 0
    endpoints_discovered: int = 0
    parameters_discovered: int = 0

    def add_observation(self, description: str, source: str, data: dict | None = None) -> CaseObservation:
        """Add an observation to the case."""
        obs = CaseObservation(
            description=description,
            source=source,
            data=data or {},
        )
        self.observations.append(obs)
        self.updated_at = datetime.now(timezone.utc).isoformat()
        return obs

    def add_hypothesis(self, description: str, vuln_class: str = "", endpoint: str = "") -> CaseHypothesis:
        """Add a hypothesis to the case."""
        hyp = CaseHypothesis(
            description=description,
            vuln_class=vuln_class,
            endpoint=endpoint,
        )
        self.hypotheses.append(hyp)
        self.updated_at = datetime.now(timezone.utc).isoformat()
        return hyp

    def add_experiment(self, hypothesis_id: str, action: str, target: str, tool: str = "") -> CaseExperiment:
        """Add an experiment to the case."""
        exp = CaseExperiment(
            hypothesis_id=hypothesis_id,
            action=action,
            target=target,
            tool=tool,
        )
        self.experiments.append(exp)
        self.updated_at = datetime.now(timezone.utc).isoformat()
        return exp

    def add_finding(self, hypothesis_id: str, title: str, severity: str, vuln_class: str, endpoint: str) -> CaseFinding:
        """Add a finding to the case."""
        finding = CaseFinding(
            hypothesis_id=hypothesis_id,
            title=title,
            severity=severity,
            vuln_class=vuln_class,
            endpoint=endpoint,
        )
        self.findings.append(finding)
        self.updated_at = datetime.now(timezone.utc).isoformat()
        return finding

    def get_active_hypotheses(self) -> list[CaseHypothesis]:
        """Get hypotheses that are still being investigated."""
        return [h for h in self.hypotheses if h.status in (HypothesisStatus.PROPOSED, HypothesisStatus.TESTING)]

    def get_confirmed_findings(self) -> list[CaseFinding]:
        """Get confirmed findings."""
        return [f for f in self.findings if f.confirmed]

    def get_next_action(self) -> NextBestAction | None:
        """Get the next best action."""
        return self.next_action

    def set_next_action(self, action: NextBestAction):
        """Set the next best action."""
        self.next_action = action
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def increment_iteration(self):
        """Increment the iteration counter."""
        self.iteration += 1
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        """Serialize the case to a dictionary."""
        return {
            "id": self.id,
            "engagement_id": self.engagement_id,
            "target": self.target,
            "status": self.status.value,
            "observations": [o.to_dict() for o in self.observations],
            "hypotheses": [h.to_dict() for h in self.hypotheses],
            "experiments": [e.to_dict() for e in self.experiments],
            "findings": [f.to_dict() for f in self.findings],
            "next_action": self.next_action.to_dict() if self.next_action else None,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "iteration": self.iteration,
            "stats": {
                "observations": len(self.observations),
                "hypotheses": len(self.hypotheses),
                "experiments": len(self.experiments),
                "findings": len(self.findings),
                "confirmed_findings": len(self.get_confirmed_findings()),
                "active_hypotheses": len(self.get_active_hypotheses()),
            },
            "assets_discovered": self.assets_discovered,
            "endpoints_discovered": self.endpoints_discovered,
            "parameters_discovered": self.parameters_discovered,
        }

    def save(self, path: str):
        """Save the case to a JSON file."""
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, path: str) -> ResearchCase:
        """Load a case from a JSON file."""
        with open(path) as f:
            data = json.load(f)

        case = cls(
            id=data["id"],
            engagement_id=data.get("engagement_id", ""),
            target=data.get("target", ""),
            status=CaseStatus(data.get("status", "active")),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
            iteration=data.get("iteration", 0),
            assets_discovered=data.get("assets_discovered", 0),
            endpoints_discovered=data.get("endpoints_discovered", 0),
            parameters_discovered=data.get("parameters_discovered", 0),
        )

        for obs_data in data.get("observations", []):
            case.observations.append(CaseObservation(**obs_data))

        for hyp_data in data.get("hypotheses", []):
            hyp_data["status"] = HypothesisStatus(hyp_data.get("status", "proposed"))
            case.hypotheses.append(CaseHypothesis(**hyp_data))

        for exp_data in data.get("experiments", []):
            case.experiments.append(CaseExperiment(**exp_data))

        for find_data in data.get("findings", []):
            case.findings.append(CaseFinding(**find_data))

        if data.get("next_action"):
            case.next_action = NextBestAction(**data["next_action"])

        return case

    def __repr__(self) -> str:
        return (
            f"ResearchCase(id={self.id}, target={self.target}, "
            f"status={self.status.value}, iteration={self.iteration}, "
            f"findings={len(self.findings)}, hypotheses={len(self.hypotheses)})"
        )
