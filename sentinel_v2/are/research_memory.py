"""Research Memory — replaces visited endpoints with intelligent research state.

Stores hypothesis, result, confidence, failure reason, evidence,
related endpoints, business object, and attack family.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class HypothesisStatus(str, Enum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    FALSE = "false"
    INCONCLUSIVE = "inconclusive"
    ESCALATED = "escalated"


class AttackFamily(str, Enum):
    IDOR = "idor"
    XSS = "xss"
    SQLI = "sqli"
    SSRF = "ssrf"
    AUTH_BYPASS = "auth_bypass"
    PRIVESC = "privesc"
    RACE = "race"
    BUSINESS_LOGIC = "business_logic"
    INFO_DISCLOSURE = "info_disclosure"
    CSRF = "csrf"
    JWT = "jwt"
    UPLOAD = "upload"
    INJECTION = "injection"
    OPEN_REDIRECT = "open_redirect"
    CHAIN = "chain"
    OTHER = "other"


@dataclass
class Hypothesis:
    id: str
    description: str
    attack_family: AttackFamily
    endpoint: str
    method: str = "GET"
    parameter: str = ""
    status: HypothesisStatus = HypothesisStatus.PENDING
    confidence: float = 0.5
    initial_confidence: float = 0.5
    result: str = ""
    failure_reason: str = ""
    evidence: list[dict[str, Any]] = field(default_factory=list)
    related_endpoints: list[str] = field(default_factory=list)
    business_object: str = ""
    created_at: float = field(default_factory=time.time)
    tested_at: float = 0
    test_count: int = 0
    mutation_attempts: int = 0
    chain_step: int = 0
    parent_chain_id: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "description": self.description,
            "attack_family": self.attack_family.value,
            "endpoint": self.endpoint,
            "method": self.method,
            "parameter": self.parameter,
            "status": self.status.value,
            "confidence": self.confidence,
            "initial_confidence": self.initial_confidence,
            "result": self.result,
            "failure_reason": self.failure_reason,
            "evidence": self.evidence,
            "related_endpoints": self.related_endpoints,
            "business_object": self.business_object,
            "created_at": self.created_at,
            "tested_at": self.tested_at,
            "test_count": self.test_count,
            "mutation_attempts": self.mutation_attempts,
            "chain_step": self.chain_step,
            "parent_chain_id": self.parent_chain_id,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Hypothesis:
        return cls(
            id=data["id"],
            description=data["description"],
            attack_family=AttackFamily(data.get("attack_family", "other")),
            endpoint=data.get("endpoint", ""),
            method=data.get("method", "GET"),
            parameter=data.get("parameter", ""),
            status=HypothesisStatus(data.get("status", "pending")),
            confidence=data.get("confidence", 0.5),
            initial_confidence=data.get("initial_confidence", 0.5),
            result=data.get("result", ""),
            failure_reason=data.get("failure_reason", ""),
            evidence=data.get("evidence", []),
            related_endpoints=data.get("related_endpoints", []),
            business_object=data.get("business_object", ""),
            created_at=data.get("created_at", 0),
            tested_at=data.get("tested_at", 0),
            test_count=data.get("test_count", 0),
            mutation_attempts=data.get("mutation_attempts", 0),
            chain_step=data.get("chain_step", 0),
            parent_chain_id=data.get("parent_chain_id", ""),
        )


@dataclass
class ResearchAction:
    iteration: int
    action_type: str
    endpoint: str
    method: str
    hypothesis_id: str = ""
    payload: str = ""
    result_status: int = 0
    result_length: int = 0
    result_snippet: str = ""
    confidence_before: float = 0
    confidence_after: float = 0
    timestamp: float = field(default_factory=time.time)
    duration: float = 0
    finding_created: bool = False

    def to_dict(self) -> dict:
        return {
            "iteration": self.iteration,
            "action_type": self.action_type,
            "endpoint": self.endpoint,
            "method": self.method,
            "hypothesis_id": self.hypothesis_id,
            "payload": self.payload,
            "result_status": self.result_status,
            "result_length": self.result_length,
            "result_snippet": self.result_snippet,
            "confidence_before": self.confidence_before,
            "confidence_after": self.confidence_after,
            "timestamp": self.timestamp,
            "duration": self.duration,
            "finding_created": self.finding_created,
        }


class ResearchMemory:
    """Intelligent research state tracker.

    Stores hypotheses, actions, and learning state.
    Enables the researcher to never repeat failed approaches.
    """

    def __init__(self, output_dir: str = "hunt_output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.hypotheses: dict[str, Hypothesis] = {}
        self.actions: list[ResearchAction] = []
        self.failed_approaches: set[str] = set()
        self.successful_patterns: list[dict[str, Any]] = []
        self.total_actions: int = 0
        self.total_findings: int = 0
        self.total_hypotheses: int = 0
        self._hypothesis_counter: int = 0

    def create_hypothesis(
        self,
        description: str,
        attack_family: str,
        endpoint: str,
        method: str = "GET",
        parameter: str = "",
        confidence: float = 0.5,
        related: list[str] | None = None,
        business_object: str = "",
    ) -> Hypothesis:
        self._hypothesis_counter += 1
        h = Hypothesis(
            id=f"H{self._hypothesis_counter:04d}",
            description=description,
            attack_family=AttackFamily(attack_family),
            endpoint=endpoint,
            method=method,
            parameter=parameter,
            confidence=confidence,
            initial_confidence=confidence,
            related_endpoints=related or [],
            business_object=business_object,
        )
        self.hypotheses[h.id] = h
        self.total_hypotheses += 1
        return h

    def record_action(self, action: ResearchAction) -> None:
        self.actions.append(action)
        self.total_actions += 1
        if action.finding_created:
            self.total_findings += 1

    def mark_failed(self, hypothesis_id: str, reason: str) -> Hypothesis | None:
        h = self.hypotheses.get(hypothesis_id)
        if not h:
            return None
        h.status = HypothesisStatus.FALSE
        h.failure_reason = reason
        h.tested_at = time.time()
        h.test_count += 1
        approach_key = f"{h.attack_family.value}:{h.endpoint}:{h.parameter}"
        self.failed_approaches.add(approach_key)
        return h

    def mark_confirmed(self, hypothesis_id: str, evidence: list[dict] | None = None) -> Hypothesis | None:
        h = self.hypotheses.get(hypothesis_id)
        if not h:
            return None
        h.status = HypothesisStatus.CONFIRMED
        h.confidence = 1.0
        h.tested_at = time.time()
        if evidence:
            h.evidence.extend(evidence)
        self.successful_patterns.append({
            "attack_family": h.attack_family.value,
            "endpoint_pattern": h.endpoint,
            "parameter": h.parameter,
        })
        return h

    def is_failed(self, attack_family: str, endpoint: str, parameter: str = "") -> bool:
        key = f"{attack_family}:{endpoint}:{parameter}"
        return key in self.failed_approaches

    def get_untested_hypotheses(self) -> list[Hypothesis]:
        return [h for h in self.hypotheses.values() if h.status == HypothesisStatus.PENDING]

    def get_highest_confidence_pending(self) -> Hypothesis | None:
        pending = self.get_untested_hypotheses()
        if not pending:
            return None
        return max(pending, key=lambda h: h.confidence)

    def get_repeated_failures(self) -> list[str]:
        failure_counts: dict[str, int] = {}
        for h in self.hypotheses.values():
            if h.status == HypothesisStatus.FALSE:
                key = f"{h.attack_family.value}:{h.endpoint}"
                failure_counts[key] = failure_counts.get(key, 0) + 1
        return [k for k, v in failure_counts.items() if v >= 2]

    def get_coverage(self) -> dict[str, Any]:
        families = {}
        for h in self.hypotheses.values():
            f = h.attack_family.value
            if f not in families:
                families[f] = {"total": 0, "confirmed": 0, "false": 0, "pending": 0}
            families[f]["total"] += 1
            if h.status == HypothesisStatus.CONFIRMED:
                families[f]["confirmed"] += 1
            elif h.status == HypothesisStatus.FALSE:
                families[f]["false"] += 1
            elif h.status == HypothesisStatus.PENDING:
                families[f]["pending"] += 1
        return {
            "total_hypotheses": self.total_hypotheses,
            "total_actions": self.total_actions,
            "total_findings": self.total_findings,
            "failed_approaches": len(self.failed_approaches),
            "by_family": families,
        }

    def should_skip(self, attack_family: str, endpoint: str, parameter: str = "") -> bool:
        return self.is_failed(attack_family, endpoint, parameter)

    def save(self) -> None:
        data = {
            "hypotheses": {k: v.to_dict() for k, v in self.hypotheses.items()},
            "actions": [a.to_dict() for a in self.actions[-200:]],
            "failed_approaches": list(self.failed_approaches),
            "successful_patterns": self.successful_patterns,
            "total_actions": self.total_actions,
            "total_findings": self.total_findings,
            "total_hypotheses": self.total_hypotheses,
            "_hypothesis_counter": self._hypothesis_counter,
        }
        path = self.output_dir / "research_memory.json"
        path.write_text(json.dumps(data, indent=2, default=str))

    def load(self) -> bool:
        path = self.output_dir / "research_memory.json"
        if not path.exists():
            return False
        try:
            data = json.loads(path.read_text())
            for hid, hdata in data.get("hypotheses", {}).items():
                self.hypotheses[hid] = Hypothesis.from_dict(hdata)
            for adata in data.get("actions", []):
                self.actions.append(ResearchAction(**adata))
            self.failed_approaches = set(data.get("failed_approaches", []))
            self.successful_patterns = data.get("successful_patterns", [])
            self.total_actions = data.get("total_actions", 0)
            self.total_findings = data.get("total_findings", 0)
            self.total_hypotheses = data.get("total_hypotheses", 0)
            self._hypothesis_counter = data.get("_hypothesis_counter", 0)
            return True
        except Exception:
            return False
