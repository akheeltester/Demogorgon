"""Canonical domain models — the single source of truth.

Every module that needs Finding, Hypothesis, Endpoint, BusinessObject, etc.
imports from this file. Backward-compatible aliases are provided in
memory.py and app_model.py for existing consumers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4


# ── Enums ───────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class HypothesisStatus(str, Enum):
    PENDING = "pending"
    TESTING = "testing"
    CONFIRMED = "confirmed"
    FALSE = "false"
    INCONCLUSIVE = "inconclusive"
    REJECTED = "rejected"
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


class ProductType(str, Enum):
    ECOMMERCE = "ecommerce"
    BANKING = "banking"
    MARKETPLACE = "marketplace"
    SAAS = "saas"
    SOCIAL = "social"
    HEALTHCARE = "healthcare"
    GOVERNMENT = "government"
    AI_PLATFORM = "ai_platform"
    EDUCATION = "education"
    GAMING = "gaming"
    UNKNOWN = "unknown"


class ObjectState(str, Enum):
    CREATED = "created"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DELETED = "deleted"
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


# ── Core Data Models ────────────────────────────────────────────

@dataclass
class Finding:
    """A confirmed or likely vulnerability finding."""
    title: str
    severity: Severity | str
    vuln_class: str
    endpoint: str
    method: str = "GET"
    evidence: list[dict[str, Any]] = field(default_factory=list)
    reproduction: str = ""
    impact: str = ""
    confirmed: bool = False
    confidence: float = 0.0
    request: str = ""
    response: str = ""
    screenshot: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        sev = self.severity.value if isinstance(self.severity, Severity) else self.severity
        return {
            "title": self.title,
            "severity": sev,
            "vuln_class": self.vuln_class,
            "endpoint": self.endpoint,
            "method": self.method,
            "evidence": self.evidence,
            "reproduction": self.reproduction,
            "impact": self.impact,
            "confirmed": self.confirmed,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "request": self.request,
            "response": self.response,
            "screenshot": self.screenshot,
        }


@dataclass
class Hypothesis:
    """A testable hypothesis about a potential vulnerability.

    Superset of all three original definitions (memory.py, are/research_memory.py,
    controller/executive.py). Backward-compatible with all consumers.
    """
    id: str = field(default_factory=lambda: str(uuid4())[:8])
    description: str = ""

    # Classification (superset of vuln_class and attack_family)
    vuln_class: str = ""
    attack_family: AttackFamily | str = ""

    # Target
    endpoint: str = ""
    method: str = "GET"
    parameter: str = ""

    # Status — accepts str or HypothesisStatus for backward compat
    status: HypothesisStatus | str = HypothesisStatus.PENDING
    confidence: float = 0.5
    initial_confidence: float = 0.5

    # Test plan and results
    test_plan: str = ""
    result: str = ""
    failure_reason: str = ""

    # Evidence tracking
    evidence: list[dict[str, Any]] = field(default_factory=list)
    evidence_for: list[dict[str, Any]] = field(default_factory=list)
    evidence_against: list[dict[str, Any]] = field(default_factory=list)

    # Execution tracking
    tests_run: int = 0
    tests_succeeded: int = 0
    tested: bool = False

    # Chain support
    related_endpoints: list[str] = field(default_factory=list)
    business_object: str = ""
    chain_step: int = 0
    parent_chain_id: str = ""
    mutation_attempts: int = 0

    # Timestamps
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    tested_at: str = ""

    @property
    def is_pending(self) -> bool:
        if isinstance(self.status, HypothesisStatus):
            return self.status == HypothesisStatus.PENDING
        return str(self.status).lower() in ("pending", "")

    @property
    def is_confirmed(self) -> bool:
        if isinstance(self.status, HypothesisStatus):
            return self.status == HypothesisStatus.CONFIRMED
        return str(self.status).lower() == "confirmed"

    def update_confidence(self):
        """Update confidence based on evidence_for/evidence_against lists."""
        total = len(self.evidence_for) + len(self.evidence_against)
        if total == 0:
            return
        positive = len(self.evidence_for)
        self.confidence = positive / total
        if self.confidence > 0.8:
            self.status = HypothesisStatus.CONFIRMED
        elif self.confidence < 0.2:
            self.status = HypothesisStatus.REJECTED

    def to_dict(self) -> dict:
        st = self.status.value if isinstance(self.status, HypothesisStatus) else self.status
        af = self.attack_family.value if isinstance(self.attack_family, AttackFamily) else self.attack_family
        return {
            "id": self.id,
            "description": self.description,
            "vuln_class": self.vuln_class,
            "attack_family": af,
            "endpoint": self.endpoint,
            "method": self.method,
            "parameter": self.parameter,
            "status": st,
            "confidence": self.confidence,
            "test_plan": self.test_plan,
            "result": self.result,
            "failure_reason": self.failure_reason,
            "evidence_for": self.evidence_for,
            "evidence_against": self.evidence_against,
            "tests_run": self.tests_run,
            "tests_succeeded": self.tests_succeeded,
            "tested": self.tested,
            "timestamp": self.timestamp,
        }


@dataclass
class Endpoint:
    """A discovered API endpoint."""
    url: str
    method: str = "GET"
    params: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    content_type: str = ""
    status_code: int = 0
    response_length: int = 0
    response_snippet: str = ""
    tech_stack: list[str] = field(default_factory=list)
    auth_required: bool = False
    tested: bool = False
    discovered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    request: str = ""
    response: str = ""


@dataclass
class BusinessObject:
    """A business entity discovered during testing (user, order, token, etc.).

    Superset of both memory.py and app_model.py definitions.
    """
    object_type: str = ""
    # Identity — both field names supported for backward compat
    object_id: str = ""
    identifier: str = ""

    # Ownership
    owner: str = ""
    organization: str = ""
    id_type: str = ""

    # Visibility & lifecycle
    visibility: str = "private"
    lifecycle: str = ""
    state: ObjectState | str = ObjectState.ACTIVE

    # Relationships
    parent_objects: list[str] = field(default_factory=list)
    child_objects: list[str] = field(default_factory=list)

    # Structure & access
    properties: dict[str, Any] = field(default_factory=dict)
    workflow: str = ""
    permissions: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)

    # Location
    endpoint: str = ""
    discovered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self):
        # Sync the two identifier fields
        if self.object_id and not self.identifier:
            self.identifier = self.object_id
        elif self.identifier and not self.object_id:
            self.object_id = self.identifier

    def to_dict(self) -> dict:
        st = self.state.value if isinstance(self.state, ObjectState) else self.state
        return {
            "object_type": self.object_type,
            "object_id": self.object_id,
            "identifier": self.identifier,
            "owner": self.owner,
            "organization": self.organization,
            "workflow": self.workflow,
            "permissions": self.permissions,
            "endpoint": self.endpoint,
            "data": self.data,
            "visibility": self.visibility,
            "lifecycle": self.lifecycle,
            "state": st,
            "id_type": self.id_type,
            "properties": self.properties,
            "discovered_at": self.discovered_at,
        }


@dataclass
class Observation:
    """A factual observation about the target application."""
    description: str
    endpoint: str = ""
    category: str = ""
    entities: list[str] = field(default_factory=list)
    properties: dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class TrustBoundary:
    """A boundary between trust levels in the application.

    Superset of both app_model.py and are/trust_boundary.py.
    """
    name: str = ""
    from_level: str = ""
    to_level: str = ""
    boundary_type: str = ""
    endpoint: str = ""
    description: str = ""
    bypass_techniques: list[str] = field(default_factory=list)
    test_generated: bool = False

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "from_level": self.from_level,
            "to_level": self.to_level,
            "boundary_type": self.boundary_type,
            "endpoint": self.endpoint,
            "description": self.description,
            "bypass_techniques": self.bypass_techniques,
            "test_generated": self.test_generated,
        }


@dataclass
class WorkflowStep:
    """A step in a business workflow."""
    name: str = ""
    endpoint: str = ""
    method: str = "GET"
    requires_auth: bool = False
    requires_role: str = ""
    produces_objects: list[str] = field(default_factory=list)
    consumes_objects: list[str] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)
    description: str = ""
    state_transition: str = ""
    trust_boundary_crossed: str = ""


@dataclass
class AttackOpportunity:
    """A potential attack identified from the application model."""
    description: str = ""
    vuln_class: str = ""
    endpoint: str = ""
    method: str = "GET"
    confidence: float = 0.5
    reasoning: str = ""
    test_plan: str = ""
    depends_on: list[str] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    expected_impact: str = ""


@dataclass
class AttackSurface:
    """A classified endpoint on the attack surface."""
    endpoint: str = ""
    method: str = "GET"
    category: str = ""
    risk_level: str = "low"
    auth_required: bool = False
    rate_limited: bool = False
    description: str = ""
    parameters: list[str] = field(default_factory=list)
    state_changing: bool = False


@dataclass
class ObjectRelationship:
    """A relationship between two business objects."""
    from_type: str = ""
    to_type: str = ""
    relationship: str = ""
    from_id: str = ""
    to_id: str = ""
    description: str = ""
    bidirectional: bool = False
    trust_required: bool = False

    def to_dict(self) -> dict:
        return {
            "from_type": self.from_type,
            "to_type": self.to_type,
            "relationship": self.relationship,
            "from_id": self.from_id,
            "to_id": self.to_id,
            "description": self.description,
            "bidirectional": self.bidirectional,
            "trust_required": self.trust_required,
        }


@dataclass
class Experiment:
    """A planned or completed experiment."""
    id: str = field(default_factory=lambda: str(uuid4())[:8])
    hypothesis_id: str = ""
    executor: str = ""
    status: str = "pending"
    target: str = ""
    method: str = "GET"
    payload: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    started_at: str = ""
    completed_at: str = ""
    result: dict[str, Any] = field(default_factory=dict)
    finding: Finding | None = None


@dataclass
class ExperimentResult:
    """Result of a single experiment."""
    experiment_id: str = ""
    hypothesis_id: str = ""
    executor: str = ""
    endpoint: str = ""
    method: str = "GET"
    findings: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    new_observations: list[dict[str, Any]] = field(default_factory=list)
    new_business_objects: list[dict[str, Any]] = field(default_factory=list)
    is_finding: bool = False
    duration: float = 0.0
    error: str | None = None


@dataclass
class FindingScore:
    """5-dimensional scored finding from ExploitConfidenceEngine."""
    finding_id: str = ""
    title: str = ""
    severity: Severity | str = Severity.INFO
    vuln_class: str = ""
    endpoint: str = ""
    evidence_score: float = 0.0
    impact_score: float = 0.0
    reproducibility_score: float = 0.0
    business_value_score: float = 0.0
    exploitability_score: float = 0.0
    final_confidence: float = 0.0
    should_report: bool = False
    evidence: list[dict[str, Any]] = field(default_factory=list)
    reasoning: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class ResearchAction:
    """An action taken during research (logged by ResearchMemory)."""
    iteration: int = 0
    action_type: str = ""
    endpoint: str = ""
    method: str = "GET"
    hypothesis_id: str = ""
    payload: str = ""
    result_status: str = ""
    result_length: int = 0
    result_snippet: str = ""
    confidence_before: float = 0.5
    confidence_after: float = 0.5
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    duration: float = 0.0
    finding_created: bool = False
