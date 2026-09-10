"""Working memory for the Researcher.

Structured observations, business object tracking, hypothesis confidence,
and dynamic LLM context. No fake intelligence. No event buses. Just data.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    title: str
    severity: Severity
    vuln_class: str
    endpoint: str
    method: str
    evidence: str
    reproduction: list[str]
    impact: str
    confirmed: bool = False
    timestamp: float = field(default_factory=time.time)
    request: dict | None = None
    response: dict | None = None
    screenshot: str | None = None

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "vuln_class": self.vuln_class,
            "endpoint": self.endpoint,
            "method": self.method,
            "evidence": self.evidence,
            "reproduction": self.reproduction,
            "impact": self.impact,
            "confirmed": self.confirmed,
            "timestamp": self.timestamp,
            "request": self.request,
            "response": self.response,
            "screenshot": self.screenshot,
        }


@dataclass
class Hypothesis:
    description: str
    vuln_class: str
    endpoint: str
    confidence: float
    test_plan: list[str]
    status: str = "pending"  # pending, testing, confirmed, rejected
    result: str | None = None
    evidence_for: list[str] = field(default_factory=list)
    evidence_against: list[str] = field(default_factory=list)
    tests_run: int = 0
    tests_succeeded: int = 0
    timestamp: float = field(default_factory=time.time)

    def update_confidence(self):
        """Update confidence based on evidence."""
        total = len(self.evidence_for) + len(self.evidence_against)
        if total == 0:
            return
        positive = len(self.evidence_for)
        self.confidence = positive / total
        if self.confidence > 0.8:
            self.status = "confirmed"
        elif self.confidence < 0.2:
            self.status = "rejected"


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    params: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    body: str | None = None
    content_type: str | None = None
    status_code: int | None = None
    response_length: int | None = None
    response_snippet: str | None = None
    tech_stack: list[str] = field(default_factory=list)
    auth_required: bool = False
    tested: bool = False
    discovered_at: float = field(default_factory=time.time)
    request: dict | None = None  # Full request for replay
    response: dict | None = None  # Full response


@dataclass
class BusinessObject:
    """A business entity discovered during the hunt."""
    object_type: str  # e.g., "offer", "user", "order", "invoice"
    object_id: str  # e.g., "8123", "uuid-here"
    owner: str | None = None  # e.g., "buyer_a", "admin"
    organization: str | None = None
    workflow: str | None = None  # e.g., "purchase", "invite"
    permissions: list[str] = field(default_factory=list)  # e.g., ["owner_only"]
    endpoint: str = ""  # Where this object was discovered
    data: dict = field(default_factory=dict)  # Any associated data
    discovered_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "object_type": self.object_type,
            "object_id": self.object_id,
            "owner": self.owner,
            "organization": self.organization,
            "workflow": self.workflow,
            "permissions": self.permissions,
            "endpoint": self.endpoint,
            "data": self.data,
        }


@dataclass
class Observation:
    """A structured observation about the target."""
    description: str
    endpoint: str
    category: str  # e.g., "endpoint_behavior", "auth_flow", "data_leak", "business_logic"
    entities: list[str] = field(default_factory=list)  # Related business objects
    properties: dict[str, Any] = field(default_factory=dict)  # Structured data
    confidence: float = 1.0
    timestamp: float = field(default_factory=time.time)


class Memory:
    """Working memory for the researcher.

    Tracks:
    - Target info (URL, tech stack, auth state)
    - Discovered endpoints with full request/response for replay
    - Business objects (users, offers, orders, etc.)
    - Structured observations with entities and properties
    - Hypotheses with evidence-based confidence
    - Findings with full evidence packages
    - Tested endpoints (to avoid duplicates)
    """

    def __init__(self, target_url: str, output_dir: str = "hunt_output"):
        self.target_url = target_url
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Target profile
        self.tech_stack: list[str] = []
        self.auth_state: dict[str, Any] = {}
        self.scope: list[str] = []
        self.current_user: str | None = None
        self.current_role: str | None = None

        # Working data
        self.endpoints: dict[str, Endpoint] = {}  # url -> Endpoint
        self.hypotheses: list[Hypothesis] = []
        self.findings: list[Finding] = []
        self.observations: list[Observation] = []
        self.evidence: list[dict[str, Any]] = []
        self.business_objects: list[BusinessObject] = []

        # Tracking
        self.tested_urls: set[str] = set()
        self.test_count: int = 0
        self.finding_count: int = 0
        self.start_time: float = time.time()
        self.failed_tests: list[dict[str, Any]] = []

    # ============================================================
    # Endpoint management
    # ============================================================

    def add_endpoint(self, url: str, **kwargs) -> Endpoint:
        if url not in self.endpoints:
            self.endpoints[url] = Endpoint(url=url, **kwargs)
        else:
            for k, v in kwargs.items():
                if v is not None:
                    setattr(self.endpoints[url], k, v)
        return self.endpoints[url]

    def mark_tested(self, url: str, method: str = "GET"):
        key = f"{method} {url}"
        self.tested_urls.add(key)
        if url in self.endpoints:
            self.endpoints[url].tested = True

    # ============================================================
    # Hypothesis management
    # ============================================================

    def add_hypothesis(self, description: str, vuln_class: str, endpoint: str,
                       confidence: float, test_plan: list[str]) -> Hypothesis:
        h = Hypothesis(
            description=description,
            vuln_class=vuln_class,
            endpoint=endpoint,
            confidence=confidence,
            test_plan=test_plan,
        )
        self.hypotheses.append(h)
        return h

    def get_active_hypotheses(self) -> list[Hypothesis]:
        return [h for h in self.hypotheses if h.status in ("pending", "testing")]

    def get_confirmed_hypotheses(self) -> list[Hypothesis]:
        return [h for h in self.hypotheses if h.status == "confirmed"]

    def get_rejected_hypotheses(self) -> list[Hypothesis]:
        return [h for h in self.hypotheses if h.status == "rejected"]

    # ============================================================
    # Finding management
    # ============================================================

    def add_finding(self, title: str, severity: str, vuln_class: str,
                    endpoint: str, method: str, evidence: str,
                    reproduction: list[str], impact: str,
                    request: dict | None = None, response: dict | None = None,
                    screenshot: str | None = None) -> Finding:
        f = Finding(
            title=title,
            severity=Severity(severity),
            vuln_class=vuln_class,
            endpoint=endpoint,
            method=method,
            evidence=evidence,
            reproduction=reproduction,
            impact=impact,
            confirmed=True,
            request=request,
            response=response,
            screenshot=screenshot,
        )
        self.findings.append(f)
        self.finding_count += 1
        return f

    # ============================================================
    # Observation management
    # ============================================================

    def add_observation(self, description: str, endpoint: str,
                        category: str = "general",
                        entities: list[str] | None = None,
                        properties: dict[str, Any] | None = None,
                        confidence: float = 1.0):
        self.observations.append(Observation(
            description=description,
            endpoint=endpoint,
            category=category,
            entities=entities or [],
            properties=properties or {},
            confidence=confidence,
        ))

    def get_observations_by_category(self, category: str) -> list[Observation]:
        return [o for o in self.observations if o.category == category]

    def get_observations_for_entity(self, entity: str) -> list[Observation]:
        return [o for o in self.observations if entity in o.entities]

    # ============================================================
    # Business object management
    # ============================================================

    def add_business_object(self, object_type: str, object_id: str,
                            owner: str | None = None, organization: str | None = None,
                            workflow: str | None = None, permissions: list[str] | None = None,
                            endpoint: str = "", data: dict | None = None) -> BusinessObject:
        obj = BusinessObject(
            object_type=object_type,
            object_id=object_id,
            owner=owner,
            organization=organization,
            workflow=workflow,
            permissions=permissions or [],
            endpoint=endpoint,
            data=data or {},
        )
        self.business_objects.append(obj)
        return obj

    def get_idor_candidates(self) -> list[tuple[BusinessObject, BusinessObject]]:
        """Find object pairs that could be IDOR targets (same type, different owners)."""
        candidates = []
        by_type: dict[str, list[BusinessObject]] = {}
        for obj in self.business_objects:
            by_type.setdefault(obj.object_type, []).append(obj)
        for obj_type, objects in by_type.items():
            owners = set(o.owner for o in objects if o.owner)
            if len(owners) > 1:
                for i, o1 in enumerate(objects):
                    for o2 in objects[i+1:]:
                        if o1.owner != o2.owner:
                            candidates.append((o1, o2))
        return candidates

    # ============================================================
    # Evidence management
    # ============================================================

    def add_evidence(self, method: str, url: str, request_headers: dict,
                     request_body: str | None, response_status: int,
                     response_headers: dict, response_body: str):
        self.evidence.append({
            "method": method,
            "url": url,
            "request_headers": request_headers,
            "request_body": request_body,
            "response_status": response_status,
            "response_headers": response_headers,
            "response_body": response_body[:10000],
            "timestamp": time.time(),
        })

    def add_failed_test(self, url: str, method: str, reason: str, test_type: str):
        """Record a failed test to avoid repeating it."""
        self.failed_tests.append({
            "url": url,
            "method": method,
            "reason": reason,
            "test_type": test_type,
            "timestamp": time.time(),
        })

    def is_already_tested(self, url: str, method: str, test_type: str) -> bool:
        """Check if a specific test has already been attempted."""
        return any(
            t["url"] == url and t["method"] == method and t["test_type"] == test_type
            for t in self.failed_tests
        )

    # ============================================================
    # Dynamic LLM context
    # ============================================================

    # ============================================================
    # Persistence
    # ============================================================

    def get_summary(self) -> dict:
        return {
            "target": self.target_url,
            "tech_stack": self.tech_stack,
            "current_user": self.current_user,
            "current_role": self.current_role,
            "endpoints_discovered": len(self.endpoints),
            "endpoints_tested": len(self.tested_urls),
            "business_objects": len(self.business_objects),
            "idor_candidates": len(self.get_idor_candidates()),
            "hypotheses": len(self.hypotheses),
            "hypotheses_active": len(self.get_active_hypotheses()),
            "hypotheses_confirmed": len(self.get_confirmed_hypotheses()),
            "hypotheses_rejected": len(self.get_rejected_hypotheses()),
            "findings": len(self.findings),
            "observations": len(self.observations),
            "evidence_items": len(self.evidence),
            "failed_tests": len(self.failed_tests),
            "runtime_seconds": time.time() - self.start_time,
        }

    def save(self, filename: str = "hunt_state.json"):
        path = self.output_dir / filename
        data = {
            "target": self.target_url,
            "tech_stack": self.tech_stack,
            "auth_state": self.auth_state,
            "current_user": self.current_user,
            "current_role": self.current_role,
            "scope": self.scope,
            "endpoints": {url: {
                "url": e.url,
                "method": e.method,
                "status_code": e.status_code,
                "tech_stack": e.tech_stack,
                "auth_required": e.auth_required,
                "tested": e.tested,
                "request": e.request,
            } for url, e in self.endpoints.items()},
            "business_objects": [o.to_dict() for o in self.business_objects],
            "hypotheses": [{
                "description": h.description,
                "vuln_class": h.vuln_class,
                "endpoint": h.endpoint,
                "confidence": h.confidence,
                "status": h.status,
                "result": h.result,
                "evidence_for": h.evidence_for,
                "evidence_against": h.evidence_against,
                "tests_run": h.tests_run,
                "tests_succeeded": h.tests_succeeded,
            } for h in self.hypotheses],
            "findings": [f.to_dict() for f in self.findings],
            "observations": [{
                "description": o.description,
                "endpoint": o.endpoint,
                "category": o.category,
                "entities": o.entities,
                "properties": o.properties,
                "confidence": o.confidence,
                "timestamp": o.timestamp,
            } for o in self.observations],
            "failed_tests": self.failed_tests,
            "summary": self.get_summary(),
        }
        path.write_text(json.dumps(data, indent=2))
