"""Working memory for the Researcher.

Structured observations, business object tracking, hypothesis confidence,
and dynamic LLM context. No fake intelligence. No event buses. Just data.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

# Canonical models — single source of truth
from demogorgon.core.models import (
    Severity,
    Finding,
    Hypothesis,
    Endpoint,
    BusinessObject,
    Observation,
)


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
        return [h for h in self.hypotheses
                if h.status in ("pending", "testing")]

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
                    screenshot: str | None = None,
                    confidence: float = 0.0) -> Finding:
        f = Finding(
            title=title,
            severity=Severity(severity),
            vuln_class=vuln_class,
            endpoint=endpoint,
            method=method,
            evidence=[{"text": evidence}] if evidence else [],
            reproduction=reproduction,
            impact=impact,
            confirmed=True,
            confidence=confidence,
            request=str(request) if request else "",
            response=str(response) if response else "",
            screenshot=screenshot or "",
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
            owner=owner or "",
            organization=organization or "",
            workflow=workflow or "",
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
    # Summary & Persistence
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
            "hypotheses": [h.to_dict() for h in self.hypotheses],
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
        path.write_text(json.dumps(data, indent=2, default=str))

    @classmethod
    def load(cls, target_url: str, filename: str = "hunt_state.json",
             output_dir: str = "hunt_output") -> Memory | None:
        """Load saved state. Returns None if no checkpoint exists."""
        path = Path(output_dir) / filename
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text())
            mem = cls(target_url, output_dir)
            mem.tech_stack = data.get("tech_stack", [])
            mem.auth_state = data.get("auth_state", {})
            mem.scope = data.get("scope", [])
            mem.current_user = data.get("current_user")
            mem.current_role = data.get("current_role")

            for url_str, ep_data in data.get("endpoints", {}).items():
                mem.endpoints[url_str] = Endpoint(
                    url=ep_data["url"],
                    method=ep_data.get("method", "GET"),
                    status_code=ep_data.get("status_code", 0),
                    tech_stack=ep_data.get("tech_stack", []),
                    auth_required=ep_data.get("auth_required", False),
                    tested=ep_data.get("tested", False),
                    request=ep_data.get("request"),
                )

            for h_data in data.get("hypotheses", []):
                mem.hypotheses.append(Hypothesis(
                    id=h_data.get("id", ""),
                    description=h_data.get("description", ""),
                    vuln_class=h_data.get("vuln_class", ""),
                    endpoint=h_data.get("endpoint", ""),
                    confidence=h_data.get("confidence", 0.5),
                    test_plan=h_data.get("test_plan", ""),
                ))

            for f_data in data.get("findings", []):
                sev = f_data.get("severity", "info")
                if isinstance(sev, str):
                    sev = Severity(sev)
                mem.findings.append(Finding(
                    title=f_data.get("title", ""),
                    severity=sev,
                    vuln_class=f_data.get("vuln_class", ""),
                    endpoint=f_data.get("endpoint", ""),
                    method=f_data.get("method", "GET"),
                    evidence=f_data.get("evidence", []),
                    reproduction=f_data.get("reproduction", []),
                    impact=f_data.get("impact", ""),
                    confirmed=f_data.get("confirmed", True),
                    confidence=f_data.get("confidence", 0),
                ))

            mem.tested_urls = set(data.get("tested_urls", []))
            mem.failed_tests = data.get("failed_tests", [])
            return mem
        except (json.JSONDecodeError, KeyError, IOError):
            return None
