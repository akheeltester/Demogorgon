"""Application Understanding Engine

Before testing anything, the researcher must understand the target.
This module builds a complete mental model of the application:

1. Product Understanding — what is this app?
2. Business Object Discovery — what entities exist?
3. Workflow Reconstruction — how do users interact?
4. Trust Boundary Mapping — where are the boundaries?
5. Attack Surface Classification — what kind of endpoints exist?
6. Attack Opportunity Generation — what's worth testing?

Every observation updates this graph.
Never rediscover known information.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# Canonical models — single source of truth
from demogorgon.core.models import (
    ProductType,
    ObjectState,
    BusinessObject,
    ObjectRelationship,
    WorkflowStep,
    TrustBoundary,
    AttackSurface,
    AttackOpportunity,
)


@dataclass
class UserRole:
    """A user role in the application."""
    name: str
    level: int  # 0=guest, 1=user, 2=premium, 3=seller, 4=admin, 5=superadmin
    permissions: list[str] = field(default_factory=list)
    description: str = ""
    can_do: list[str] = field(default_factory=list)
    cannot_do: list[str] = field(default_factory=list)


class ApplicationModel:
    """Complete mental model of the target application.

    This is what the researcher builds BEFORE testing.
    It contains everything the researcher knows about the app.
    Every observation updates this graph.
    Never rediscover known information.
    """

    def __init__(self, target_url: str):
        self.target_url = target_url
        self.product_type = ProductType.UNKNOWN
        self.product_description = ""
        self.user_roles: list[UserRole] = []
        self.business_objects: list[BusinessObject] = []
        self.relationships: list[ObjectRelationship] = []
        self.workflows: dict[str, list[WorkflowStep]] = {}  # workflow_name -> steps
        self.trust_boundaries: list[TrustBoundary] = []
        self.attack_surface: list[AttackSurface] = []
        self.attack_opportunities: list[AttackOpportunity] = []
        self.ownership_model: str = ""
        self.monetization_model: str = ""
        self.tech_stack: list[str] = []
        self.api_style: str = ""  # REST, GraphQL, gRPC, etc.
        self.observations: list[dict[str, Any]] = []
        self.confidence: float = 0.0  # how confident are we in this model
        self.last_updated: float = time.time()

        # Tracking indices
        self._object_types: dict[str, list[BusinessObject]] = {}  # type -> objects
        self._objects_by_owner: dict[str, list[BusinessObject]] = {}  # owner -> objects
        self._objects_by_endpoint: dict[str, list[BusinessObject]] = {}  # endpoint -> objects
        self._observation_categories: dict[str, list[dict]] = {}  # category -> observations

    def add_business_object(self, obj: BusinessObject):
        """Add or update a business object."""
        # Check if already exists
        for existing in self.business_objects:
            if existing.object_type == obj.object_type and existing.identifier == obj.identifier:
                # Update existing
                if obj.owner:
                    existing.owner = obj.owner
                if obj.organization:
                    existing.organization = obj.organization
                if obj.properties and isinstance(obj.properties, dict) and isinstance(existing.properties, dict):
                    existing.properties.update(obj.properties)
                if obj.state != ObjectState.ACTIVE:
                    existing.state = obj.state
                if obj.id_type != "unknown":
                    existing.id_type = obj.id_type
                return

        self.business_objects.append(obj)

        # Update indices
        self._object_types.setdefault(obj.object_type, []).append(obj)
        if obj.owner:
            self._objects_by_owner.setdefault(obj.owner, []).append(obj)
        if obj.endpoint:
            self._objects_by_endpoint.setdefault(obj.endpoint, []).append(obj)

    def add_relationship(self, relationship: ObjectRelationship):
        """Add a relationship between objects."""
        # Check if already exists
        for existing in self.relationships:
            if (existing.from_type == relationship.from_type and
                existing.to_type == relationship.to_type and
                existing.relationship == relationship.relationship):
                return
        self.relationships.append(relationship)

    def get_idor_candidates(self) -> list[tuple[BusinessObject, BusinessObject]]:
        """Find object pairs that could be IDOR targets."""
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

    def get_objects_by_type(self, object_type: str) -> list[BusinessObject]:
        """Get all objects of a specific type."""
        return self._object_types.get(object_type, [])

    def get_objects_by_owner(self, owner: str) -> list[BusinessObject]:
        """Get all objects owned by a specific owner."""
        return self._objects_by_owner.get(owner, [])

    def get_relationships(self, from_type: str = "", to_type: str = "",
                          relationship: str = "") -> list[ObjectRelationship]:
        """Get relationships matching criteria."""
        results = self.relationships
        if from_type:
            results = [r for r in results if r.from_type == from_type]
        if to_type:
            results = [r for r in results if r.to_type == to_type]
        if relationship:
            results = [r for r in results if r.relationship == relationship]
        return results

    def get_objects_in_state(self, state: ObjectState) -> list[BusinessObject]:
        """Get all objects in a specific lifecycle state."""
        return [o for o in self.business_objects if o.state == state]

    def get_state_transitions(self) -> list[tuple[ObjectState, ObjectState]]:
        """Get all observed state transitions."""
        transitions = set()
        for obj in self.business_objects:
            if len(obj.lifecycle) >= 2:
                for i in range(len(obj.lifecycle) - 1):
                    try:
                        from_state = ObjectState(obj.lifecycle[i])
                        to_state = ObjectState(obj.lifecycle[i + 1])
                        transitions.add((from_state, to_state))
                    except ValueError:
                        pass
        return list(transitions)

    def add_workflow(self, name: str, steps: list[WorkflowStep]):
        self.workflows[name] = steps

    def add_trust_boundary(self, boundary: TrustBoundary):
        self.trust_boundaries.append(boundary)

    def add_attack_surface(self, surface: AttackSurface):
        self.attack_surface.append(surface)

    def add_attack_opportunity(self, opportunity: AttackOpportunity):
        self.attack_opportunities.append(opportunity)

    def add_observation(self, observation: dict[str, Any]):
        self.observations.append(observation)
        self.last_updated = time.time()

        # Update observation index
        category = observation.get("category", "general")
        self._observation_categories.setdefault(category, []).append(observation)

    def get_untested_opportunities(self, tested: set[str]) -> list[AttackOpportunity]:
        """Get attack opportunities that haven't been tested yet."""
        return [o for o in self.attack_opportunities
                if f"{o.method} {o.endpoint}" not in tested]

    def get_observations_by_category(self, category: str) -> list[dict]:
        """Get observations in a specific category."""
        return self._observation_categories.get(category, [])

    def get_high_risk_endpoints(self) -> list[AttackSurface]:
        """Get endpoints with high or critical risk levels."""
        return [s for s in self.attack_surface if s.risk_level in ("high", "critical")]

    def get_state_changing_endpoints(self) -> list[AttackSurface]:
        """Get endpoints that change application state."""
        return [s for s in self.attack_surface if s.state_changing]

    def get_untested_workflows(self, tested_endpoints: set[str]) -> list[str]:
        """Get workflows that haven't been fully tested."""
        untested = []
        for name, steps in self.workflows.items():
            for step in steps:
                if step.endpoint not in tested_endpoints:
                    untested.append(name)
                    break
        return untested

    def get_untested_trust_boundaries(self, tested_endpoints: set[str]) -> list[TrustBoundary]:
        """Get trust boundaries that haven't been tested."""
        return [b for b in self.trust_boundaries if b.endpoint not in tested_endpoints]

    def get_summary(self) -> str:
        """Get a human-readable summary of the application model."""
        lines = [f"APPLICATION MODEL: {self.target_url}"]
        lines.append(f"Product: {self.product_type.value} - {self.product_description}")
        lines.append(f"Tech: {', '.join(self.tech_stack)}")
        lines.append(f"API: {self.api_style}")
        lines.append(f"Ownership: {self.ownership_model}")
        lines.append(f"Monetization: {self.monetization_model}")
        lines.append(f"Confidence: {self.confidence:.0%}")

        if self.user_roles:
            lines.append(f"\nUSER ROLES ({len(self.user_roles)}):")
            for role in self.user_roles:
                lines.append(f"  {role.name} (level {role.level}): {role.description}")
                if role.can_do:
                    lines.append(f"    Can: {', '.join(role.can_do[:5])}")
                if role.cannot_do:
                    lines.append(f"    Cannot: {', '.join(role.cannot_do[:5])}")

        if self.business_objects:
            lines.append(f"\nBUSINESS OBJECTS ({len(self.business_objects)}):")
            by_type: dict[str, list[BusinessObject]] = {}
            for obj in self.business_objects:
                by_type.setdefault(obj.object_type, []).append(obj)
            for obj_type, objects in by_type.items():
                owners = set(o.owner for o in objects if o.owner)
                states = set(o.state.value for o in objects)
                lines.append(f"  {obj_type}: {len(objects)} instances, owners: {owners}, states: {states}")

        if self.relationships:
            lines.append(f"\nRELATIONSHIPS ({len(self.relationships)}):")
            for r in self.relationships[:10]:
                lines.append(f"  {r.from_type} --[{r.relationship}]--> {r.to_type}")

        idor = self.get_idor_candidates()
        if idor:
            lines.append(f"\nIDOR CANDIDATES ({len(idor)}):")
            for o1, o2 in idor[:5]:
                lines.append(f"  {o1.object_type}#{o1.identifier} (owner={o1.owner}) vs {o2.object_type}#{o2.identifier} (owner={o2.owner})")

        if self.workflows:
            lines.append(f"\nWORKFLOWS ({len(self.workflows)}):")
            for name, steps in self.workflows.items():
                lines.append(f"  {name}: {' -> '.join(s.name for s in steps)}")

        if self.trust_boundaries:
            lines.append(f"\nTRUST BOUNDARIES ({len(self.trust_boundaries)}):")
            for b in self.trust_boundaries:
                lines.append(f"  {b.name}: {b.from_level} -> {b.to_level} ({b.boundary_type})")
                if b.bypass_techniques:
                    lines.append(f"    Bypass: {', '.join(b.bypass_techniques[:3])}")

        if self.attack_surface:
            lines.append(f"\nATTACK SURFACE ({len(self.attack_surface)}):")
            by_cat: dict[str, list[AttackSurface]] = {}
            for s in self.attack_surface:
                by_cat.setdefault(s.category, []).append(s)
            for cat, surfaces in by_cat.items():
                high_risk = sum(1 for s in surfaces if s.risk_level in ("high", "critical"))
                lines.append(f"  {cat}: {len(surfaces)} endpoints ({high_risk} high-risk)")

        if self.attack_opportunities:
            lines.append(f"\nATTACK OPPORTUNITIES ({len(self.attack_opportunities)}):")
            for o in self.attack_opportunities[:10]:
                lines.append(f"  [{o.confidence:.0%}] {o.description}")
                lines.append(f"    {o.reasoning}")

        if self.observations:
            lines.append(f"\nOBSERVATIONS ({len(self.observations)}):")
            for obs in self.observations[-10:]:
                lines.append(f"  [{obs.get('category', 'general')}] {obs.get('description', '')[:100]}")

        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "target_url": self.target_url,
            "product_type": self.product_type.value,
            "product_description": self.product_description,
            "tech_stack": self.tech_stack,
            "api_style": self.api_style,
            "ownership_model": self.ownership_model,
            "monetization_model": self.monetization_model,
            "confidence": self.confidence,
            "user_roles": [{"name": r.name, "level": r.level, "permissions": r.permissions, "description": r.description, "can_do": r.can_do, "cannot_do": r.cannot_do} for r in self.user_roles],
            "business_objects": [o.to_dict() for o in self.business_objects],
            "relationships": [r.to_dict() for r in self.relationships],
            "workflows": {name: [{"name": s.name, "endpoint": s.endpoint, "method": s.method, "state_transition": s.state_transition, "trust_boundary_crossed": s.trust_boundary_crossed} for s in steps] for name, steps in self.workflows.items()},
            "trust_boundaries": [b.to_dict() for b in self.trust_boundaries],
            "attack_surface": [{"endpoint": s.endpoint, "method": s.method, "category": s.category, "risk_level": s.risk_level, "auth_required": s.auth_required, "state_changing": s.state_changing} for s in self.attack_surface],
            "attack_opportunities": [{"description": o.description, "vuln_class": o.vuln_class, "endpoint": o.endpoint, "confidence": o.confidence, "reasoning": o.reasoning, "expected_impact": o.expected_impact} for o in self.attack_opportunities],
            "observations": self.observations,
        }

    def save(self, path: str):
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
