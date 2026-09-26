"""Program Policy AST — structured, trustworthy representation of a program policy.

The parser produces these types instead of naive domain extraction:

- Assets are only created from explicit scope sections (never from prose).
- Every asset carries provenance: source_section, source_text, confidence.
- Inclusion states distinguish IN_SCOPE / OUT_OF_SCOPE / CONDITIONALLY_IN_SCOPE /
  FORBIDDEN_ACTION / EXCLUDED_VULNERABILITY / KNOWN_ISSUE / TESTING_REQUIREMENT.
- Low-confidence assets never become automatically authorized targets.

Import policy: data models only — no parsing logic lives here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class InclusionState(Enum):
    """How a policy element relates to authorization."""

    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"
    CONDITIONALLY_IN_SCOPE = "conditionally_in_scope"
    FORBIDDEN_ACTION = "forbidden_action"
    EXCLUDED_VULNERABILITY = "excluded_vulnerability"
    KNOWN_ISSUE = "known_issue"
    TESTING_REQUIREMENT = "testing_requirement"


#: Confidence at/above which an asset is treated as explicitly authorized.
EXPLICIT_CONFIDENCE = 0.85


@dataclass
class ScopeRule:
    """A single positively-scoped target rule."""

    canonical_pattern: str
    asset_type: str = "domain"
    source_section: str = ""
    source_text: str = ""
    inclusion_state: InclusionState = InclusionState.IN_SCOPE
    confidence: float = 1.0
    description: str = ""

    @property
    def is_explicit(self) -> bool:
        """Explicit rules are authorized without further review."""
        return (
            self.inclusion_state == InclusionState.IN_SCOPE
            and self.confidence >= EXPLICIT_CONFIDENCE
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "canonical_pattern": self.canonical_pattern,
            "asset_type": self.asset_type,
            "source_section": self.source_section,
            "source_text": self.source_text,
            "inclusion_state": self.inclusion_state.value,
            "confidence": self.confidence,
            "description": self.description,
        }


@dataclass
class ExclusionRule:
    """A rule that removes something from scope."""

    canonical_pattern: str
    source_section: str = ""
    source_text: str = ""
    inclusion_state: InclusionState = InclusionState.OUT_OF_SCOPE
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "canonical_pattern": self.canonical_pattern,
            "source_section": self.source_section,
            "source_text": self.source_text,
            "inclusion_state": self.inclusion_state.value,
            "reason": self.reason,
        }


@dataclass
class RestrictionRule:
    """A testing restriction (category-ordered, with provenance)."""

    category: str
    allowed: bool = False
    description: str = ""
    rate_limit: float | None = None
    max_requests: int | None = None
    source_section: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "allowed": self.allowed,
            "description": self.description,
            "rate_limit": self.rate_limit,
            "max_requests": self.max_requests,
            "source_section": self.source_section,
        }


@dataclass
class AllowedVulnerability:
    """A vulnerability class the program explicitly accepts."""

    name: str
    source_section: str = ""
    source_text: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "source_section": self.source_section,
                "source_text": self.source_text}


@dataclass
class ForbiddenVulnerability:
    """A vulnerability class the program explicitly excludes."""

    name: str
    source_section: str = ""
    source_text: str = ""
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "source_section": self.source_section,
                "source_text": self.source_text, "reason": self.reason}


@dataclass
class TestingConstraint:
    """A general testing constraint (rate limits, tooling, timing, …)."""

    category: str
    description: str = ""
    allowed: bool = False
    source_section: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "description": self.description,
            "allowed": self.allowed,
            "source_section": self.source_section,
        }


@dataclass
class EvidenceRequirement:
    """What evidence a report must include."""

    description: str
    required: bool = True
    source_section: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "description": self.description,
            "required": self.required,
            "source_section": self.source_section,
        }


@dataclass
class RequiredHeader:
    """A header the program requires on test traffic (e.g. X-Testing)."""

    name: str
    value: str = ""
    purpose: str = ""
    source_section: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "value": self.value,
            "purpose": self.purpose,
            "source_section": self.source_section,
        }


@dataclass
class AccountConstraint:
    """Account / credential rules."""

    creation_allowed: bool | None = None  # None = not specified
    credentials_allowed: bool | None = None
    description: str = ""
    source_section: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "creation_allowed": self.creation_allowed,
            "credentials_allowed": self.credentials_allowed,
            "description": self.description,
            "source_section": self.source_section,
        }


@dataclass
class KnownIssue:
    """A known/accepted issue — candidate findings matching these are flagged."""

    description: str
    reference: str = ""
    source_section: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "description": self.description,
            "reference": self.reference,
            "source_section": self.source_section,
        }


@dataclass
class SafeHarbor:
    """Safe-harbor provision."""

    present: bool = False
    text: str = ""
    source_section: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"present": self.present, "text": self.text,
                "source_section": self.source_section}


@dataclass
class PolicyMetadata:
    """Parser provenance: sections found, warnings, low-confidence assets."""

    platform: str = ""
    detected_sections: list[str] = field(default_factory=list)
    parse_warnings: list[str] = field(default_factory=list)
    low_confidence_assets: list[str] = field(default_factory=list)
    parser_version: str = "2"

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "detected_sections": list(self.detected_sections),
            "parse_warnings": list(self.parse_warnings),
            "low_confidence_assets": list(self.low_confidence_assets),
            "parser_version": self.parser_version,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PolicyMetadata:
        return cls(
            platform=data.get("platform", ""),
            detected_sections=list(data.get("detected_sections", [])),
            parse_warnings=list(data.get("parse_warnings", [])),
            low_confidence_assets=list(data.get("low_confidence_assets", [])),
            parser_version=data.get("parser_version", "2"),
        )
