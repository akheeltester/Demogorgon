"""Engagement models — the core data structures for bug bounty engagements.

An Engagement represents a complete authorized testing session:
- What program is being tested
- What assets are in scope
- What rules apply
- What status the engagement is in
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
import json
import uuid


class EngagementStatus(Enum):
    """Status of an engagement."""
    CREATED = "created"
    ACTIVE = "active"
    PAUSED = "paused"  # HITL or manual pause
    COMPLETED = "completed"
    ABANDONED = "abandoned"


class AuthorizationSource(Enum):
    """How authorization was established."""
    BUG_BOUNTY_PROGRAM = "bug_bounty_program"  # HackerOne, Bugcrowd, etc.
    USER_DECLARED = "user_declared"  # User said they have permission
    SCOPE_FILE = "scope_file"  # Loaded from a scope file


class AuthorizationStatus(Enum):
    """Status of authorization."""
    PENDING_CONFIRMATION = "pending_confirmation"
    CONFIRMED = "confirmed"
    EXPIRED = "expired"
    REVOKED = "revoked"


@dataclass
class ScopeAsset:
    """A single asset in scope."""
    pattern: str  # e.g., "*.example.com", "192.168.1.0/24", "https://app.example.com"
    asset_type: str = "domain"  # domain, subdomain, ip_range, url, mobile_app, api
    description: str = ""
    in_scope: bool = True
    source: str = ""  # where this came from (program policy, user input, etc.)

    def to_dict(self) -> dict:
        return {
            "pattern": self.pattern,
            "asset_type": self.asset_type,
            "description": self.description,
            "in_scope": self.in_scope,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, data: dict) -> ScopeAsset:
        return cls(**data)


@dataclass
class TestingRestriction:
    """A restriction on testing."""
    category: str  # e.g., "dos", "social_engineering", "automated_scanning"
    allowed: bool = False
    description: str = ""
    rate_limit: float | None = None  # requests per second, if applicable
    max_requests: int | None = None  # absolute limit, if applicable

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "allowed": self.allowed,
            "description": self.description,
            "rate_limit": self.rate_limit,
            "max_requests": self.max_requests,
        }


@dataclass
class ProgramPolicy:
    """Parsed bug bounty program policy."""
    program_name: str = ""
    organization: str = ""
    platform: str = ""  # hackerone, bugcrowd, intigriti, yeswehack, immunefi, custom
    
    # Scope
    in_scope: list[ScopeAsset] = field(default_factory=list)
    out_of_scope: list[ScopeAsset] = field(default_factory=list)
    
    # Restrictions
    restrictions: list[TestingRestriction] = field(default_factory=list)
    
    # Rules
    allowed_vulnerabilities: list[str] = field(default_factory=list)
    forbidden_vulnerabilities: list[str] = field(default_factory=list)
    
    # Authentication
    account_creation_allowed: bool = True
    authentication_requirements: str = ""
    
    # Disclosure
    disclosure_policy: str = ""
    safe_harbor: bool = False
    
    # Rewards
    reward_info: str = ""
    
    # Raw policy
    raw_policy: str = ""
    
    # Metadata
    parsed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "program_name": self.program_name,
            "organization": self.organization,
            "platform": self.platform,
            "in_scope": [a.to_dict() for a in self.in_scope],
            "out_of_scope": [a.to_dict() for a in self.out_of_scope],
            "restrictions": [r.to_dict() for r in self.restrictions],
            "allowed_vulnerabilities": self.allowed_vulnerabilities,
            "forbidden_vulnerabilities": self.forbidden_vulnerabilities,
            "account_creation_allowed": self.account_creation_allowed,
            "authentication_requirements": self.authentication_requirements,
            "disclosure_policy": self.disclosure_policy,
            "safe_harbor": self.safe_harbor,
            "reward_info": self.reward_info,
            "parsed_at": self.parsed_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> ProgramPolicy:
        policy = cls(
            program_name=data.get("program_name", ""),
            organization=data.get("organization", ""),
            platform=data.get("platform", ""),
            allowed_vulnerabilities=data.get("allowed_vulnerabilities", []),
            forbidden_vulnerabilities=data.get("forbidden_vulnerabilities", []),
            account_creation_allowed=data.get("account_creation_allowed", True),
            authentication_requirements=data.get("authentication_requirements", ""),
            disclosure_policy=data.get("disclosure_policy", ""),
            safe_harbor=data.get("safe_harbor", False),
            reward_info=data.get("reward_info", ""),
            parsed_at=data.get("parsed_at", ""),
        )
        for a in data.get("in_scope", []):
            policy.in_scope.append(ScopeAsset.from_dict(a))
        for a in data.get("out_of_scope", []):
            policy.out_of_scope.append(ScopeAsset.from_dict(a))
        for r in data.get("restrictions", []):
            policy.restrictions.append(TestingRestriction(**r))
        return policy


@dataclass
class Engagement:
    """A complete bug bounty engagement.

    This is the first-class object that everything operates inside.
    All modules receive an EngagementContext rather than independently
    deciding what targets to scan.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    name: str = ""
    organization: str = ""
    
    # Authorization
    authorization_source: AuthorizationSource = AuthorizationSource.USER_DECLARED
    authorization_status: AuthorizationStatus = AuthorizationStatus.PENDING_CONFIRMATION
    authorization_confirmed_by: str = ""  # user who confirmed
    
    # Policy
    policy: ProgramPolicy = field(default_factory=ProgramPolicy)
    
    # Status
    status: EngagementStatus = EngagementStatus.CREATED
    
    # Configuration
    target_url: str = ""
    proxy: str | None = None
    headless: bool = True
    rate_limit: float = 1.0
    
    # Timestamps
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    started_at: str | None = None
    completed_at: str | None = None
    
    # Workspace
    workspace_dir: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "organization": self.organization,
            "authorization_source": self.authorization_source.value,
            "authorization_status": self.authorization_status.value,
            "authorization_confirmed_by": self.authorization_confirmed_by,
            "policy": self.policy.to_dict(),
            "status": self.status.value,
            "target_url": self.target_url,
            "proxy": self.proxy,
            "headless": self.headless,
            "rate_limit": self.rate_limit,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "workspace_dir": self.workspace_dir,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Engagement:
        return cls(
            id=data.get("id", ""),
            name=data.get("name", ""),
            organization=data.get("organization", ""),
            authorization_source=AuthorizationSource(data.get("authorization_source", "user_declared")),
            authorization_status=AuthorizationStatus(data.get("authorization_status", "pending_confirmation")),
            authorization_confirmed_by=data.get("authorization_confirmed_by", ""),
            policy=ProgramPolicy.from_dict(data.get("policy", {})),
            status=EngagementStatus(data.get("status", "created")),
            target_url=data.get("target_url", ""),
            proxy=data.get("proxy"),
            headless=data.get("headless", True),
            rate_limit=data.get("rate_limit", 1.0),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
            started_at=data.get("started_at"),
            completed_at=data.get("completed_at"),
            workspace_dir=data.get("workspace_dir", ""),
        )

    def save(self, path: str):
        """Save engagement to JSON file."""
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, path: str) -> Engagement:
        """Load engagement from JSON file."""
        with open(path) as f:
            return cls.from_dict(json.load(f))

    def __repr__(self) -> str:
        return (
            f"Engagement(id={self.id}, name={self.name}, "
            f"status={self.status.value}, auth={self.authorization_status.value})"
        )
