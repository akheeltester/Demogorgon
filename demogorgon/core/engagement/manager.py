"""Engagement Manager — creates and manages engagements.

Handles:
- Creating engagements from program policies
- Creating engagements from user-provided URLs
- Loading/saving engagements
- Managing engagement lifecycle
"""

from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

from . import (
    Engagement, EngagementStatus, AuthorizationSource, AuthorizationStatus,
    ProgramPolicy, ScopeAsset,
)
from ..scope.parser import parse_program_policy


class EngagementManager:
    """Manages engagement lifecycle.

    Usage:
        manager = EngagementManager(workspace_root="./engagements")

        # From program policy text
        engagement = manager.create_from_policy(policy_text, user="researcher")

        # From user-provided URL
        engagement = manager.create_from_url("https://example.com", user="researcher")

        # Load existing
        engagement = manager.load("engagement_abc123")
    """

    def __init__(self, workspace_root: str = "./engagements"):
        self._workspace_root = Path(workspace_root)
        self._workspace_root.mkdir(parents=True, exist_ok=True)

    def create_from_policy(
        self,
        policy_text: str,
        user: str = "",
        name: str = "",
    ) -> Engagement:
        """Create an engagement from a bug bounty program policy.

        This is the preferred way to create an engagement.
        The policy is parsed and the scope is extracted automatically.
        """
        policy = parse_program_policy(policy_text)
        
        engagement = Engagement(
            name=name or policy.program_name,
            organization=policy.organization,
            authorization_source=AuthorizationSource.BUG_BOUNTY_PROGRAM,
            authorization_status=AuthorizationStatus.PENDING_CONFIRMATION,
            policy=policy,
            status=EngagementStatus.CREATED,
        )

        # Create workspace
        workspace = self._create_workspace(engagement)
        engagement.workspace_dir = str(workspace)

        # Save raw policy
        policy_file = workspace / "program" / "raw_policy.txt"
        policy_file.parent.mkdir(parents=True, exist_ok=True)
        policy_file.write_text(policy_text)

        # Save parsed policy
        parsed_file = workspace / "program" / "policy.json"
        parsed_file.write_text(json.dumps(policy.to_dict(), indent=2))

        # Save engagement
        engagement.save(str(workspace / "engagement.json"))

        return engagement

    def create_from_url(
        self,
        url: str,
        user: str = "",
        name: str = "",
    ) -> Engagement:
        """Create an engagement from a user-provided URL.

        This creates a 'user-declared' engagement with PENDING confirmation.
        The user MUST confirm they are authorized before active testing begins.
        """
        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"

        from urllib.parse import urlparse
        parsed = urlparse(url)
        hostname = parsed.hostname or url

        engagement = Engagement(
            name=name or f"User Target: {hostname}",
            organization=hostname,
            authorization_source=AuthorizationSource.USER_DECLARED,
            authorization_status=AuthorizationStatus.PENDING_CONFIRMATION,
            target_url=url,
            status=EngagementStatus.CREATED,
            policy=ProgramPolicy(
                program_name=f"User Target: {hostname}",
                in_scope=[ScopeAsset(
                    pattern=url,
                    asset_type="url",
                    description=f"User-provided target: {url}",
                    source="user_input",
                )],
            ),
        )

        # Create workspace
        workspace = self._create_workspace(engagement)
        engagement.workspace_dir = str(workspace)

        # Save engagement
        engagement.save(str(workspace / "engagement.json"))

        return engagement

    def load(self, engagement_id: str) -> Engagement | None:
        """Load an existing engagement by ID."""
        workspace = self._workspace_root / engagement_id
        engagement_file = workspace / "engagement.json"
        
        if engagement_file.exists():
            return Engagement.load(str(engagement_file))
        
        return None

    def list_engagements(self) -> list[dict[str, Any]]:
        """List all engagements."""
        engagements = []
        
        for workspace in self._workspace_root.iterdir():
            if not workspace.is_dir():
                continue
            
            engagement_file = workspace / "engagement.json"
            if engagement_file.exists():
                try:
                    engagement = Engagement.load(str(engagement_file))
                    engagements.append({
                        "id": engagement.id,
                        "name": engagement.name,
                        "status": engagement.status.value,
                        "created_at": engagement.created_at,
                    })
                except Exception:
                    continue
        
        return engagements

    def _create_workspace(self, engagement: Engagement) -> Path:
        """Create workspace directory structure for an engagement."""
        workspace = self._workspace_root / engagement.id
        workspace.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories
        (workspace / "program").mkdir(exist_ok=True)
        (workspace / "scope").mkdir(exist_ok=True)
        (workspace / "recon").mkdir(exist_ok=True)
        (workspace / "crawl").mkdir(exist_ok=True)
        (workspace / "model").mkdir(exist_ok=True)
        (workspace / "research").mkdir(exist_ok=True)
        (workspace / "evidence").mkdir(exist_ok=True)
        (workspace / "findings").mkdir(exist_ok=True)
        (workspace / "reports").mkdir(exist_ok=True)
        
        return workspace
