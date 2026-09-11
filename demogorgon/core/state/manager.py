"""StateManager — persists and resumes engagement state.

Handles saving/loading:
- Research case state (observations, hypotheses, findings)
- Evidence collections
- Auth sessions
- Loop configuration and progress
- Checkpoints for crash recovery
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class EngagementState:
    """Complete state of an engagement for persistence."""
    engagement_id: str = ""
    target: str = ""
    started_at: float = field(default_factory=time.time)
    last_updated: float = field(default_factory=time.time)
    status: str = "active"  # active, paused, completed, abandoned
    iteration: int = 0
    strategy: str = "explore"
    findings_count: int = 0
    evidence_count: int = 0
    hypotheses_count: int = 0
    observations_count: int = 0
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "engagement_id": self.engagement_id,
            "target": self.target,
            "started_at": self.started_at,
            "last_updated": self.last_updated,
            "status": self.status,
            "iteration": self.iteration,
            "strategy": self.strategy,
            "findings_count": self.findings_count,
            "evidence_count": self.evidence_count,
            "hypotheses_count": self.hypotheses_count,
            "observations_count": self.observations_count,
            "data": self.data,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EngagementState:
        return cls(
            engagement_id=data.get("engagement_id", ""),
            target=data.get("target", ""),
            started_at=data.get("started_at", 0),
            last_updated=data.get("last_updated", 0),
            status=data.get("status", "active"),
            iteration=data.get("iteration", 0),
            strategy=data.get("strategy", "explore"),
            findings_count=data.get("findings_count", 0),
            evidence_count=data.get("evidence_count", 0),
            hypotheses_count=data.get("hypotheses_count", 0),
            observations_count=data.get("observations_count", 0),
            data=data.get("data", {}),
        )


class StateManager:
    """Manages persistence of engagement state.

    Directory structure:
        workspace_dir/
        ├── state.json          # Engagement state
        ├── case.json           # Research case data
        ├── evidence/           # Evidence files
        ├── auth_sessions.json  # Auth credentials
        └── checkpoints/        # Loop checkpoints
    """

    def __init__(self, workspace_dir: str):
        self._workspace_dir = workspace_dir
        self._state_path = os.path.join(workspace_dir, "state.json")
        self._case_path = os.path.join(workspace_dir, "case.json")
        self._auth_path = os.path.join(workspace_dir, "auth_sessions.json")
        self._checkpoints_dir = os.path.join(workspace_dir, "checkpoints")
        self._evidence_dir = os.path.join(workspace_dir, "evidence")

    def initialize(self, engagement_id: str, target: str) -> EngagementState:
        """Initialize a new engagement state."""
        os.makedirs(self._workspace_dir, exist_ok=True)
        os.makedirs(self._checkpoints_dir, exist_ok=True)
        os.makedirs(self._evidence_dir, exist_ok=True)

        state = EngagementState(
            engagement_id=engagement_id,
            target=target,
        )
        self.save_state(state)
        logger.info(f"Initialized engagement: {engagement_id}")
        return state

    def save_state(self, state: EngagementState) -> None:
        """Save engagement state to disk."""
        state.last_updated = time.time()
        os.makedirs(os.path.dirname(self._state_path) or ".", exist_ok=True)
        with open(self._state_path, "w") as f:
            json.dump(state.to_dict(), f, indent=2)

    def load_state(self) -> EngagementState | None:
        """Load engagement state from disk."""
        if not os.path.exists(self._state_path):
            return None

        try:
            with open(self._state_path) as f:
                data = json.load(f)
            return EngagementState.from_dict(data)
        except Exception as e:
            logger.error(f"Failed to load state: {e}")
            return None

    def save_case(self, case_data: dict[str, Any]) -> None:
        """Save research case data."""
        os.makedirs(os.path.dirname(self._case_path) or ".", exist_ok=True)
        with open(self._case_path, "w") as f:
            json.dump(case_data, f, indent=2)

    def load_case(self) -> dict[str, Any] | None:
        """Load research case data."""
        if not os.path.exists(self._case_path):
            return None

        try:
            with open(self._case_path) as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load case: {e}")
            return None

    def save_checkpoint(self, iteration: int, data: dict[str, Any]) -> str:
        """Save a checkpoint. Returns the checkpoint path."""
        path = os.path.join(self._checkpoints_dir, f"checkpoint_{iteration:06d}.json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        logger.debug(f"Checkpoint saved: {path}")
        return path

    def load_checkpoint(self, iteration: int) -> dict[str, Any] | None:
        """Load a specific checkpoint."""
        path = os.path.join(self._checkpoints_dir, f"checkpoint_{iteration:06d}.json")
        if not os.path.exists(path):
            return None

        try:
            with open(path) as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load checkpoint: {e}")
            return None

    def get_latest_checkpoint(self) -> tuple[int, dict[str, Any]] | None:
        """Get the most recent checkpoint."""
        if not os.path.exists(self._checkpoints_dir):
            return None

        files = sorted(os.listdir(self._checkpoints_dir))
        if not files:
            return None

        latest = files[-1]
        try:
            name = latest.replace(".json", "")
            iteration = int(name.split("_")[1])
            path = os.path.join(self._checkpoints_dir, latest)
            with open(path) as f:
                return iteration, json.load(f)
        except Exception as e:
            logger.error(f"Failed to load latest checkpoint: {e}")
            return None

    def list_checkpoints(self) -> list[int]:
        """List all checkpoint iteration numbers."""
        if not os.path.exists(self._checkpoints_dir):
            return []

        iterations = []
        for f in sorted(os.listdir(self._checkpoints_dir)):
            try:
                name = f.replace(".json", "")
                iterations.append(int(name.split("_")[1]))
            except (IndexError, ValueError):
                continue
        return iterations

    def cleanup_checkpoints(self, keep_last: int = 5) -> int:
        """Remove old checkpoints, keeping the most recent N. Returns count removed."""
        iterations = self.list_checkpoints()
        if len(iterations) <= keep_last:
            return 0

        to_remove = iterations[:-keep_last]
        for it in to_remove:
            path = os.path.join(self._checkpoints_dir, f"checkpoint_{it:06d}.json")
            try:
                os.remove(path)
            except OSError:
                pass

        return len(to_remove)

    def get_summary(self) -> dict[str, Any]:
        """Get a summary of persisted state."""
        state = self.load_state()
        checkpoints = self.list_checkpoints()

        return {
            "workspace_dir": self._workspace_dir,
            "has_state": state is not None,
            "has_case": os.path.exists(self._case_path),
            "has_auth": os.path.exists(self._auth_path),
            "checkpoint_count": len(checkpoints),
            "latest_checkpoint": checkpoints[-1] if checkpoints else None,
            "state": state.to_dict() if state else None,
        }
