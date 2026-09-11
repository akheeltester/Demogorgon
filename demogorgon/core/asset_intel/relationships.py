"""Asset Relationships — tracks relationships between assets.

Builds a graph of how assets relate to each other:
- Domain -> Subdomain
- Subdomain -> IP
- IP -> Port -> Service
- Service -> Application
- Application -> Endpoint
- Endpoint -> Parameter
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from enum import Enum


class RelationType(Enum):
    """Types of relationships between assets."""
    RESOLVES_TO = "resolves_to"
    HOSTS = "hosts"
    EXPOSES = "exposes"
    REFERENCES = "references"
    CALLS = "calls"
    AUTHENTICATES_TO = "authenticates_to"
    REDIRECTS_TO = "redirects_to"
    BELONGS_TO = "belongs_to"
    DISCOVERED_FROM = "discovered_from"
    VULNERABLE_TO = "vulnerable_to"
    RELATED_TO = "related_to"


@dataclass
class Relationship:
    """A relationship between two assets."""
    source_id: str
    target_id: str
    relation_type: RelationType
    properties: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.5
    discovered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relation_type": self.relation_type.value,
            "properties": self.properties,
            "confidence": self.confidence,
            "discovered_at": self.discovered_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Relationship:
        return cls(
            source_id=data["source_id"],
            target_id=data["target_id"],
            relation_type=RelationType(data["relation_type"]),
            properties=data.get("properties", {}),
            confidence=data.get("confidence", 0.5),
            discovered_at=data.get("discovered_at", ""),
        )


class RelationshipGraph:
    """Graph of asset relationships.

    Usage:
        graph = RelationshipGraph()

        # Add relationships
        graph.add_relationship(domain_id, subdomain_id, RelationType.HOSTS)
        graph.add_relationship(subdomain_id, ip_id, RelationType.RESOLVES_TO)

        # Query relationships
        neighbors = graph.get_neighbors(asset_id)
        paths = graph.find_paths(source_id, target_id)
    """

    def __init__(self):
        self._relationships: list[Relationship] = []
        self._adjacency: dict[str, list[Relationship]] = {}  # node_id -> relationships

    def add_relationship(
        self,
        source_id: str,
        target_id: str,
        relation_type: RelationType,
        properties: dict[str, Any] | None = None,
        confidence: float = 0.5,
    ) -> Relationship:
        """Add a relationship between two assets."""
        rel = Relationship(
            source_id=source_id,
            target_id=target_id,
            relation_type=relation_type,
            properties=properties or {},
            confidence=confidence,
        )

        self._relationships.append(rel)
        self._adjacency.setdefault(source_id, []).append(rel)
        self._adjacency.setdefault(target_id, []).append(rel)

        return rel

    def get_neighbors(self, asset_id: str) -> list[Relationship]:
        """Get all relationships involving an asset."""
        return self._adjacency.get(asset_id, [])

    def get_outgoing(self, asset_id: str) -> list[Relationship]:
        """Get relationships where asset is the source."""
        return [r for r in self._adjacency.get(asset_id, []) if r.source_id == asset_id]

    def get_incoming(self, asset_id: str) -> list[Relationship]:
        """Get relationships where asset is the target."""
        return [r for r in self._adjacency.get(asset_id, []) if r.target_id == asset_id]

    def find_paths(
        self,
        source_id: str,
        target_id: str,
        max_depth: int = 5,
    ) -> list[list[str]]:
        """Find paths between two assets."""
        paths = []
        self._dfs(source_id, target_id, set(), [source_id], paths, max_depth)
        return paths

    def _dfs(
        self,
        current: str,
        target: str,
        visited: set,
        path: list,
        paths: list,
        max_depth: int,
    ):
        """Depth-first search for paths."""
        if len(path) > max_depth:
            return
        if current == target:
            paths.append(list(path))
            return

        visited.add(current)
        for rel in self._adjacency.get(current, []):
            next_node = rel.target_id if rel.source_id == current else rel.source_id
            if next_node not in visited:
                path.append(next_node)
                self._dfs(next_node, target, visited, path, paths, max_depth)
                path.pop()
        visited.discard(current)

    def get_stats(self) -> dict[str, Any]:
        """Get graph statistics."""
        nodes = set()
        for rel in self._relationships:
            nodes.add(rel.source_id)
            nodes.add(rel.target_id)

        return {
            "nodes": len(nodes),
            "edges": len(self._relationships),
            "by_type": {
                rt.value: len([r for r in self._relationships if r.relation_type == rt])
                for rt in RelationType
            },
        }

    def save(self, filepath: str) -> None:
        """Save the graph to a JSON file."""
        data = {
            "relationships": [r.to_dict() for r in self._relationships],
            "stats": self.get_stats(),
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }

        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

    def load(self, filepath: str) -> bool:
        """Load the graph from a JSON file."""
        try:
            with open(filepath) as f:
                data = json.load(f)

            for rel_data in data.get("relationships", []):
                rel = Relationship.from_dict(rel_data)
                self._relationships.append(rel)
                self._adjacency.setdefault(rel.source_id, []).append(rel)
                self._adjacency.setdefault(rel.target_id, []).append(rel)

            return True
        except Exception:
            return False
