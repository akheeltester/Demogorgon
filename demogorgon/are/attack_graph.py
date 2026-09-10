"""Attack Graph — the living model of the application.

Every discovered object becomes a Node.
Every workflow becomes an Edge.
The researcher hunts the graph, not a list of endpoints.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class NodeType(str, Enum):
    ENTITY = "entity"
    ENDPOINT = "endpoint"
    WORKFLOW = "workflow"
    TRUST_BOUNDARY = "trust_boundary"
    EXTERNAL = "external"


class EdgeType(str, Enum):
    CREATES = "creates"
    READS = "reads"
    UPDATES = "updates"
    DELETES = "deletes"
    AUTHORIZES = "authorizes"
    DEPENDS_ON = "depends_on"
    FLOWS_TO = "flows_to"
    CONTROLS = "controls"
    OWNS = "owns"


@dataclass
class Node:
    id: str
    name: str
    node_type: NodeType
    properties: dict[str, Any] = field(default_factory=dict)
    discovered_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    access_count: int = 0
    vulnerability_count: int = 0
    confidence: float = 0.5

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "node_type": self.node_type.value,
            "properties": self.properties,
            "discovered_at": self.discovered_at,
            "last_seen": self.last_seen,
            "access_count": self.access_count,
            "vulnerability_count": self.vulnerability_count,
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Node:
        return cls(
            id=data["id"],
            name=data["name"],
            node_type=NodeType(data["node_type"]),
            properties=data.get("properties", {}),
            discovered_at=data.get("discovered_at", 0),
            last_seen=data.get("last_seen", 0),
            access_count=data.get("access_count", 0),
            vulnerability_count=data.get("vulnerability_count", 0),
            confidence=data.get("confidence", 0.5),
        )


@dataclass
class Edge:
    source_id: str
    target_id: str
    edge_type: EdgeType
    properties: dict[str, Any] = field(default_factory=dict)
    discovered_at: float = field(default_factory=time.time)
    confidence: float = 0.5

    def to_dict(self) -> dict:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type.value,
            "properties": self.properties,
            "discovered_at": self.discovered_at,
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Edge:
        return cls(
            source_id=data["source_id"],
            target_id=data["target_id"],
            edge_type=EdgeType(data["edge_type"]),
            properties=data.get("properties", {}),
            discovered_at=data.get("discovered_at", 0),
            confidence=data.get("confidence", 0.5),
        )


class AttackGraph:
    """Living model of the application's attack surface.

    Nodes represent entities (users, orders, payments, etc.) and endpoints.
    Edges represent relationships (creates, reads, authorizes, etc.).
    """

    def __init__(self):
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        self._adjacency: dict[str, list[str]] = {}
        self._reverse_adjacency: dict[str, list[str]] = {}

    def add_node(self, node: Node) -> None:
        self.nodes[node.id] = node
        if node.id not in self._adjacency:
            self._adjacency[node.id] = []
        if node.id not in self._reverse_adjacency:
            self._reverse_adjacency[node.id] = []

    def add_edge(self, edge: Edge) -> None:
        self.edges.append(edge)
        self._adjacency.setdefault(edge.source_id, []).append(edge.target_id)
        self._reverse_adjacency.setdefault(edge.target_id, []).append(edge.source_id)

    def get_node(self, node_id: str) -> Node | None:
        return self.nodes.get(node_id)

    def get_edges_from(self, node_id: str) -> list[Edge]:
        return [e for e in self.edges if e.source_id == node_id]

    def get_edges_to(self, node_id: str) -> list[Edge]:
        return [e for e in self.edges if e.target_id == node_id]

    def get_neighbors(self, node_id: str) -> list[str]:
        return self._adjacency.get(node_id, [])

    def get_parents(self, node_id: str) -> list[str]:
        return self._reverse_adjacency.get(node_id, [])

    def find_paths(self, start: str, end: str, max_depth: int = 6) -> list[list[str]]:
        paths = []
        self._dfs(start, end, [start], set(), paths, max_depth)
        return paths

    def _dfs(self, current: str, target: str, path: list[str], visited: set, paths: list, depth: int):
        if depth <= 0:
            return
        if current == target and len(path) > 1:
            paths.append(list(path))
            return
        visited.add(current)
        for neighbor in self.get_neighbors(current):
            if neighbor not in visited:
                path.append(neighbor)
                self._dfs(neighbor, target, path, visited, paths, depth - 1)
                path.pop()
        visited.discard(current)

    def get_untested_nodes(self) -> list[Node]:
        return [n for n in self.nodes.values() if n.access_count == 0]

    def get_high_value_nodes(self, min_score: float = 0.7) -> list[Node]:
        scored = []
        for node in self.nodes.values():
            score = self._score_node(node)
            if score >= min_score:
                scored.append((score, node))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [node for _, node in scored]

    def _score_node(self, node: Node) -> float:
        props = node.properties
        business_value = props.get("business_value", 50)
        exposure = props.get("exposure", 50)
        privilege = props.get("privilege", 50)
        mutation = props.get("mutation_potential", 50)
        return (business_value * 0.35 + exposure * 0.25 + privilege * 0.25 + mutation * 0.15) / 100

    def get_attack_chains(self, max_length: int = 5) -> list[list[Node]]:
        chains = []
        for node in self.nodes.values():
            if node.node_type == NodeType.TRUST_BOUNDARY:
                continue
            self._find_chains(node.id, [node.id], set(), chains, max_length)
        return [[self.nodes[nid] for nid in chain] for chain in chains]

    def _find_chains(self, current: str, path: list[str], visited: set, chains: list, depth: int):
        if depth <= 0:
            return
        visited.add(current)
        for neighbor in self.get_neighbors(current):
            if neighbor not in visited and neighbor in self.nodes:
                new_path = path + [neighbor]
                if len(new_path) >= 2:
                    chains.append(list(new_path))
                self._find_chains(neighbor, new_path, visited, chains, depth - 1)
        visited.discard(current)

    def get_summary(self) -> dict[str, Any]:
        type_counts = {}
        for node in self.nodes.values():
            t = node.node_type.value
            type_counts[t] = type_counts.get(t, 0) + 1

        edge_counts = {}
        for edge in self.edges:
            t = edge.edge_type.value
            edge_counts[t] = edge_counts.get(t, 0) + 1

        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "node_types": type_counts,
            "edge_types": edge_counts,
            "untested": len(self.get_untested_nodes()),
            "high_value": len(self.get_high_value_nodes()),
        }

    def save(self, path: str) -> None:
        data = {
            "nodes": {k: v.to_dict() for k, v in self.nodes.items()},
            "edges": [e.to_dict() for e in self.edges],
        }
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(data, indent=2, default=str))

    def load(self, path: str) -> bool:
        p = Path(path)
        if not p.exists():
            return False
        try:
            data = json.loads(p.read_text())
            for nid, ndata in data.get("nodes", {}).items():
                self.add_node(Node.from_dict(ndata))
            for edata in data.get("edges", []):
                self.add_edge(Edge.from_dict(edata))
            return True
        except Exception:
            return False
