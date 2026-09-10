"""Execution Graph — replaces iteration loops with goal-driven execution.

Goal → Hypothesis → Experiment → Evidence → Finding → New Goal

The graph determines the next action. Not the iteration count.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class NodeType(str, Enum):
    GOAL = "goal"
    HYPOTHESIS = "hypothesis"
    EXPERIMENT = "experiment"
    EVIDENCE = "evidence"
    FINDING = "finding"
    STRATEGY = "strategy"


class NodeStatus(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    COMPLETED = "completed"
    FAILED = "failed"
    ABANDONED = "abandoned"


@dataclass
class GraphNode:
    id: str
    node_type: NodeType
    value: dict[str, Any]
    status: NodeStatus = NodeStatus.PENDING
    created_at: float = field(default_factory=time.time)
    completed_at: float = 0.0
    parent_id: str = ""
    children_ids: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.node_type.value,
            "status": self.status.value,
            "value": self.value,
            "parent_id": self.parent_id,
            "children_ids": self.children_ids,
            "metadata": self.metadata,
        }


class ExecutionGraph:
    """Goal-driven execution graph.

    Replaces iteration loops. The graph determines the next action.
    """

    def __init__(self):
        self.nodes: dict[str, GraphNode] = {}
        self._counter = 0
        self._current_goal: str | None = None

    def add_goal(self, description: str, priority: float = 0.5) -> GraphNode:
        self._counter += 1
        node = GraphNode(
            id=f"G{self._counter:04d}",
            node_type=NodeType.GOAL,
            value={"description": description, "priority": priority},
        )
        self.nodes[node.id] = node
        if self._current_goal is None:
            self._current_goal = node.id
        return node

    def add_hypothesis(
        self,
        goal_id: str,
        description: str,
        vuln_class: str,
        endpoint: str,
        confidence: float,
        test_plan: list[str],
    ) -> GraphNode:
        self._counter += 1
        node = GraphNode(
            id=f"H{self._counter:04d}",
            node_type=NodeType.HYPOTHESIS,
            value={
                "description": description,
                "vuln_class": vuln_class,
                "endpoint": endpoint,
                "confidence": confidence,
                "test_plan": test_plan,
            },
            parent_id=goal_id,
        )
        self.nodes[node.id] = node
        if goal_id in self.nodes:
            self.nodes[goal_id].children_ids.append(node.id)
        return node

    def add_experiment(
        self,
        hypothesis_id: str,
        executor: str,
        target: str,
        payload: dict[str, Any] | None = None,
    ) -> GraphNode:
        self._counter += 1
        node = GraphNode(
            id=f"E{self._counter:04d}",
            node_type=NodeType.EXPERIMENT,
            value={
                "executor": executor,
                "target": target,
                "payload": payload or {},
            },
            parent_id=hypothesis_id,
        )
        self.nodes[node.id] = node
        if hypothesis_id in self.nodes:
            self.nodes[hypothesis_id].children_ids.append(node.id)
        return node

    def add_evidence(
        self,
        experiment_id: str,
        result: dict[str, Any],
        is_finding: bool = False,
    ) -> GraphNode:
        self._counter += 1
        node = GraphNode(
            id=f"V{self._counter:04d}",
            node_type=NodeType.EVIDENCE,
            value={"result": result, "is_finding": is_finding},
            parent_id=experiment_id,
        )
        self.nodes[node.id] = node
        if experiment_id in self.nodes:
            self.nodes[experiment_id].children_ids.append(node.id)
        return node

    def add_finding(
        self,
        evidence_id: str,
        title: str,
        severity: str,
        vuln_class: str,
        endpoint: str,
        evidence: str,
    ) -> GraphNode:
        self._counter += 1
        node = GraphNode(
            id=f"F{self._counter:04d}",
            node_type=NodeType.FINDING,
            value={
                "title": title,
                "severity": severity,
                "vuln_class": vuln_class,
                "endpoint": endpoint,
                "evidence": evidence,
            },
            parent_id=evidence_id,
        )
        self.nodes[node.id] = node
        if evidence_id in self.nodes:
            self.nodes[evidence_id].children_ids.append(node.id)
        return node

    def get_next_action(self) -> dict[str, Any] | None:
        """Determine the next action based on graph state."""
        if self._current_goal and self._current_goal in self.nodes:
            goal = self.nodes[self._current_goal]
            if goal.status == NodeStatus.COMPLETED:
                self._current_goal = None
                return self.get_next_action()

            pending_hyps = [
                self.nodes[cid]
                for cid in goal.children_ids
                if cid in self.nodes
                and self.nodes[cid].node_type == NodeType.HYPOTHESIS
                and self.nodes[cid].status == NodeStatus.PENDING
            ]
            if pending_hyps:
                best = max(pending_hyps, key=lambda n: n.value.get("confidence", 0))
                return {
                    "action": "test_hypothesis",
                    "hypothesis_id": best.id,
                    "hypothesis": best.value,
                }

            active_exps = [
                self.nodes[cid]
                for cid in goal.children_ids
                if cid in self.nodes
                and self.nodes[cid].node_type == NodeType.HYPOTHESIS
                and self.nodes[cid].status == NodeStatus.ACTIVE
            ]
            if active_exps:
                return {"action": "wait_for_experiment", "hypothesis_id": active_exps[0].id}

        pending_goals = [
            n for n in self.nodes.values()
            if n.node_type == NodeType.GOAL and n.status == NodeStatus.PENDING
        ]
        if pending_goals:
            best = max(pending_goals, key=lambda n: n.value.get("priority", 0))
            self._current_goal = best.id
            best.status = NodeStatus.ACTIVE
            return {"action": "start_goal", "goal_id": best.id, "goal": best.value}

        return None

    def complete_node(self, node_id: str, status: NodeStatus = NodeStatus.COMPLETED) -> None:
        if node_id in self.nodes:
            self.nodes[node_id].status = status
            self.nodes[node_id].completed_at = time.time()

    def get_findings(self) -> list[dict[str, Any]]:
        return [
            n.value for n in self.nodes.values()
            if n.node_type == NodeType.FINDING
        ]

    def get_statistics(self) -> dict[str, Any]:
        type_counts = {}
        for node in self.nodes.values():
            t = node.node_type.value
            type_counts[t] = type_counts.get(t, 0) + 1
        return {
            "total_nodes": len(self.nodes),
            "by_type": type_counts,
            "findings": len(self.get_findings()),
            "current_goal": self._current_goal,
        }

    def to_dict(self) -> dict:
        return {
            "nodes": {k: v.to_dict() for k, v in self.nodes.items()},
            "statistics": self.get_statistics(),
        }
