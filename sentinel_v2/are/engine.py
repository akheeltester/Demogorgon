"""Adaptive Research Engine — orchestrates graph-based hunting.

Replaces iterative endpoint testing with graph-based hunting.
Continuously updates a live model of the application.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from sentinel_v2.are.attack_graph import AttackGraph, Node, Edge, NodeType, EdgeType
from sentinel_v2.are.research_memory import ResearchMemory, Hypothesis, ResearchAction
from sentinel_v2.are.mutation_intelligence import MutationIntelligence
from sentinel_v2.are.trust_boundary import TrustBoundaryMapper
from sentinel_v2.are.exploit_confidence import ExploitConfidenceEngine, FindingScore
from sentinel_v2.are.chain_finder import ChainFinder, Chain
from sentinel_v2.are.knowledge_base import KnowledgeBase, HuntResult


@dataclass
class ResearchCycle:
    cycle_id: int
    hypothesis: str
    actions_taken: int
    findings: int
    new_endpoints: int
    new_vulns: int
    duration: float = 0.0
    confidence_delta: float = 0.0

    def to_dict(self) -> dict:
        return {
            "cycle_id": self.cycle_id,
            "hypothesis": self.hypothesis,
            "actions_taken": self.actions_taken,
            "findings": self.findings,
            "new_endpoints": self.new_endpoints,
            "new_vulns": self.new_vulns,
            "duration": self.duration,
            "confidence_delta": self.confidence_delta,
        }


@dataclass
class EngineState:
    total_cycles: int = 0
    total_findings: int = 0
    total_endpoints: int = 0
    total_vulns: int = 0
    current_confidence: float = 0.0
    exploration_rate: float = 0.7
    curiosity_score: float = 0.0
    strategy: str = "explore"
    stop_reason: str = ""
    cycles: list[ResearchCycle] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "total_cycles": self.total_cycles,
            "total_findings": self.total_findings,
            "total_endpoints": self.total_endpoints,
            "total_vulns": self.total_vulns,
            "current_confidence": self.current_confidence,
            "exploration_rate": self.exploration_rate,
            "curiosity_score": self.curiosity_score,
            "strategy": self.strategy,
            "stop_reason": self.stop_reason,
        }


class AdaptiveResearchEngine:
    """Orchestrates graph-based hunting.

    Each cycle:
      1. Self-evaluate: what do I know, what's uncertain
      2. Generate curiosity questions: what haven't I tested
      3. Select hypothesis: pick best action
      4. Execute action: mutate, probe, chain
      5. Update graph: add nodes, edges, findings
      6. Check stop condition: confidence threshold or budget
    """

    MAX_CYCLES = 100
    CONFIDENCE_THRESHOLD = 0.85
    MAX_ACTIONS_PER_CYCLE = 10

    def __init__(self, output_dir: str = "hunt_output"):
        self.graph = AttackGraph()
        self.memory = ResearchMemory(output_dir=output_dir)
        self.mutations = MutationIntelligence()
        self.trust = TrustBoundaryMapper()
        self.confidence_engine = ExploitConfidenceEngine()
        self.chains = ChainFinder()
        self.knowledge = KnowledgeBase()
        self.state = EngineState()
        self._cycle_counter = 0

    def start_hunt(self, target_url: str, max_cycles: int | None = None) -> EngineState:
        if max_cycles:
            self.MAX_CYCLES = max_cycles

        self.graph.add_node(Node(
            id="root",
            name=target_url,
            node_type=NodeType.ENDPOINT,
            properties={"role": "entry_point", "url": target_url},
        ))

        while self._should_continue():
            cycle = self._run_cycle()
            self.state.cycles.append(cycle)
            self._adjust_strategy()

        return self.state

    def _should_continue(self) -> bool:
        if self._cycle_counter >= self.MAX_CYCLES:
            self.state.stop_reason = "max_cycles_reached"
            return False
        if self.state.current_confidence >= self.CONFIDENCE_THRESHOLD:
            self.state.stop_reason = "confidence_threshold_reached"
            return False
        failed_count = len(self.memory.failed_approaches)
        if failed_count > 20:
            self.state.stop_reason = "too_many_failed_approaches"
            return False
        return True

    def _run_cycle(self) -> ResearchCycle:
        self._cycle_counter += 1
        start = time.time()

        hypothesis_text = self._select_hypothesis()
        actions = self._generate_actions(hypothesis_text)

        findings = 0
        new_endpoints = 0
        new_vulns = 0

        for action in actions[:self.MAX_ACTIONS_PER_CYCLE]:
            result = self._execute_action(action)
            if result.get("is_finding"):
                findings += 1
                new_vulns += 1
            if result.get("new_endpoints"):
                new_endpoints += len(result["new_endpoints"])

        confidence_before = self.state.current_confidence
        self._update_confidence()

        duration = time.time() - start
        cycle = ResearchCycle(
            cycle_id=self._cycle_counter,
            hypothesis=hypothesis_text,
            actions_taken=len(actions[:self.MAX_ACTIONS_PER_CYCLE]),
            findings=findings,
            new_endpoints=new_endpoints,
            new_vulns=new_vulns,
            duration=duration,
            confidence_delta=self.state.current_confidence - confidence_before,
        )
        self.state.total_cycles += 1
        self.state.total_findings += findings
        self.state.total_endpoints += new_endpoints
        self.state.total_vulns += new_vulns
        return cycle

    def _select_hypothesis(self) -> str:
        pending = self.memory.get_untested_hypotheses()
        if pending:
            best = max(pending, key=lambda h: h.confidence)
            return f"test_hypothesis:{best.id}:{best.description}"

        questions = self._generate_curiosity_questions()
        if not questions:
            return "no_questions_generated"

        return f"explore:{questions[0]}"

    def _generate_curiosity_questions(self) -> list[str]:
        questions = []
        untested = self.graph.get_untested_nodes()
        for node in untested[:10]:
            questions.append(f"untested:{node.id}:{node.name}")
        high_value = self.graph.get_high_value_nodes(min_score=0.7)
        for node in high_value[:5]:
            questions.append(f"high_value:{node.id}:{node.name}")
        return questions

    def _generate_actions(self, hypothesis: str) -> list[dict[str, Any]]:
        actions = []

        if hypothesis.startswith("test_hypothesis:"):
            parts = hypothesis.split(":", 2)
            hid = parts[1] if len(parts) > 1 else ""
            h = self.memory.hypotheses.get(hid)
            if h:
                actions.append({
                    "type": "test_hypothesis",
                    "hypothesis_id": hid,
                    "target": h.endpoint,
                    "param": h.parameter,
                    "description": h.description,
                })
                param_mutations = self.mutations.get_mutations(h.parameter, "")
                for value in param_mutations[:5]:
                    actions.append({
                        "type": "mutate_param",
                        "target": h.endpoint,
                        "param": h.parameter,
                        "value": value,
                        "description": f"Mutate {h.parameter} with {value[:30]}",
                    })

        elif hypothesis.startswith("explore:"):
            node_ref = hypothesis.split(":", 1)[1]
            parts = node_ref.split(":", 2)
            node_id = parts[0] if parts else ""
            node_name = parts[1] if len(parts) > 1 else ""
            actions.append({
                "type": "probe_endpoint",
                "target": node_name,
                "node_id": node_id,
                "description": f"Probe endpoint {node_name}",
            })
            common_params = ["id", "userId", "role", "token", "redirect", "file", "page"]
            for param in common_params:
                param_mutations = self.mutations.get_mutations(param, "")
                for value in param_mutations[:3]:
                    actions.append({
                        "type": "mutate_param",
                        "target": node_name,
                        "param": param,
                        "value": value,
                        "description": f"Mutate {param} on {node_name}",
                    })

        else:
            root = self.graph.get_node("root")
            if root:
                actions.append({
                    "type": "explore_root",
                    "target": root.name,
                    "description": "Explore from root",
                })

        return actions

    def _execute_action(self, action: dict[str, Any]) -> dict[str, Any]:
        action_type = action.get("type", "unknown")
        target = action.get("target", "")
        node_id = action.get("node_id", f"node_{self._cycle_counter}_{action_type}")

        self.memory.record_action(ResearchAction(
            iteration=self._cycle_counter,
            action_type=action_type,
            endpoint=target,
            method="GET",
            hypothesis_id=action.get("hypothesis_id", ""),
        ))

        result: dict[str, Any] = {"success": True, "is_finding": False, "new_endpoints": []}

        if action_type == "probe_endpoint":
            self.graph.add_node(Node(
                id=node_id,
                name=target,
                node_type=NodeType.ENDPOINT,
                properties={"tested": True, "cycle": self._cycle_counter},
            ))
            root = self.graph.get_node("root")
            if root:
                self.graph.add_edge(Edge(
                    source_id="root",
                    target_id=node_id,
                    edge_type=EdgeType.FLOWS_TO,
                    properties={"discovered_in_cycle": self._cycle_counter},
                ))

        elif action_type == "mutate_param":
            param = action.get("param", "")
            value = action.get("value", "")
            param_node_id = f"param:{target}:{param}:{hash(value) & 0xFFFFFF:06x}"
            self.graph.add_node(Node(
                id=param_node_id,
                name=f"{param}={value[:50]}",
                node_type=NodeType.ENTITY,
                properties={"endpoint": target, "param": param, "value": value, "cycle": self._cycle_counter},
            ))
            self.graph.add_edge(Edge(
                source_id=node_id,
                target_id=param_node_id,
                edge_type=EdgeType.CONTROLS,
            ))

        elif action_type == "test_hypothesis":
            self.graph.update_node_properties(node_id, {"tested": True, "cycle": self._cycle_counter})

        elif action_type == "explore_root":
            root = self.graph.get_node("root")
            if root:
                root.access_count += 1

        return result

    def _update_confidence(self) -> None:
        confirmed = [h for h in self.memory.hypotheses.values() if h.status.value == "confirmed"]
        total = len(self.memory.hypotheses)
        if total > 0:
            self.state.current_confidence = len(confirmed) / total
        else:
            self.state.current_confidence = 0.0

    def _adjust_strategy(self) -> None:
        if self.state.current_confidence >= 0.8:
            self.state.strategy = "exploit"
            self.state.exploration_rate = 0.3
        elif self.state.current_confidence >= 0.5:
            self.state.strategy = "validate"
            self.state.exploration_rate = 0.5
        elif self.state.total_findings == 0 and self.state.total_cycles > 5:
            self.state.strategy = "pivot"
            self.state.exploration_rate = 0.9
        else:
            self.state.strategy = "explore"
            self.state.exploration_rate = 0.7

        total_nodes = len(self.graph.nodes)
        untested = len(self.graph.get_untested_nodes())
        if total_nodes > 0:
            self.state.curiosity_score = untested / total_nodes
        else:
            self.state.curiosity_score = 0.0

    def record_finding(self, finding: dict[str, Any]) -> FindingScore:
        score = self.confidence_engine.score_finding(
            finding_id=finding.get("id", f"finding_{self.state.total_findings}"),
            title=finding.get("title", "Unknown Finding"),
            severity=finding.get("severity", "medium"),
            vuln_class=finding.get("vuln_class", "unknown"),
            endpoint=finding.get("endpoint", "unknown"),
            evidence=finding.get("evidence", []),
            response_status=finding.get("status", 0),
            response_changed=finding.get("response_changed", False),
            has_screenshot=finding.get("has_screenshot", False),
            has_request_response=finding.get("has_request_response", False),
        )
        self.memory.create_hypothesis(
            description=finding.get("title", "Finding"),
            attack_family=finding.get("vuln_class", "other"),
            endpoint=finding.get("endpoint", "unknown"),
            confidence=score.final_confidence,
        )
        self.chains.add_finding(finding)
        self.state.total_findings += 1
        return score

    def get_reportable_findings(self) -> list[dict[str, Any]]:
        confirmed = [h for h in self.memory.hypotheses.values() if h.status.value == "confirmed"]
        return [h.to_dict() for h in confirmed]

    def get_chains(self) -> list[Chain]:
        return self.chains.get_reportable_chains()

    def get_state(self) -> dict[str, Any]:
        state_dict = self.state.to_dict()
        state_dict["graph"] = self.graph.get_summary()
        state_dict["memory"] = self.memory.get_coverage()
        state_dict["chains"] = self.chains.get_chain_summary()
        state_dict["trust"] = self.trust.to_dict()
        return state_dict

    def save(self, path: str = "hunt_output/are_state.json") -> None:
        from pathlib import Path
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        data = self.get_state()
        data["cycles"] = [c.to_dict() for c in self.state.cycles]
        p.write_text(json.dumps(data, indent=2, default=str))
        self.graph.save(str(p.parent / "attack_graph.json"))
        self.memory.save()
