"""Executive Controller — orchestrates the entire hunt.

Sits between the LLM and tools. The LLM only decides WHAT to test.
The controller decides HOW to test it.

Prevents loops, rejects duplicates, chooses engines, tracks coverage.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ExperimentStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class StagnationLevel(str, Enum):
    FRESH = "fresh"
    SLOWING = "slowing"
    STAGNANT = "stagnant"
    STUCK = "stuck"


@dataclass
class Hypothesis:
    id: str
    description: str
    vuln_class: str
    endpoint: str
    confidence: float
    test_plan: list[str]
    created_at: float = field(default_factory=time.time)
    tested: bool = False
    result: str = ""


@dataclass
class Experiment:
    id: str
    hypothesis_id: str
    executor: str
    status: ExperimentStatus
    target: str
    method: str = "GET"
    payload: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    started_at: float = 0.0
    completed_at: float = 0.0
    result: dict[str, Any] = field(default_factory=dict)
    finding: dict[str, Any] | None = None


@dataclass
class CoverageState:
    endpoints_discovered: int = 0
    endpoints_tested: int = 0
    vuln_classes_tested: set[str] = field(default_factory=set)
    vuln_classes_found: set[str] = field(default_factory=set)
    parameters_tested: int = 0
    roles_tested: int = 0
    total_experiments: int = 0
    findings_count: int = 0
    false_positives: int = 0

    @property
    def endpoint_coverage(self) -> float:
        if self.endpoints_discovered == 0:
            return 0.0
        return self.endpoints_tested / self.endpoints_discovered

    @property
    def vuln_class_coverage(self) -> float:
        all_classes = {
            "idor", "xss", "sqli", "ssrf", "cors", "auth_bypass",
            "jwt", "privesc", "race", "info_disclosure", "csrf",
            "file_upload", "ssti", "xxe", "open_redirect", "business_logic",
        }
        if not all_classes:
            return 0.0
        return len(self.vuln_classes_tested) / len(all_classes)


class ExecutiveController:
    """Orchestrates the entire hunt.

    LLM decides: "What hypothesis should be tested?"
    Controller decides: "Which tool should execute it?"
    """

    MAX_SAME_VULN_CLASS = 3
    MAX_SAME_ENDPOINT = 5
    STAGNATION_THRESHOLD = 3

    def __init__(self):
        self.hypotheses: dict[str, Hypothesis] = {}
        self.experiments: list[Experiment] = []
        self.coverage = CoverageState()
        self._hyp_counter = 0
        self._exp_counter = 0
        self._action_history: list[str] = []
        self._stagnation_count = 0
        self._last_findings_count = 0
        self._duplicate_actions: set[str] = set()

    def create_hypothesis(
        self,
        description: str,
        vuln_class: str,
        endpoint: str,
        confidence: float,
        test_plan: list[str],
    ) -> Hypothesis:
        self._hyp_counter += 1
        h = Hypothesis(
            id=f"H{self._hyp_counter:04d}",
            description=description,
            vuln_class=vuln_class,
            endpoint=endpoint,
            confidence=confidence,
            test_plan=test_plan,
        )
        self.hypotheses[h.id] = h
        return h

    def select_experiment(self) -> Experiment | None:
        """Select the next hypothesis to test based on priority."""
        pending = [h for h in self.hypotheses.values() if not h.tested]
        if not pending:
            return None

        pending.sort(key=lambda h: h.confidence, reverse=True)

        for hyp in pending:
            action_key = f"{hyp.vuln_class}:{hyp.endpoint}"
            if action_key in self._duplicate_actions:
                continue
            if self._is_endpoint_over_tested(hyp.endpoint):
                continue
            if self._is_vuln_class_over_tested(hyp.vuln_class):
                continue

            executor = self._select_executor(hyp.vuln_class)
            if executor:
                exp = self._create_experiment(hyp, executor)
                hyp.tested = True
                return exp

        return None

    def record_experiment_result(
        self,
        experiment_id: str,
        result: dict[str, Any],
        finding: dict[str, Any] | None = None,
    ) -> None:
        for exp in self.experiments:
            if exp.id == experiment_id:
                exp.status = ExperimentStatus.COMPLETED
                exp.completed_at = time.time()
                exp.result = result
                exp.finding = finding

                action_key = f"{exp.executor}:{exp.target}"
                self._duplicate_actions.add(action_key)
                self._action_history.append(action_key)

                self.coverage.total_experiments += 1

                hyp = self.hypotheses.get(exp.hypothesis_id)
                if hyp:
                    self.coverage.vuln_classes_tested.add(hyp.vuln_class)

                if finding:
                    self.coverage.findings_count += 1
                    self.coverage.vuln_classes_found.add(
                        finding.get("vuln_class", "unknown")
                    )

                if finding is None and result.get("status", "") != "vulnerable":
                    self._stagnation_count += 1
                else:
                    self._stagnation_count = 0

                break

    def get_stagnation_level(self) -> StagnationLevel:
        if self._stagnation_count == 0:
            return StagnationLevel.FRESH
        elif self._stagnation_count <= 1:
            return StagnationLevel.SLOWING
        elif self._stagnation_count <= self.STAGNATION_THRESHOLD:
            return StagnationLevel.STAGNANT
        else:
            return StagnationLevel.STUCK

    def should_change_strategy(self) -> bool:
        return self.get_stagnation_level() == StagnationLevel.STUCK

    def get_untested_vuln_classes(self) -> list[str]:
        all_classes = {
            "idor", "xss", "sqli", "ssrf", "cors", "auth_bypass",
            "jwt", "privesc", "race", "info_disclosure", "csrf",
            "file_upload", "ssti", "xxe", "open_redirect", "business_logic",
        }
        return list(all_classes - self.coverage.vuln_classes_tested)

    def get_coverage_report(self) -> dict[str, Any]:
        return {
            "endpoints_discovered": self.coverage.endpoints_discovered,
            "endpoints_tested": self.coverage.endpoints_tested,
            "endpoint_coverage": f"{self.coverage.endpoint_coverage:.1%}",
            "vuln_classes_tested": len(self.coverage.vuln_classes_tested),
            "vuln_class_coverage": f"{self.coverage.vuln_class_coverage:.1%}",
            "parameters_tested": self.coverage.parameters_tested,
            "roles_tested": self.coverage.roles_tested,
            "total_experiments": self.coverage.total_experiments,
            "findings_count": self.coverage.findings_count,
            "stagnation_level": self.get_stagnation_level().value,
            "untested_vuln_classes": self.get_untested_vuln_classes(),
        }

    def _select_executor(self, vuln_class: str) -> str | None:
        mapping = {
            "cors": "cors_detector",
            "jwt": "jwt_attacker",
            "idor": "idor_tester",
            "xss": "xss_detector",
            "auth_bypass": "auth_bypass_tester",
            "privesc": "privesc_tester",
            "sqli": "sqli_detector",
            "ssrf": "ssrf_tester",
            "race": "race_detector",
            "info_disclosure": "info_disclosure_detector",
            "csrf": "csrf_tester",
            "file_upload": "upload_tester",
            "ssti": "ssti_detector",
            "xxe": "xxe_detector",
            "open_redirect": "redirect_tester",
            "business_logic": "logic_tester",
        }
        return mapping.get(vuln_class)

    def _create_experiment(self, hyp: Hypothesis, executor: str) -> Experiment:
        self._exp_counter += 1
        exp = Experiment(
            id=f"E{self._exp_counter:04d}",
            hypothesis_id=hyp.id,
            executor=executor,
            status=ExperimentStatus.PENDING,
            target=hyp.endpoint,
        )
        self.experiments.append(exp)
        return exp

    def _is_endpoint_over_tested(self, endpoint: str) -> bool:
        count = sum(1 for e in self.experiments if e.target == endpoint)
        return count >= self.MAX_SAME_ENDPOINT

    def _is_vuln_class_over_tested(self, vuln_class: str) -> bool:
        count = sum(
            1 for h in self.hypotheses.values()
            if h.vuln_class == vuln_class and h.tested
        )
        return count >= self.MAX_SAME_VULN_CLASS
