"""Research Brain — orchestrates the autonomous research loop.

Connects LLMReasoner, ExperimentPlanner, Validator with ResearchCase
to create a complete observation → hypothesis → experiment → validation cycle.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Awaitable

from ..interfaces import Decision, ActionType, Observation
from ..research_loop.case import (
    ResearchCase,
    CaseStatus,
    CaseObservation,
    CaseHypothesis,
    CaseExperiment,
    CaseFinding,
    NextBestAction,
    HypothesisStatus,
)
from .reasoner import LLMReasoner
from .planner import LLMExperimentPlanner
from .validator import LLMValidator

logger = logging.getLogger(__name__)


class ResearchBrain:
    """Orchestrates the autonomous research loop.

    The brain:
    1. Observes the target (via tools)
    2. Reasons about what to test next (via LLMReasoner)
    3. Plans experiments (via LLMExperimentPlanner)
    4. Validates findings (via LLMValidator)
    5. Tracks everything in a ResearchCase

    Usage:
        brain = ResearchBrain(
            target="https://example.com",
            llm_generate=llm_manager.generate,
        )
        await brain.initialize()
        decision = await brain.reason_next_action()
        result = await brain.run_experiment(decision)
        await brain.process_results(result)
    """

    def __init__(
        self,
        target: str,
        llm_generate: Callable[..., Awaitable[dict[str, Any]]],
        engagement_id: str = "",
        tools: list[str] | None = None,
        scope_status: str = "unknown",
    ):
        self.target = target
        self.engagement_id = engagement_id
        self.tools = tools or []
        self.scope_status = scope_status

        # Initialize components
        self.reasoner = LLMReasoner(llm_generate)
        self.planner = LLMExperimentPlanner(llm_generate)
        self.validator = LLMValidator(llm_generate)
        self._llm = llm_generate

        # Initialize case
        self.case = ResearchCase(
            engagement_id=engagement_id,
            target=target,
        )

        # State
        self._iteration = 0
        self._max_iterations = 100
        self._tested_actions: set[str] = set()
        self._tested_endpoints: set[str] = set()
        self._tested_vuln_classes: dict[str, int] = {}
        self._consecutive_failures = 0
        self._max_consecutive_failures = 10

        # Dedup limits
        self._max_same_vuln_class = 3
        self._max_same_endpoint = 5

    async def initialize(self) -> None:
        """Initialize the brain with initial observations."""
        self.case.add_observation(
            description=f"Starting research on {self.target}",
            source="brain",
            data={"target": self.target, "tools": self.tools},
        )

    async def reason_next_action(self) -> Decision:
        """Reason about the next best action."""
        self._iteration += 1
        self.case.increment_iteration()

        # Build context from case state
        context = self._build_context()

        # Get decision from reasoner
        decision = await self.reasoner.reason(context)

        # Check if action was already tested
        action_key = f"{decision.action.value}:{decision.target}"
        if action_key in self._tested_actions:
            # Ask reasoner to try something different
            context["tested_actions"] = list(self._tested_actions)
            decision = await self.reasoner.reason(context)

        # Set next action in case
        next_action = NextBestAction(
            action=decision.action.value,
            target=decision.target,
            reason=decision.reason,
            confidence=decision.confidence,
            priority=decision.priority,
            tool_hint=decision.tool_hint,
            params=decision.params,
        )
        self.case.set_next_action(next_action)

        return decision

    async def plan_experiment(self, hypothesis: CaseHypothesis) -> dict[str, Any]:
        """Plan an experiment for a hypothesis."""
        context = self._build_context()
        hypothesis_dict = hypothesis.to_dict()

        plan = await self.planner.plan(hypothesis_dict, context)
        return plan

    async def execute_experiment(
        self,
        plan: dict[str, Any],
        hypothesis_id: str,
        action: str,
        target: str,
        tool: str = "",
    ) -> CaseExperiment:
        """Execute an experiment and record it in the case."""
        start_time = time.time()

        # Add experiment to case
        experiment = self.case.add_experiment(
            hypothesis_id=hypothesis_id,
            action=action,
            target=target,
            tool=tool,
        )
        experiment.plan = plan

        # Record that we tested this action
        action_key = f"{action}:{target}"
        self._tested_actions.add(action_key)
        self._tested_endpoints.add(target)
        if action.startswith("test_"):
            vuln_class = action.replace("test_", "")
            self._tested_vuln_classes[vuln_class] = self._tested_vuln_classes.get(vuln_class, 0) + 1

        # Execute would happen here — for now we return the experiment
        # The actual execution is handled by the tool executor
        experiment.duration = time.time() - start_time
        return experiment

    async def validate_finding(self, evidence: dict[str, Any]) -> dict[str, Any]:
        """Validate evidence as a potential finding."""
        result = await self.validator.validate(evidence)

        if result.get("is_finding"):
            # Add finding to case
            finding = self.case.add_finding(
                hypothesis_id=evidence.get("hypothesis_id", ""),
                title=result.get("title", "Untitled Finding"),
                severity=result.get("severity", "info"),
                vuln_class=result.get("vuln_class", "unknown"),
                endpoint=result.get("endpoint", ""),
            )
            finding.description = result.get("description", "")
            finding.impact = result.get("impact", "")
            finding.remediation = result.get("remediation", "")
            finding.confidence = result.get("confidence", 0.5)
            finding.steps_to_reproduce = result.get("steps_to_reproduce", [])
            finding.confirmed = True

            self._consecutive_failures = 0
            logger.info(f"Finding confirmed: {finding.title} ({finding.severity})")
        else:
            self._consecutive_failures += 1
            logger.debug(f"Evidence rejected: {result.get('false_positive_reason', 'Unknown')}")

        return result

    def add_observation(self, description: str, source: str, data: dict | None = None) -> CaseObservation:
        """Add an observation to the case."""
        return self.case.add_observation(description, source, data)

    def add_hypothesis(self, description: str, vuln_class: str = "", endpoint: str = "") -> CaseHypothesis:
        """Add a hypothesis to the case."""
        return self.case.add_hypothesis(description, vuln_class, endpoint)

    def update_hypothesis_status(self, hypothesis_id: str, status: HypothesisStatus) -> None:
        """Update a hypothesis status."""
        for hyp in self.case.hypotheses:
            if hyp.id == hypothesis_id:
                hyp.status = status
                hyp.updated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                break

    def should_stop(self) -> tuple[bool, str]:
        """Check if the brain should stop."""
        if self._iteration >= self._max_iterations:
            return True, f"Max iterations ({self._max_iterations}) reached"

        if self._consecutive_failures >= self._max_consecutive_failures:
            return True, f"Too many consecutive failures ({self._consecutive_failures})"

        if self.case.status == CaseStatus.COMPLETED:
            return True, "Case completed"

        if self.case.status == CaseStatus.ABANDONED:
            return True, "Case abandoned"

        return False, ""

    def get_stats(self) -> dict[str, Any]:
        """Get current brain statistics."""
        return {
            "iteration": self._iteration,
            "observations": len(self.case.observations),
            "hypotheses": len(self.case.hypotheses),
            "active_hypotheses": len(self.case.get_active_hypotheses()),
            "experiments": len(self.case.experiments),
            "findings": len(self.case.findings),
            "confirmed_findings": len(self.case.get_confirmed_findings()),
            "tested_actions": len(self._tested_actions),
            "tested_endpoints": len(self._tested_endpoints),
            "consecutive_failures": self._consecutive_failures,
            "status": self.case.status.value,
            "vuln_class_coverage": dict(self._tested_vuln_classes),
        }

    def is_action_tested(self, action: str, target: str) -> bool:
        """Check if an action+target was already tested."""
        return f"{action}:{target}" in self._tested_actions

    def is_overtested(self, vuln_class: str, endpoint: str) -> bool:
        """Check if a vuln class or endpoint has been over-tested."""
        if self._tested_vuln_classes.get(vuln_class, 0) >= self._max_same_vuln_class:
            return True
        # Count tests per endpoint
        endpoint_count = sum(
            1 for a in self._tested_actions
            if a.endswith(f":{endpoint}")
        )
        return endpoint_count >= self._max_same_endpoint

    def get_untested_vuln_classes(self) -> list[str]:
        """Get vuln classes that haven't been tested yet."""
        all_classes = [
            "idor", "xss", "sqli", "ssrf", "csrf", "auth_bypass",
            "open_redirect", "info_disclosure", "file_upload", "ssti",
            "xxe", "race_condition", "mass_assignment", "business_logic",
        ]
        return [vc for vc in all_classes if vc not in self._tested_vuln_classes]

    def get_coverage_report(self) -> dict[str, Any]:
        """Get a coverage report."""
        return {
            "total_tested": len(self._tested_actions),
            "unique_endpoints": len(self._tested_endpoints),
            "vuln_classes_tested": len(self._tested_vuln_classes),
            "vuln_classes_untested": len(self.get_untested_vuln_classes()),
            "coverage_by_class": dict(self._tested_vuln_classes),
        }

    def get_case_summary(self) -> str:
        """Get a human-readable case summary."""
        stats = self.get_stats()
        lines = [
            f"RESEARCH CASE: {self.target}",
            f"Status: {stats['status']}",
            f"Iteration: {stats['iteration']}",
            f"Observations: {stats['observations']}",
            f"Hypotheses: {stats['hypotheses']} ({stats['active_hypotheses']} active)",
            f"Experiments: {stats['experiments']}",
            f"Findings: {stats['findings']} ({stats['confirmed_findings']} confirmed)",
            f"Tested actions: {stats['tested_actions']}",
        ]

        if self.case.get_confirmed_findings():
            lines.append("\nCONFIRMED FINDINGS:")
            for f in self.case.get_confirmed_findings():
                lines.append(f"  [{f.severity}] {f.title}")
                lines.append(f"    Endpoint: {f.endpoint}")
                lines.append(f"    Impact: {f.impact[:100]}")

        return "\n".join(lines)

    def save_case(self, path: str) -> None:
        """Save the case to disk."""
        self.case.save(path)

    def load_case(self, path: str) -> None:
        """Load a case from disk."""
        self.case = ResearchCase.load(path)
        self.target = self.case.target
        self.engagement_id = self.case.engagement_id
        self._iteration = self.case.iteration

    def _build_context(self) -> dict[str, Any]:
        """Build context dict from case state."""
        return {
            "target": self.target,
            "iteration": self._iteration,
            "assets": [],
            "observations": [o.to_dict() for o in self.case.observations[-20:]],
            "hypotheses": [h.to_dict() for h in self.case.hypotheses],
            "findings": [f.to_dict() for f in self.case.findings],
            "tested_actions": list(self._tested_actions),
            "available_tools": self.tools,
            "scope_status": self.scope_status,
        }
