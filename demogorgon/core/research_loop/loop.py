"""Research Loop — main orchestrator for autonomous research.

Connects the ResearchBrain, PlanExecutor, EvidenceCollector, and
ResearchCase into a complete observation → hypothesis → experiment →
validation cycle.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Awaitable

from ..interfaces import Decision, ActionType
from ..research_loop.case import (
    ResearchCase,
    CaseStatus,
    HypothesisStatus,
    NextBestAction,
)
from .executor import PlanExecutor
from .evidence import EvidenceCollector

logger = logging.getLogger(__name__)


class LoopConfig:
    """Configuration for the research loop."""

    def __init__(
        self,
        max_iterations: int = 100,
        max_consecutive_failures: int = 10,
        stagnation_threshold: int = 5,
        rate_limit_delay: float = 1.0,
        checkpoint_interval: int = 10,
        self_eval_interval: int = 20,
    ):
        self.max_iterations = max_iterations
        self.max_consecutive_failures = max_consecutive_failures
        self.stagnation_threshold = stagnation_threshold
        self.rate_limit_delay = rate_limit_delay
        self.checkpoint_interval = checkpoint_interval
        self.self_eval_interval = self_eval_interval


class ResearchLoop:
    """Main orchestrator for autonomous research.

    Connects brain, executor, evidence collector, and case into a
    complete research cycle.

    Usage:
        loop = ResearchLoop(
            target="https://example.com",
            llm_generate=llm_manager.generate,
            http_client=http_client,
            tools=["httpx", "nuclei"],
        )
        await loop.initialize()
        await loop.run()
    """

    def __init__(
        self,
        target: str,
        llm_generate: Callable[..., Awaitable[dict[str, Any]]],
        http_client: Any = None,
        tool_executor: Any = None,
        browser: Any = None,
        tools: list[str] | None = None,
        auth_headers: dict[str, str] | None = None,
        config: LoopConfig | None = None,
        workspace_dir: str = "",
        engagement_id: str = "",
    ):
        self.target = target
        self.config = config or LoopConfig()
        self.workspace_dir = workspace_dir

        # Lazy import to avoid circular dependency
        from ..brain.research_brain import ResearchBrain

        # Initialize brain
        self.brain = ResearchBrain(
            target=target,
            llm_generate=llm_generate,
            engagement_id=engagement_id,
            tools=tools or [],
        )

        # Initialize executor
        self.executor = PlanExecutor(
            http_client=http_client,
            tool_executor=tool_executor,
            browser=browser,
            auth_headers=auth_headers,
            rate_limit_delay=self.config.rate_limit_delay,
        )

        # Initialize evidence collector
        self.evidence = EvidenceCollector(workspace_dir=workspace_dir)

        # State
        self._iteration = 0
        self._consecutive_failures = 0
        self._stagnation_count = 0
        self._strategy = "explore"  # explore, validate, exploit
        self._tested_endpoints: set[str] = set()

    async def initialize(self) -> None:
        """Initialize the loop."""
        await self.brain.initialize()
        logger.info(f"Research loop initialized for {self.target}")

    async def run(self) -> dict[str, Any]:
        """Run the complete research loop."""
        start_time = time.time()

        while True:
            # Check stopping conditions
            should_stop, reason = self._check_stopping_conditions()
            if should_stop:
                logger.info(f"Stopping: {reason}")
                break

            # Run one iteration
            result = await self._iteration_cycle()

            # Periodic tasks
            if self._iteration % self.config.checkpoint_interval == 0:
                self._save_checkpoint()

            if self._iteration % self.config.self_eval_interval == 0:
                self._self_evaluate()

        # Generate final report
        report = self._generate_report()
        report["duration"] = time.time() - start_time

        return report

    async def _iteration_cycle(self) -> dict[str, Any]:
        """Run a single iteration of the research cycle."""
        self._iteration += 1
        self.brain.case.increment_iteration()

        try:
            # 1. Reason about next action
            decision = await self.brain.reason_next_action()
            logger.info(f"Iteration {self._iteration}: {decision.action.value} on {decision.target}")

            # 2. Check if we should stop
            if decision.action == ActionType.STOP:
                return {"action": "stop", "reason": decision.reason}

            # 3. Check if already tested
            action_key = f"{decision.action.value}:{decision.target}"
            if action_key in self._tested_endpoints:
                logger.debug(f"Already tested: {action_key}")
                self._stagnation_count += 1
                return {"action": "skip", "reason": "already tested"}

            # 4. Add hypothesis if this is a test action
            hypothesis = None
            if decision.action.value.startswith("test_"):
                hypothesis = self.brain.add_hypothesis(
                    description=decision.reason,
                    vuln_class=decision.action.value.replace("test_", ""),
                    endpoint=decision.target,
                )

            # 5. Plan experiment if we have a hypothesis
            plan = None
            if hypothesis:
                plan = await self.brain.plan_experiment(hypothesis)

            # 6. Execute experiment
            if plan:
                # Record experiment in case
                experiment = self.brain.case.add_experiment(
                    hypothesis_id=hypothesis.id,
                    action=decision.action.value,
                    target=decision.target,
                    tool=decision.tool_hint,
                )
                experiment.plan = plan

                # Execute
                result = await self.executor.execute(plan)

                # Record result
                experiment.result = result
                experiment.success = result.get("success", False)
                experiment.error = result.get("error", "")
                experiment.duration = result.get("duration", 0)

                # Collect evidence
                for evidence_item in result.get("evidence", []):
                    self.evidence.add_evidence(
                        type=evidence_item.get("type", ""),
                        description=evidence_item.get("description", ""),
                        request=evidence_item.get("request"),
                        response=evidence_item.get("response"),
                        data=evidence_item.get("data"),
                    )

                # Add observations to case
                for obs in result.get("observations", []):
                    self.brain.case.add_observation(
                        description=obs.get("description", ""),
                        source="executor",
                        data=obs.get("data"),
                    )

                # Validate if we have evidence
                if result.get("evidence"):
                    validation_result = await self._validate_evidence(
                        decision, hypothesis, result
                    )
                    if validation_result.get("is_finding"):
                        self._consecutive_failures = 0
                        self._stagnation_count = 0
                    else:
                        self._consecutive_failures += 1
                        self._stagnation_count += 1
                else:
                    self._consecutive_failures += 1
                    self._stagnation_count += 1

                # Mark as tested
                self._tested_endpoints.add(action_key)

                return {
                    "action": decision.action.value,
                    "target": decision.target,
                    "success": result.get("success", False),
                    "evidence_count": len(result.get("evidence", [])),
                }
            else:
                # No plan needed (recon, observe, etc.)
                self.brain.case.add_observation(
                    description=f"Executed {decision.action.value} on {decision.target}",
                    source="brain",
                )
                self._tested_endpoints.add(action_key)
                return {"action": decision.action.value, "target": decision.target}

        except Exception as e:
            logger.error(f"Iteration {self._iteration} failed: {e}")
            self._consecutive_failures += 1
            self._stagnation_count += 1
            return {"action": "error", "error": str(e)}

    async def _validate_evidence(
        self,
        decision: Decision,
        hypothesis: Any,
        result: dict[str, Any],
    ) -> dict[str, Any]:
        """Validate evidence from an experiment."""
        # Package evidence for validation
        evidence_package = self.evidence.package_for_validation(
            vuln_class=decision.action.value.replace("test_", ""),
            endpoint=decision.target,
            method=decision.params.get("method", "GET"),
        )

        # Add hypothesis reference
        evidence_package["hypothesis_id"] = hypothesis.id

        # Validate
        validation_result = await self.brain.validate_finding(evidence_package)
        return validation_result

    def _check_stopping_conditions(self) -> tuple[bool, str]:
        """Check if the loop should stop."""
        if self._iteration >= self.config.max_iterations:
            return True, f"Max iterations ({self.config.max_iterations}) reached"

        if self._consecutive_failures >= self.config.max_consecutive_failures:
            return True, f"Too many consecutive failures ({self._consecutive_failures})"

        if self._stagnation_count >= self.config.stagnation_threshold:
            # Try to pivot strategy
            if self._strategy == "explore":
                self._strategy = "validate"
                self._stagnation_count = 0
                logger.info("Pivoting strategy: explore -> validate")
                return False, ""
            elif self._strategy == "validate":
                self._strategy = "exploit"
                self._stagnation_count = 0
                logger.info("Pivoting strategy: validate -> exploit")
                return False, ""
            else:
                return True, "Stagnant across all strategies"

        should_stop, reason = self.brain.should_stop()
        if should_stop:
            return True, reason

        return False, ""

    def _save_checkpoint(self) -> None:
        """Save a checkpoint of the current state."""
        if self.workspace_dir:
            path = f"{self.workspace_dir}/checkpoint.json"
            self.brain.save_case(path)
            logger.debug(f"Checkpoint saved: {path}")

    def _self_evaluate(self) -> None:
        """Evaluate progress and adjust strategy."""
        stats = self.brain.get_stats()
        logger.info(
            f"Self-eval: iteration={stats['iteration']}, "
            f"observations={stats['observations']}, "
            f"hypotheses={stats['hypotheses']}, "
            f"findings={stats['findings']}, "
            f"strategy={self._strategy}"
        )

    def _generate_report(self) -> dict[str, Any]:
        """Generate a final report."""
        stats = self.brain.get_stats()
        evidence_summary = self.evidence.get_summary()

        return {
            "target": self.target,
            "iterations": self._iteration,
            "strategy": self._strategy,
            "stats": stats,
            "evidence": evidence_summary,
            "findings": [
                f.to_dict() for f in self.brain.case.get_confirmed_findings()
            ],
            "hypotheses": [
                h.to_dict() for h in self.brain.case.hypotheses
            ],
            "observations_count": len(self.brain.case.observations),
        }

    def get_status(self) -> dict[str, Any]:
        """Get current loop status."""
        return {
            "target": self.target,
            "iteration": self._iteration,
            "strategy": self._strategy,
            "consecutive_failures": self._consecutive_failures,
            "stagnation_count": self._stagnation_count,
            "tested_endpoints": len(self._tested_endpoints),
            "brain_stats": self.brain.get_stats(),
            "evidence_summary": self.evidence.get_summary(),
        }
