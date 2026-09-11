"""LLM Experiment Planner — creates safe experiment plans for testing hypotheses.

Implements the ExperimentPlanner interface. Uses LLM to design experiment
steps, preconditions, safety checks, and evidence collection.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from ..interfaces import ExperimentPlanner

logger = logging.getLogger(__name__)

PLANNER_SYSTEM_PROMPT = """You are a security experiment planner for an autonomous bug bounty hunter.

Your job: design a SAFE, CONTROLLED experiment to test a hypothesis.

RULES:
1. Every experiment must have safety checks
2. Never propose destructive actions (DELETE data, modify production)
3. Always collect evidence before and after
4. Include rollback steps if something goes wrong
5. Define clear success/failure criteria
6. Stay within scope

RESPOND WITH VALID JSON:
{
    "steps": [
        {"step": 1, "action": "...", "target": "...", "method": "...", "expected": "..."}
    ],
    "preconditions": ["..."],
    "expected_outcomes": ["..."],
    "safety_checks": ["..."],
    "evidence_to_collect": ["..."],
    "rollback_steps": ["..."],
    "estimated_duration_seconds": 30,
    "risk_level": "low|medium|high"
}
"""

PLANNER_PROMPT = """Design an experiment to test this hypothesis:

HYPOTHESIS:
{hypothesis}

ENDPOINT: {endpoint}
VULN CLASS: {vuln_class}

CONTEXT:
{context}

AVAILABLE TOOLS: {tools}

Design a safe, controlled experiment. Include:
1. Exact steps to execute
2. Preconditions that must be true
3. Safety checks
4. Evidence to collect
5. Expected outcomes for both success and failure

Respond with JSON only."""


class LLMExperimentPlanner(ExperimentPlanner):
    """LLM-powered experiment planner.

    Usage:
        planner = LLMExperimentPlanner(llm_generate)
        plan = await planner.plan(hypothesis, context)
    """

    def __init__(self, llm_generate: Any):
        """Initialize with an LLM generate function."""
        self._llm = llm_generate

    async def plan(self, hypothesis: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        """Create an experiment plan for a hypothesis."""
        prompt = PLANNER_PROMPT.format(
            hypothesis=hypothesis.get("description", "Unknown hypothesis"),
            endpoint=hypothesis.get("endpoint", "Unknown"),
            vuln_class=hypothesis.get("vuln_class", "Unknown"),
            context=self._format_context(context),
            tools=", ".join(context.get("available_tools", [])),
        )

        messages = [
            {"role": "system", "content": PLANNER_SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]

        try:
            response = await self._llm(messages, response_format={"type": "json_object"})
            if hasattr(response, "content"):
                content = response.content or "{}"
            elif isinstance(response, dict):
                content = response.get("content", "{}")
            else:
                content = str(response)
            plan = json.loads(content)
            return self._validate_plan(plan, hypothesis)
        except (json.JSONDecodeError, KeyError, TypeError, Exception) as e:
            logger.warning(f"Failed to parse planner response: {e}")
            return self._fallback_plan(hypothesis)

    def _format_context(self, context: dict[str, Any]) -> str:
        """Format context for the prompt."""
        lines = []
        for key in ["target", "tech_stack", "auth_state", "recent_observations"]:
            value = context.get(key, "")
            if value:
                if isinstance(value, list):
                    lines.append(f"{key}: {', '.join(str(v) for v in value[:10])}")
                else:
                    lines.append(f"{key}: {str(value)[:200]}")
        return "\n".join(lines) if lines else "No additional context"

    def _validate_plan(self, plan: dict[str, Any], hypothesis: dict[str, Any]) -> dict[str, Any]:
        """Validate and normalize the plan."""
        # Ensure required fields
        plan.setdefault("steps", [])
        plan.setdefault("preconditions", [])
        plan.setdefault("expected_outcomes", [])
        plan.setdefault("safety_checks", [])
        plan.setdefault("evidence_to_collect", [])
        plan.setdefault("rollback_steps", [])
        plan.setdefault("estimated_duration_seconds", 60)
        plan.setdefault("risk_level", "medium")

        # Add hypothesis reference
        plan["hypothesis_id"] = hypothesis.get("id", "")
        plan["hypothesis_description"] = hypothesis.get("description", "")

        # Ensure safety checks exist
        if not plan["safety_checks"]:
            plan["safety_checks"] = [
                "Verify target is in scope",
                "Check rate limits before execution",
                "Collect baseline response before testing",
            ]

        return plan

    def _fallback_plan(self, hypothesis: dict[str, Any]) -> dict[str, Any]:
        """Create a minimal fallback plan when LLM fails."""
        endpoint = hypothesis.get("endpoint", "")
        vuln_class = hypothesis.get("vuln_class", "unknown")

        return {
            "steps": [
                {
                    "step": 1,
                    "action": "send_request",
                    "target": endpoint,
                    "method": "GET",
                    "expected": "Observe response for vulnerability indicators",
                }
            ],
            "preconditions": ["Target is reachable", "In scope"],
            "expected_outcomes": [
                "Response contains vulnerability indicator",
                "Response is normal (hypothesis likely false)",
            ],
            "safety_checks": [
                "Verify target is in scope",
                "Rate limit respected",
            ],
            "evidence_to_collect": [
                "Full request/response pair",
                "Response headers",
                "Response body",
            ],
            "rollback_steps": [],
            "estimated_duration_seconds": 30,
            "risk_level": "low",
            "hypothesis_id": hypothesis.get("id", ""),
            "hypothesis_description": hypothesis.get("description", ""),
        }
