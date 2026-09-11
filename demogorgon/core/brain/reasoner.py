"""LLM Reasoner — proposes next actions using LLM reasoning.

Implements the Reasoner interface. Uses structured prompts to analyze
context and propose the next best action. The LLM reasons; deterministic
code validates and executes.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from ..interfaces import Reasoner, Decision, ActionType, Observation
from ..research_loop.case import ResearchCase, CaseObservation

logger = logging.getLogger(__name__)

# System prompt for the reasoner
REASONER_SYSTEM_PROMPT = """You are a security research reasoner for an autonomous bug bounty hunter.

Your job: analyze the current state of an investigation and propose the SINGLE BEST next action.

You have access to:
- Discovered assets and endpoints
- Observations from previous actions
- Hypotheses being tested
- Findings confirmed so far
- Available tools
- Scope restrictions

RULES:
1. Never propose actions outside the defined scope
2. Prioritize high-impact vulnerability classes (IDOR, auth bypass, SSRF, RCE)
3. Don't repeat actions already taken
4. If no interesting leads remain, propose STOP
5. Consider tool availability when proposing actions
6. Each action must have a clear security rationale

RESPOND WITH VALID JSON:
{
    "action": "<action_type>",
    "target": "<specific target URL or endpoint>",
    "reason": "<why this is the best next action>",
    "confidence": <0.0 to 1.0>,
    "priority": <0.0 to 1.0>,
    "params": {},
    "tool_hint": "<suggested tool or empty>"
}

Action types: recon, crawl, fuzz, test_endpoint, test_idor, test_xss, test_sqli, test_ssrf, test_csrf, test_redirect, test_upload, analyze_js, analyze_api, test_auth, investigate, observe, wait, stop
"""

REASONING_PROMPT = """Analyze this context and propose the next best action.

Current iteration: {iteration}
Target: {target}

DISCOVERED ASSETS ({asset_count}):
{assets_summary}

RECENT OBSERVATIONS:
{observations_summary}

ACTIVE HYPOTHESES:
{hypotheses_summary}

CONFIRMED FINDINGS ({finding_count}):
{findings_summary}

TESTED ACTIONS ({tested_count}):
{tested_summary}

AVAILABLE TOOLS:
{tools_summary}

SCOPE: {scope_summary}

What is the SINGLE BEST next action? Consider:
1. Which vulnerability class has the highest expected value given what we know?
2. Which endpoints are most promising?
3. What haven't we tried yet?
4. What tools do we have available?

Respond with JSON only."""


class LLMReasoner(Reasoner):
    """LLM-powered reasoner that proposes next actions.

    Usage:
        reasoner = LLMReasoner(llm_manager)
        decision = await reasoner.reason(context)
    """

    def __init__(self, llm_generate: Any):
        """Initialize with an LLM generate function.

        Args:
            llm_generate: Async callable that takes messages list and returns
                         a dict with 'content' key containing the response text.
        """
        self._llm = llm_generate
        self._action_map = {
            "recon": ActionType.RECON,
            "crawl": ActionType.CRAWL,
            "fuzz": ActionType.FUZZ,
            "test_endpoint": ActionType.TEST_ENDPOINT,
            "test_idor": ActionType.TEST_IDOR,
            "test_xss": ActionType.TEST_XSS,
            "test_sqli": ActionType.TEST_Sqli,
            "test_ssrf": ActionType.TEST_SSRF,
            "test_csrf": ActionType.TEST_CSRF,
            "test_redirect": ActionType.TEST_REDIRECT,
            "test_upload": ActionType.TEST_UPLOAD,
            "analyze_js": ActionType.ANALYZE_JS,
            "analyze_api": ActionType.ANALYZE_API,
            "test_auth": ActionType.TEST_AUTH,
            "investigate": ActionType.INVESTIGATE,
            "observe": ActionType.OBSERVE,
            "wait": ActionType.WAIT,
            "stop": ActionType.STOP,
        }

    async def reason(self, context: dict[str, Any]) -> Decision:
        """Analyze context and propose next action."""
        prompt = self._build_reasoning_prompt(context)

        messages = [
            {"role": "system", "content": REASONER_SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]

        try:
            response = await self._llm(messages, response_format={"type": "json_object"})
            content = response.get("content", "{}") if isinstance(response, dict) else str(response)
            decision_data = json.loads(content)
            return self._parse_decision(decision_data)
        except (json.JSONDecodeError, KeyError, TypeError, Exception) as e:
            logger.warning(f"Failed to parse LLM response: {e}")
            return Decision(
                action=ActionType.OBSERVE,
                target=context.get("target", ""),
                reason=f"LLM parse error, defaulting to observe: {e}",
                confidence=0.2,
            )

    async def explain(self, decision: Decision) -> str:
        """Explain why this decision was made."""
        prompt = f"""Explain why this action was chosen:

Action: {decision.action.value}
Target: {decision.target}
Reason: {decision.reason}
Confidence: {decision.confidence}

Provide a concise explanation of the security rationale."""

        messages = [
            {"role": "system", "content": "You are a security research explainability engine. Explain the reasoning concisely."},
            {"role": "user", "content": prompt},
        ]

        try:
            response = await self._llm(messages)
            return response.get("content", decision.reason) if isinstance(response, dict) else str(response)
        except Exception:
            return decision.reason

    def _build_reasoning_prompt(self, context: dict[str, Any]) -> str:
        """Build the reasoning prompt from context."""
        # Assets summary
        assets = context.get("assets", [])
        assets_lines = []
        for asset in assets[:20]:
            if isinstance(asset, dict):
                assets_lines.append(f"- {asset.get('hostname', asset.get('url', 'unknown'))} ({asset.get('type', 'unknown')})")
            else:
                assets_lines.append(f"- {asset}")
        assets_summary = "\n".join(assets_lines) if assets_lines else "No assets discovered yet"

        # Observations summary
        observations = context.get("observations", [])
        obs_lines = []
        for obs in observations[-10:]:
            if isinstance(obs, dict):
                obs_lines.append(f"- [{obs.get('source', '?')}] {obs.get('description', '')[:100]}")
            elif hasattr(obs, 'description'):
                obs_lines.append(f"- [{obs.source}] {obs.description[:100]}")
        observations_summary = "\n".join(obs_lines) if obs_lines else "No observations yet"

        # Hypotheses summary
        hypotheses = context.get("hypotheses", [])
        hyp_lines = []
        for hyp in hypotheses[-5:]:
            if isinstance(hyp, dict):
                hyp_lines.append(f"- [{hyp.get('status', '?')}] {hyp.get('description', '')[:80]}")
            elif hasattr(hyp, 'description'):
                hyp_lines.append(f"- [{hyp.status.value}] {hyp.description[:80]}")
        hypotheses_summary = "\n".join(hyp_lines) if hyp_lines else "No active hypotheses"

        # Findings summary
        findings = context.get("findings", [])
        findings_lines = []
        for f in findings:
            if isinstance(f, dict):
                findings_lines.append(f"- [{f.get('severity', '?')}] {f.get('title', '')[:60]}")
            elif hasattr(f, 'title'):
                findings_lines.append(f"- [{f.severity}] {f.title[:60]}")
        findings_summary = "\n".join(findings_lines) if findings_lines else "No findings yet"

        # Tested actions summary
        tested = context.get("tested_actions", [])
        tested_lines = [f"- {a}" for a in tested[-20:]]
        tested_summary = "\n".join(tested_lines) if tested_lines else "None tested yet"

        # Tools summary
        tools = context.get("available_tools", [])
        tools_summary = ", ".join(tools) if tools else "No tools available"

        # Scope summary
        scope = context.get("scope_status", "unknown")
        scope_summary = f"Scope status: {scope}"

        return REASONING_PROMPT.format(
            iteration=context.get("iteration", 0),
            target=context.get("target", "unknown"),
            asset_count=len(assets),
            assets_summary=assets_summary,
            observations_summary=observations_summary,
            hypotheses_summary=hypotheses_summary,
            finding_count=len(findings),
            findings_summary=findings_summary,
            tested_count=len(tested),
            tested_summary=tested_summary,
            tools_summary=tools_summary,
            scope_summary=scope_summary,
        )

    def _parse_decision(self, data: dict[str, Any]) -> Decision:
        """Parse LLM response into a Decision object."""
        action_str = data.get("action", "observe")
        action = self._action_map.get(action_str, ActionType.OBSERVE)

        return Decision(
            action=action,
            target=data.get("target", ""),
            reason=data.get("reason", ""),
            confidence=float(data.get("confidence", 0.5)),
            priority=float(data.get("priority", 0.5)),
            params=data.get("params", {}),
            tool_hint=data.get("tool_hint", ""),
        )
