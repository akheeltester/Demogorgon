"""Laya Decision Engine — fast structured decision and policy layer.

Laya sits between observations/state and the next decision. It uses a lightweight
"fast model" to make rapid routing, prioritization, and strategy decisions.
It does NOT execute arbitrary commands. Every decision is typed and logged.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from demogorgon.llm.manager import AIProviderManager
from demogorgon.core.decision_trace import DecisionTrace
from demogorgon.core.config import LayaConfig
from demogorgon.laya.fallback import LayaFallback

logger = logging.getLogger(__name__)


class LayaEngine:
    """The fast decision engine for Demogorgon."""

    def __init__(
        self,
        llm_manager: AIProviderManager,
        config: LayaConfig,
        trace: DecisionTrace | None = None,
    ):
        self.llm = llm_manager
        self.config = config
        self.trace = trace or DecisionTrace()
        self.fallback = LayaFallback(llm_manager, self.trace)

    async def _make_decision(
        self,
        decision_type: str,
        question: str,
        options: list[str],
        context: str,
        fallback_func: Any,
        state_version: int = 0,
    ) -> dict[str, Any]:
        """Core decision loop: prompt fast model, parse, fallback if needed."""
        
        if not self.config.enabled:
            selected, conf, reason = await fallback_func()
            source = "deterministic"
            fallback_used = True
        else:
            prompt = (
                f"You are the Laya Decision Engine for a security agent.\n"
                f"Context:\n{context}\n\n"
                f"Question: {question}\n"
                f"You must select ONE of the following options: {options}\n\n"
                f"RESPOND WITH VALID JSON ONLY:\n"
                f"{{\n"
                f"  \"selected\": \"one of the options\",\n"
                f"  \"confidence\": 0.0 to 1.0,\n"
                f"  \"reason\": \"brief explanation\"\n"
                f"}}"
            )

            response = await self.llm.generate(
                messages=[{"role": "user", "content": prompt}],
                model=self.llm.fast_model,
                temperature=0.1,
                max_tokens=200,
                response_format={"type": "json_object"}
            )

            fallback_used = False
            source = "laya"
            
            try:
                if response.error:
                    raise ValueError(f"LLM Error: {response.error}")
                
                data = json.loads(response.content)
                selected = data.get("selected", "")
                conf = float(data.get("confidence", 0.0))
                reason = data.get("reason", "")
                
                if selected not in options:
                    raise ValueError(f"Selected option '{selected}' not in {options}")
                    
                if conf < self.config.confidence_threshold:
                    raise ValueError(f"Confidence {conf} below threshold {self.config.confidence_threshold}")
                    
            except Exception as e:
                logger.warning(f"Laya fast decision failed ({e}), using fallback.")
                selected, conf, reason = await fallback_func()
                source = "deterministic"
                fallback_used = True

        # Record decision
        decision = self.trace.record(
            decision_type=decision_type,
            source=source,
            question=question,
            options=options,
            selected=selected,
            confidence=conf,
            reason_code=reason,
            fallback=fallback_used,
            state_version=state_version,
        )
        
        return decision.to_dict()

    async def select_strategy(self, context_data: dict[str, Any], state_version: int = 0) -> dict[str, Any]:
        """A. Strategy selector."""
        options = ["recon", "explore", "focused", "validate", "chain", "stop"]
        context_str = json.dumps(context_data, indent=2)
        question = "What should be the next overall strategy phase?"
        
        async def do_fallback():
            return await self.fallback.fallback_strategy(context_data)
            
        return await self._make_decision("strategy", question, options, context_str, do_fallback, state_version)

    async def prioritize_target(self, candidates: list[dict[str, Any]], state_version: int = 0) -> dict[str, Any]:
        """B. Target prioritizer."""
        if not candidates:
            raise ValueError("No candidates provided")
            
        options = [str(c.get("id", c.get("url", ""))) for c in candidates]
        context_str = json.dumps(candidates, indent=2)
        question = "Which target should we test next?"
        
        async def do_fallback():
            return await self.fallback.fallback_target_priority(candidates)
            
        return await self._make_decision("target_priority", question, options, context_str, do_fallback, state_version)

    async def route_reasoning(self, observation: dict[str, Any], state_version: int = 0) -> dict[str, Any]:
        """C. Reasoning router."""
        options = ["deterministic_executor", "llm_reasoning", "human_review", "stop"]
        context_str = json.dumps(observation, indent=2)
        question = "How should we process this observation?"
        
        async def do_fallback():
            return await self.fallback.fallback_reasoning_route(observation)
            
        return await self._make_decision("reasoning_route", question, options, context_str, do_fallback, state_version)

    async def triage_finding(self, finding: dict[str, Any], state_version: int = 0) -> dict[str, Any]:
        """D. Finding triage."""
        options = ["ignore", "investigate", "validate", "escalate", "report_candidate"]
        context_str = json.dumps(finding, indent=2)
        question = "How should we triage this potential finding?"
        
        async def do_fallback():
            return await self.fallback.fallback_triage(finding)
            
        return await self._make_decision("finding_triage", question, options, context_str, do_fallback, state_version)

    async def continue_or_stop(self, state_data: dict[str, Any], state_version: int = 0) -> dict[str, Any]:
        """E. Continue/stop decision."""
        options = ["continue", "pause", "request_human", "stop"]
        context_str = json.dumps(state_data, indent=2)
        question = "Should the autonomous loop continue?"
        
        async def do_fallback():
            return await self.fallback.fallback_continue(state_data)
            
        return await self._make_decision("continue_stop", question, options, context_str, do_fallback, state_version)
