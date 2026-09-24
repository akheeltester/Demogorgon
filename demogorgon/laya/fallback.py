"""Laya Fallback — handles low confidence or unavailable Laya decisions.

Provides deterministic or LLM-reasoning fallbacks for each Laya decision point.
"""

from __future__ import annotations

import logging
import random
from typing import Any

from demogorgon.llm.manager import AIProviderManager
from demogorgon.core.decision_trace import DecisionTrace

logger = logging.getLogger(__name__)


class LayaFallback:
    """Fallback logic when the Laya fast-decision engine fails or lacks confidence."""

    def __init__(self, llm_manager: AIProviderManager, trace: DecisionTrace | None = None):
        self.llm_manager = llm_manager
        self.trace = trace

    async def fallback_strategy(self, context_data: dict[str, Any]) -> tuple[str, float, str]:
        """Fallback for strategy selection.
        
        Uses deterministic round-robin or simple rules based on state.
        """
        # Simple deterministic fallback based on endpoints and tested actions
        endpoints = context_data.get("endpoints", 0)
        tested = context_data.get("tested_actions", 0)
        
        if endpoints < 10:
            strategy = "recon"
            reason = "Deterministic Fallback: Low endpoint count, prioritizing recon."
        elif tested < endpoints:
            strategy = "explore"
            reason = "Deterministic Fallback: Untested endpoints remain, exploring."
        else:
            strategy = "focused"
            reason = "Deterministic Fallback: Most endpoints tested, focusing."
            
        return strategy, 1.0, reason

    async def fallback_target_priority(self, candidates: list[dict[str, Any]]) -> tuple[str, float, str]:
        """Fallback for target prioritization."""
        if not candidates:
            return "", 0.0, "No candidates available"
            
        # Deterministic: pick the one with most parameters or an auth endpoint
        for c in candidates:
            url = c.get("url", "").lower()
            if "api" in url or "admin" in url or "user" in url or "login" in url:
                return c.get("id", url), 0.8, "Deterministic Fallback: Keyword matched in URL"
                
        # Default to first
        first_id = candidates[0].get("id", candidates[0].get("url", ""))
        return first_id, 0.5, "Deterministic Fallback: Picked first available candidate"

    async def fallback_reasoning_route(self, observation: dict[str, Any]) -> tuple[str, float, str]:
        """Fallback for reasoning router."""
        # When in doubt, fallback to deterministic executor to avoid burning LLM budget
        return "deterministic_executor", 1.0, "Deterministic Fallback: Defaulting to deterministic execution"

    async def fallback_triage(self, finding: dict[str, Any]) -> tuple[str, float, str]:
        """Fallback for finding triage."""
        # Always investigate or validate by default to not miss things
        return "validate", 1.0, "Deterministic Fallback: Always validate potential findings"

    async def fallback_continue(self, state_data: dict[str, Any]) -> tuple[str, float, str]:
        """Fallback for continue/stop."""
        budget_used = state_data.get("budget_used", 0)
        if budget_used >= 1.0:
            return "stop", 1.0, "Deterministic Fallback: Budget exceeded"
        return "continue", 1.0, "Deterministic Fallback: Budget remaining"
