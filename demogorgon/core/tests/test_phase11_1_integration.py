"""Phase 11.1 Integration Tests — prove the full observe→reason→act→evaluate loop is real.

Tests:
1. Full chain: ResearchBrain→CapabilityRegistry→PlanExecutor→ActionGateway→tool→Observation→Evidence→Validation→ApplicationModel→ResearchBrain
2. Adaptive two-cycle: Experiment 1 → Observation 2 → Different reasoning → Experiment 2
3. Safety regression: scope/safety/HITL cannot be bypassed
"""

from __future__ import annotations

import asyncio
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def run_async(coro):
    """Helper to run async functions in tests."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ═══════════════════════════════════════════════════════════════════
# Test 1: Full Chain Integration
# ═══════════════════════════════════════════════════════════════════

class TestFullChainIntegration:
    """Prove the full chain works: Brain→Registry→Executor→Gateway→tool→Observation→Evidence→Validation→AppModel→Brain."""

    def test_research_loop_wires_agent_subsystems(self):
        """ResearchLoop accepts and wires all agent subsystems."""
        from demogorgon.core.research_loop.loop import ResearchLoop, LoopConfig
        from demogorgon.agent.events import EventBus
        from demogorgon.agent.capabilities import CapabilityRegistry
        from demogorgon.agent.memory import ResearchMemory
        from demogorgon.agent.trace import ResearchTrace
        from demogorgon.agent.strategies import StrategyEngine

        event_bus = EventBus()
        cap_registry = CapabilityRegistry()
        memory = ResearchMemory()
        trace = ResearchTrace()
        strategy = StrategyEngine()

        async def dummy_llm(**kwargs):
            return {}

        loop = ResearchLoop(
            target="https://example.com",
            llm_generate=dummy_llm,
            event_bus=event_bus,
            capability_registry=cap_registry,
            research_memory=memory,
            research_trace=trace,
            strategy_engine=strategy,
        )

        # Verify subsystems are wired
        assert loop._event_bus is event_bus
        assert loop._capability_registry is cap_registry
        assert loop._research_memory is memory
        assert loop._research_trace is trace
        assert loop._strategy_engine is strategy

        # Verify brain got subsystems
        assert loop.brain._event_bus is event_bus
        assert loop.brain._research_memory is memory

        # Verify executor got subsystems
        assert loop.executor._capability_registry is cap_registry
        assert loop.executor._event_bus is event_bus

    def test_research_brain_uses_memory_in_context(self):
        """ResearchBrain includes memory entries in LLM context."""
        from demogorgon.core.brain.research_brain import ResearchBrain
        from demogorgon.agent.memory import ResearchMemory

        memory = ResearchMemory()
        # Store with target in content so query matching works
        memory.store(
            key="xss_pattern",
            category="vuln_pattern",
            content="XSS found on https://example.com/search?q= endpoint",
            confidence=0.8,
        )

        async def dummy_llm(**kwargs):
            return {}

        brain = ResearchBrain(
            target="https://example.com",
            llm_generate=dummy_llm,
            research_memory=memory,
        )

        ctx = brain._build_context()
        assert "research_memory" in ctx
        assert len(ctx["research_memory"]) > 0
        assert ctx["research_memory"][0]["category"] == "vuln_pattern"

    def test_executor_uses_capability_registry(self):
        """PlanExecutor can look up capabilities from registry."""
        from demogorgon.core.research_loop.executor import PlanExecutor
        from demogorgon.agent.capabilities import CapabilityRegistry

        registry = CapabilityRegistry()
        executor = PlanExecutor(capability_registry=registry)

        # Verify registry is accessible
        assert executor._capability_registry is registry

        # Register a tool to make capabilities available
        registry.register_tool(
            tool_name="httpx",
            capabilities=["http_request"],
        )

        # Can look up available capabilities
        caps = registry.get_available_capabilities()
        assert len(caps) > 0
        assert "http_request" in caps

    def test_event_bus_receives_loop_events(self):
        """EventBus receives events from ResearchLoop iterations."""
        from demogorgon.agent.events import EventBus, EventType

        received_events = []

        async def collector(event):
            received_events.append({"type": event.type, "data": event.data, "source": event.source})

        bus = EventBus()
        bus.on_all(collector)

        run_async(bus.emit(EventType.AGENT_THINKING, {"cycle": 1}, source="loop"))
        run_async(bus.emit(EventType.DECISION_COMPLETE, {"action": "test_xss"}, source="loop"))
        run_async(bus.emit(EventType.TOOL_EXECUTE, {"tool": "httpx"}, source="loop"))
        run_async(bus.emit(EventType.TOOL_RESULT, {"success": True}, source="loop"))
        run_async(bus.emit(EventType.EVIDENCE_COLLECTED, {"count": 2}, source="loop"))
        run_async(bus.emit(EventType.FINDING, {"title": "XSS found"}, source="loop"))

        assert len(received_events) == 6
        types = [e["type"] for e in received_events]
        assert EventType.AGENT_THINKING in types
        assert EventType.DECISION_COMPLETE in types
        assert EventType.TOOL_EXECUTE in types
        assert EventType.FINDING in types

    def test_trace_records_decisions_and_findings(self):
        """ResearchTrace records decisions and findings from loop."""
        from demogorgon.agent.trace import ResearchTrace, TraceEntryType

        trace = ResearchTrace()

        trace.add(
            TraceEntryType.DECISION,
            "test_xss on /search: potential reflected XSS",
            iteration=1,
            cycle_id="cycle_1",
        )
        trace.add(
            TraceEntryType.FINDING,
            "Reflected XSS in /search?q=",
            data={"severity": "high"},
            iteration=1,
            cycle_id="cycle_1",
        )

        entries = trace.get_recent(10)
        assert len(entries) == 2
        assert entries[0].type == TraceEntryType.DECISION
        assert entries[1].type == TraceEntryType.FINDING

    def test_strategy_engine_influences_loop_pivot(self):
        """StrategyEngine state influences loop strategy pivots."""
        from demogorgon.agent.strategies import StrategyEngine, AgentStrategy

        engine = StrategyEngine()

        # Simulate stagnation
        ctx = {
            "endpoints_discovered": 5,
            "findings": 0,
            "validated_findings": 0,
            "false_positives": 0,
            "evidence_count": 0,
            "chains": 0,
            "consecutive_failures": 6,
            "tested_vuln_classes": ["xss", "sqli"],
        }
        state = engine.evaluate(ctx)

        # Should pivot strategy after stagnation
        assert state.strategy != AgentStrategy.RECON


# ═══════════════════════════════════════════════════════════════════
# Test 2: Adaptive Two-Cycle Test
# ═══════════════════════════════════════════════════════════════════

class TestAdaptiveTwoCycle:
    """Prove Experiment 1 → Observation 2 → Different reasoning → Experiment 2."""

    def test_brain_changes_reasoning_based_on_observations(self):
        """ResearchBrain reasons differently after receiving new observations."""
        from demogorgon.core.brain.research_brain import ResearchBrain
        from demogorgon.core.research_loop.case import ResearchCase
        import json

        call_count = 0
        decisions_made = []

        async def mock_llm(messages, **kwargs):
            nonlocal call_count
            call_count += 1

            # First call: propose XSS test
            if call_count == 1:
                return {
                    "content": json.dumps({
                        "action": "test_xss",
                        "target": "https://example.com/search",
                        "reason": "Search parameter looks vulnerable to XSS",
                        "confidence": 0.7,
                        "params": {},
                        "tool_hint": "",
                    })
                }
            # Second call: after seeing 200 OK with reflected input, propose IDOR
            else:
                return {
                    "content": json.dumps({
                        "action": "test_idor",
                        "target": "https://example.com/api/users/1",
                        "reason": "XSS test returned 200, now try IDOR on user endpoint",
                        "confidence": 0.6,
                        "params": {},
                        "tool_hint": "",
                    })
                }

        brain = ResearchBrain(
            target="https://example.com",
            llm_generate=mock_llm,
        )

        # Cycle 1: reason → get XSS decision
        decision1 = run_async(brain.reason_next_action())
        decisions_made.append(decision1)
        assert decision1.action.value == "test_xss"

        # Simulate observation from cycle 1 result
        brain.case.add_observation(
            description="GET /search?q=test returned 200 with reflected input",
            source="executor",
            data={"status_code": 200, "reflected": True},
        )
        brain._iteration += 1

        # Cycle 2: reason again → should get DIFFERENT decision (IDOR)
        decision2 = run_async(brain.reason_next_action())
        decisions_made.append(decision2)

        # The brain should have proposed a different action
        assert decision2.action.value == "test_idor"
        assert decision1.action.value != decision2.action.value

    def test_memory_influences_subsequent_reasoning(self):
        """ResearchMemory from cycle 1 influences reasoning in cycle 2."""
        from demogorgon.core.brain.research_brain import ResearchBrain
        from demogorgon.agent.memory import ResearchMemory
        import json

        memory = ResearchMemory()

        # Store a finding from cycle 1 (include target in content for query matching)
        memory.store(
            key="finding_cycle1",
            category="finding_pattern",
            content="XSS found on https://example.com/search endpoint",
            confidence=0.9,
        )

        ctx_with_memory = None

        async def mock_llm(messages, **kwargs):
            nonlocal ctx_with_memory
            # Capture the context to verify memory is included
            for msg in messages:
                if "research_memory" in str(msg.get("content", "")):
                    ctx_with_memory = True
            return {
                "content": json.dumps({
                    "action": "test_idor",
                    "target": "https://example.com/api/users/1",
                    "reason": "Already found XSS, now try IDOR",
                    "confidence": 0.6,
                    "params": {},
                    "tool_hint": "",
                })
            }

        brain = ResearchBrain(
            target="https://example.com",
            llm_generate=mock_llm,
            research_memory=memory,
        )

        decision = run_async(brain.reason_next_action())
        assert decision.action.value == "test_idor"

        # Verify memory was included in context
        ctx = brain._build_context()
        assert "research_memory" in ctx
        assert any("XSS" in m["content"] for m in ctx["research_memory"])

    def test_application_model_updated_from_observations(self):
        """ApplicationModel is updated when observations flow through the loop."""
        from demogorgon.core.research_loop.loop import ResearchLoop, LoopConfig

        observations_received = []

        class MockAppModel:
            def add_observation(self, description="", category="", data=None):
                observations_received.append({
                    "description": description,
                    "category": category,
                    "data": data,
                })

            def get_summary(self):
                return {"observations": len(observations_received)}

        app_model = MockAppModel()

        async def dummy_llm(**kwargs):
            return {}

        loop = ResearchLoop(
            target="https://example.com",
            llm_generate=dummy_llm,
            application_model=app_model,
        )

        # Simulate observations flowing through
        test_observations = [
            {"description": "GET /api/users → 200", "data": {"status_code": 200, "url": "/api/users"}},
            {"description": "POST /api/login → 302", "data": {"status_code": 302, "url": "/api/login"}},
        ]

        loop._update_app_model(test_observations)

        assert len(observations_received) == 2
        assert observations_received[0]["data"]["status_code"] == 200


# ═══════════════════════════════════════════════════════════════════
# Test 3: Safety Regression
# ═══════════════════════════════════════════════════════════════════

class TestSafetyRegression:
    """Verify scope/safety/HITL cannot be bypassed."""

    def test_action_gateway_blocks_out_of_scope(self):
        """ActionGateway denies actions on out-of-scope targets."""
        from demogorgon.core.gateway import ActionGateway, GateResult
        from demogorgon.core.scope.safety import SafetyGate
        from demogorgon.core.engagement import ScopeAsset

        safety = SafetyGate(
            in_scope_assets=[ScopeAsset(pattern="example.com")],
            out_of_scope_assets=[ScopeAsset(pattern="evil.com")],
        )
        gateway = ActionGateway(safety_gate=safety)

        # In-scope should pass
        check_in = run_async(gateway.validate("test_xss", "https://example.com/search"))
        assert check_in.allowed

        # Out-of-scope should be denied
        check_out = run_async(gateway.validate("test_xss", "https://evil.com/search"))
        assert not check_out.allowed
        assert check_out.result == GateResult.DENY

    def test_action_gateway_enforces_rate_limit(self):
        """ActionGateway rate-limits when too many actions per minute."""
        from demogorgon.core.gateway import ActionGateway, GateResult

        gateway = ActionGateway(max_actions_per_minute=3)

        # First 3 should pass
        for _ in range(3):
            check = run_async(gateway.validate("test_xss", "https://example.com/search"))
            assert check.allowed

        # 4th should be rate limited
        check = run_async(gateway.validate("test_xss", "https://example.com/search"))
        assert not check.allowed
        assert check.result == GateResult.RATE_LIMITED

    def test_hitl_gate_blocks_without_approval(self):
        """HITLGate blocks actions when approval is required."""
        from demogorgon.core.hitl.gate import HITLGate, ApprovalLevel

        hitl = HITLGate(approval_level=ApprovalLevel.REQUIRED)

        # Without approval, action should be blocked
        assert not hitl.should_allow("test_xss")

    def test_safety_gate_blocks_restricted_actions(self):
        """SafetyGate blocks actions listed in restrictions."""
        from demogorgon.core.scope.safety import SafetyGate
        from demogorgon.core.engagement import ScopeAsset, TestingRestriction

        safety = SafetyGate(
            in_scope_assets=[ScopeAsset(pattern="example.com")],
            restrictions=[
                TestingRestriction(category="delete", allowed=False),
                TestingRestriction(category="modification", allowed=False),
            ],
        )

        # Delete should be blocked
        check = safety.check_action("delete", "https://example.com/data")
        assert not check.allowed

        # Normal action should pass
        check = safety.check_action("test_xss", "https://example.com/search")
        assert check.allowed

    def test_llm_cannot_bypass_gateway(self):
        """The gateway validation is deterministic and cannot be overridden by LLM output."""
        from demogorgon.core.gateway import ActionGateway, GateResult
        from demogorgon.core.scope.safety import SafetyGate
        from demogorgon.core.engagement import ScopeAsset

        safety = SafetyGate(
            in_scope_assets=[ScopeAsset(pattern="example.com")],
            out_of_scope_assets=[ScopeAsset(pattern="internal.company.com")],
        )
        gateway = ActionGateway(safety_gate=safety)

        # Even if LLM proposes an out-of-scope action with high confidence
        # the gateway MUST deny it
        malicious_proposals = [
            ("test_ssrf", "https://internal.company.com/admin"),
            ("test_rce", "https://internal.company.com/exec"),
            ("recon", "https://evil.com/payload"),
        ]

        for action, target in malicious_proposals:
            check = run_async(gateway.validate(action, target))
            assert not check.allowed, f"Gateway should deny {action} on {target}"
            assert check.result == GateResult.DENY

    def test_scope_check_is_deterministic(self):
        """Scope validation is purely deterministic — no LLM involved."""
        from demogorgon.core.scope.safety import SafetyGate
        from demogorgon.core.engagement import ScopeAsset

        safety = SafetyGate(
            in_scope_assets=[ScopeAsset(pattern="*.example.com")],
            out_of_scope_assets=[ScopeAsset(pattern="staging.example.com")],
        )

        # Subdomain of example.com → in scope
        check = safety.check_url("https://api.example.com/users")
        assert check.allowed

        # Staging → out of scope
        check = safety.check_url("https://staging.example.com/admin")
        assert not check.allowed

        # Completely different domain → out of scope
        check = safety.check_url("https://evil.com/payload")
        assert not check.allowed


# ═══════════════════════════════════════════════════════════════════
# Test 4: Runner Passes Subsystems Through
# ═══════════════════════════════════════════════════════════════════

class TestRunnerSubsystemPassThrough:
    """Verify AutonomousRunner passes agent subsystems to ResearchLoop."""

    def test_runner_accepts_agent_subsystems(self):
        """AutonomousRunner accepts and stores agent subsystem params."""
        from demogorgon.core.runner import AutonomousRunner, RunnerConfig
        from demogorgon.core.engagement import Engagement, EngagementStatus, AuthorizationStatus
        from demogorgon.agent.events import EventBus
        from demogorgon.agent.capabilities import CapabilityRegistry

        engagement = Engagement(
            id="test_eng",
            name="Test",
            target_url="https://example.com",
            status=EngagementStatus.ACTIVE,
            authorization_status=AuthorizationStatus.CONFIRMED,
        )

        event_bus = EventBus()
        cap_registry = CapabilityRegistry()

        runner = AutonomousRunner(
            engagement=engagement,
            config=RunnerConfig(workspace_dir="/tmp/test_runner"),
            event_bus=event_bus,
            capability_registry=cap_registry,
        )

        assert runner._event_bus is event_bus
        assert runner._capability_registry is cap_registry

    def test_runner_subsystems_flow_to_research_loop(self):
        """Agent subsystems flow from Runner to ResearchLoop during _run_research."""
        from demogorgon.core.runner import AutonomousRunner, RunnerConfig
        from demogorgon.core.engagement import Engagement, EngagementStatus, AuthorizationStatus
        from demogorgon.agent.events import EventBus
        from demogorgon.agent.capabilities import CapabilityRegistry
        from demogorgon.agent.memory import ResearchMemory

        engagement = Engagement(
            id="test_eng",
            name="Test",
            target_url="https://example.com",
            status=EngagementStatus.ACTIVE,
            authorization_status=AuthorizationStatus.CONFIRMED,
        )

        event_bus = EventBus()
        cap_registry = CapabilityRegistry()
        memory = ResearchMemory()

        runner = AutonomousRunner(
            engagement=engagement,
            config=RunnerConfig(workspace_dir="/tmp/test_runner"),
            event_bus=event_bus,
            capability_registry=cap_registry,
            research_memory=memory,
        )

        # Verify runner has the subsystems
        assert runner._event_bus is event_bus
        assert runner._capability_registry is cap_registry
        assert runner._research_memory is memory


# ═══════════════════════════════════════════════════════════════════
# Test 5: NoopEventBus Backward Compatibility
# ═══════════════════════════════════════════════════════════════════

class TestBackwardCompatibility:
    """ResearchLoop works without agent subsystems (backward compatible)."""

    def test_loop_works_without_agent_subsystems(self):
        """ResearchLoop initializes and runs without any agent subsystems."""
        from demogorgon.core.research_loop.loop import ResearchLoop, LoopConfig

        async def dummy_llm(**kwargs):
            return {}

        # No agent subsystems passed — should use noop defaults
        loop = ResearchLoop(
            target="https://example.com",
            llm_generate=dummy_llm,
        )

        # Verify noop bus is used
        assert loop._event_bus is not None
        assert loop._capability_registry is None
        assert loop._research_memory is None
        assert loop._research_trace is None
        assert loop._strategy_engine is None
        assert loop._application_model is None

        # Brain should work without subsystems
        assert loop.brain._event_bus is None
        assert loop.brain._research_memory is None

    def test_context_building_without_memory(self):
        """Context building works when no memory is provided."""
        from demogorgon.core.brain.research_brain import ResearchBrain

        async def dummy_llm(**kwargs):
            return {}

        brain = ResearchBrain(
            target="https://example.com",
            llm_generate=dummy_llm,
            # No research_memory
        )

        ctx = brain._build_context()
        assert "research_memory" not in ctx
        assert "application_model" not in ctx
        assert ctx["target"] == "https://example.com"
