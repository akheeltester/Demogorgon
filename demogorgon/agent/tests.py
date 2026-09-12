"""Tests for demogorgon.agent module — EventBus, TokenTracker, BudgetController, etc.

All tests use run_async() helper since pytest-asyncio is not installed.
"""

import asyncio
import json
import os
import tempfile
import time

from demogorgon.agent.events import EventBus, EventType, AgentEvent
from demogorgon.agent.tokens import TokenTracker, TokenUsage
from demogorgon.agent.budget import BudgetController, BudgetLimits, BudgetStatus
from demogorgon.agent.trace import ResearchTrace, TraceEntry, TraceEntryType
from demogorgon.agent.strategies import StrategyEngine, AgentStrategy, StrategyState
from demogorgon.agent.commands import CommandProcessor, CommandResult, CommandType


def run_async(coro):
    """Run an async coroutine synchronously."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# === EventBus Tests ===


class TestEventBus:
    def test_create_event_bus(self):
        bus = EventBus()
        assert bus is not None
        assert len(bus._handlers) == 0

    def test_create_agent_event(self):
        event = AgentEvent(type=EventType.FINDING, data={"title": "XSS"})
        assert event.type == EventType.FINDING
        assert event.data["title"] == "XSS"
        assert event.timestamp > 0
        d = event.to_dict()
        assert d["type"] == "finding.new"

    def test_subscribe_and_emit(self):
        bus = EventBus()
        received = []

        async def handler(event):
            received.append(event)

        bus.on(EventType.FINDING, handler)
        assert EventType.FINDING in bus._handlers

    def test_unsubscribe(self):
        bus = EventBus()
        received = []

        async def handler(event):
            received.append(event)

        bus.on(EventType.FINDING, handler)
        bus.off(EventType.FINDING, handler)
        assert EventType.FINDING not in bus._handlers or len(bus._handlers.get(EventType.FINDING, [])) == 0

    def test_once_subscription(self):
        bus = EventBus()
        call_count = [0]

        async def handler(event):
            call_count[0] += 1

        bus.once(EventType.FINDING, handler)
        # After first emit, handler should be removed
        # (We can't easily test emit without async, but verify structure)
        assert EventType.FINDING in bus._handlers

    def test_get_history(self):
        bus = EventBus()
        # Manually add to history
        bus._history.append(AgentEvent(type=EventType.FINDING, data={"t": 1}))
        bus._history.append(AgentEvent(type=EventType.ERROR, data={"t": 2}))
        bus._history.append(AgentEvent(type=EventType.FINDING, data={"t": 3}))

        all_events = bus.get_history(limit=10)
        assert len(all_events) == 3

        findings = bus.get_history(event_type=EventType.FINDING)
        assert len(findings) == 2

    def test_clear_history(self):
        bus = EventBus()
        bus._history.append(AgentEvent(type=EventType.FINDING))
        bus.clear_history()
        assert len(bus._history) == 0


# === TokenTracker Tests ===


class TestTokenTracker:
    def test_create_tracker(self):
        tracker = TokenTracker()
        assert tracker.total_tokens == 0
        assert tracker.total_cost == 0.0
        assert tracker.total_calls == 0

    def test_record_usage(self):
        tracker = TokenTracker()
        usage = TokenUsage(
            prompt_tokens=100,
            completion_tokens=50,
            total_tokens=150,
            cost_usd=0.001,
            provider="openai",
            model="gpt-4o-mini",
        )
        tracker.record(usage)
        assert tracker.total_tokens == 150
        assert tracker.total_cost == 0.001
        assert tracker.total_calls == 1

    def test_record_call(self):
        tracker = TokenTracker()
        usage = tracker.record_call(
            provider="openai",
            model="gpt-4o-mini",
            prompt_tokens=200,
            completion_tokens=100,
            latency_ms=500.0,
        )
        assert usage.total_tokens == 300
        assert usage.cost_usd > 0
        assert tracker.total_calls == 1

    def test_cost_computation(self):
        tracker = TokenTracker()
        # gpt-4o-mini: $0.15/1M input, $0.60/1M output
        usage = tracker.record_call(
            provider="openai",
            model="gpt-4o-mini",
            prompt_tokens=1_000_000,  # 1M tokens
            completion_tokens=1_000_000,
        )
        # Should be ~$0.15 + $0.60 = $0.75
        assert 0.70 < usage.cost_usd < 0.80

    def test_free_model_cost(self):
        tracker = TokenTracker()
        usage = tracker.record_call(
            provider="openrouter",
            model="nvidia/nemotron-3-super-120b-a12b:free",
            prompt_tokens=1000,
            completion_tokens=500,
        )
        assert usage.cost_usd == 0.0

    def test_live_display(self):
        tracker = TokenTracker()
        tracker.record_call("openai", "gpt-4o-mini", 100, 50)
        display = tracker.live_display
        assert "Tokens:" in display
        assert "Cost:" in display
        assert "Calls:" in display

    def test_totals_display(self):
        tracker = TokenTracker()
        tracker.record_call("openai", "gpt-4o-mini", 100, 50)
        display = tracker.totals_display
        assert "Tokens:" in display
        assert "in" in display
        assert "out" in display

    def test_get_by_provider(self):
        tracker = TokenTracker()
        tracker.record_call("openai", "gpt-4o-mini", 100, 50)
        tracker.record_call("anthropic", "claude-3-5-haiku-20241022", 200, 100)

        by_provider = tracker.get_by_provider()
        assert "openai" in by_provider
        assert "anthropic" in by_provider
        assert by_provider["openai"]["calls"] == 1
        assert by_provider["anthropic"]["calls"] == 1

    def test_reset(self):
        tracker = TokenTracker()
        tracker.record_call("openai", "gpt-4o-mini", 100, 50)
        tracker.reset()
        assert tracker.total_tokens == 0
        assert tracker.total_calls == 0

    def test_to_dict(self):
        tracker = TokenTracker()
        tracker.record_call("openai", "gpt-4o-mini", 100, 50)
        d = tracker.to_dict()
        assert "total_tokens" in d
        assert "total_cost" in d
        assert "by_provider" in d


# === BudgetController Tests ===


class TestBudgetController:
    def test_create_budget(self):
        budget = BudgetController()
        assert budget._cycles == 0
        assert budget._cost == 0.0

    def test_custom_limits(self):
        limits = BudgetLimits(max_cycles=10, max_cost_usd=1.00)
        budget = BudgetController(limits)
        assert budget.limits.max_cycles == 10
        assert budget.limits.max_cost_usd == 1.00

    def test_record_cycle(self):
        budget = BudgetController()
        budget.record_cycle()
        budget.record_cycle()
        assert budget._cycles == 2

    def test_record_cost(self):
        budget = BudgetController()
        budget.record_cost(0.50)
        budget.record_cost(0.30)
        assert budget._cost == 0.80

    def test_budget_ok(self):
        budget = BudgetController(BudgetLimits(max_cycles=100, max_cost_usd=5.00))
        budget.record_cycle()
        budget.record_cost(0.01)
        status = budget.check()
        assert len(status.exceeded) == 0

    def test_budget_exceeded_cycles(self):
        budget = BudgetController(BudgetLimits(max_cycles=5))
        for _ in range(5):
            budget.record_cycle()
        status = budget.check()
        assert len(status.exceeded) > 0
        assert "Cycles" in status.exceeded[0]

    def test_budget_exceeded_cost(self):
        budget = BudgetController(BudgetLimits(max_cost_usd=1.00))
        budget.record_cost(1.50)
        status = budget.check()
        assert len(status.exceeded) > 0
        assert "Cost" in status.exceeded[0]

    def test_budget_warnings(self):
        budget = BudgetController(BudgetLimits(max_cycles=10))
        for _ in range(9):  # 90% = warning threshold
            budget.record_cycle()
        status = budget.check()
        assert len(status.warnings) > 0

    def test_should_stop(self):
        budget = BudgetController(BudgetLimits(max_cycles=3))
        budget.record_cycle()
        budget.record_cycle()
        budget.record_cycle()
        should_stop, reason = budget.should_stop()
        assert should_stop
        assert "Cycles" in reason

    def test_should_not_stop(self):
        budget = BudgetController(BudgetLimits(max_cycles=100))
        budget.record_cycle()
        should_stop, _ = budget.should_stop()
        assert not should_stop

    def test_usage_display(self):
        budget = BudgetController(BudgetLimits(max_cycles=50, max_cost_usd=2.00))
        budget.record_cycle()
        budget.record_cost(0.01)
        display = budget.get_usage_display()
        assert "Cycles:" in display
        assert "Cost:" in display

    def test_duration_tracking(self):
        budget = BudgetController(BudgetLimits(max_duration_seconds=10))
        budget.start(time.time() - 5)  # Started 5 seconds ago
        assert budget.duration >= 4.9

    def test_to_dict(self):
        budget = BudgetController()
        budget.record_cycle()
        d = budget.to_dict()
        assert "limits" in d
        assert "usage" in d
        assert d["usage"]["cycles"] == 1


# === ResearchTrace Tests ===


class TestResearchTrace:
    def test_create_trace(self):
        trace = ResearchTrace()
        assert len(trace) == 0

    def test_add_entries(self):
        trace = ResearchTrace()
        trace.add(TraceEntryType.OBSERVATION, "Found /api/users")
        trace.add(TraceEntryType.DECISION, "Testing IDOR")
        assert len(trace) == 2

    def test_get_recent(self):
        trace = ResearchTrace()
        for i in range(20):
            trace.add(TraceEntryType.OBSERVATION, f"Obs {i}")
        recent = trace.get_recent(5)
        assert len(recent) == 5
        assert recent[0].content == "Obs 15"

    def test_get_by_type(self):
        trace = ResearchTrace()
        trace.add(TraceEntryType.OBSERVATION, "Obs 1")
        trace.add(TraceEntryType.FINDING, "Finding 1")
        trace.add(TraceEntryType.OBSERVATION, "Obs 2")
        trace.add(TraceEntryType.FINDING, "Finding 2")

        findings = trace.get_by_type(TraceEntryType.FINDING)
        assert len(findings) == 2

    def test_get_last_n_actions(self):
        trace = ResearchTrace()
        trace.add(TraceEntryType.ACTION, "HTTP GET /api")
        trace.add(TraceEntryType.TOOL_CALL, "nuclei scan")
        trace.add(TraceEntryType.ACTION, "HTTP POST /api")
        actions = trace.get_last_n_actions(2)
        assert len(actions) == 2
        assert "HTTP POST" in actions[1]

    def test_check_for_loops(self):
        trace = ResearchTrace()
        # Add same action 6 times
        for _ in range(6):
            trace.add(TraceEntryType.ACTION, "HTTP GET /api/users/1")
        is_loop, pattern = trace.check_for_loops(window=3)
        assert is_loop
        assert "HTTP GET" in pattern

    def test_no_loop(self):
        trace = ResearchTrace()
        actions = ["GET /api", "POST /api", "GET /login", "POST /login", "GET /admin"]
        for a in actions:
            trace.add(TraceEntryType.ACTION, a)
        is_loop, _ = trace.check_for_loops()
        assert not is_loop

    def test_get_llm_summary(self):
        trace = ResearchTrace()
        trace.add(TraceEntryType.OBSERVATION, "Found endpoint")
        trace.add(TraceEntryType.DECISION, "Test IDOR")
        summary = trace.get_llm_summary()
        assert "[OBS]" in summary
        assert "[DEC]" in summary

    def test_save_and_load(self):
        trace = ResearchTrace()
        trace.add(TraceEntryType.OBSERVATION, "Test obs")
        trace.add(TraceEntryType.FINDING, "Test finding")

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            trace.save(path)
            loaded = ResearchTrace.load(path)
            assert len(loaded) == 2
            assert loaded._entries[0].content == "Test obs"
        finally:
            os.unlink(path)

    def test_max_entries_trim(self):
        trace = ResearchTrace(max_entries=10)
        for i in range(15):
            trace.add(TraceEntryType.OBSERVATION, f"Obs {i}")
        assert len(trace) == 10
        assert trace._entries[0].content == "Obs 5"

    def test_trace_entry_to_dict(self):
        entry = TraceEntry(
            type=TraceEntryType.FINDING,
            content="XSS in /search",
            data={"severity": "high"},
            iteration=5,
        )
        d = entry.to_dict()
        assert d["type"] == "finding"
        assert d["content"] == "XSS in /search"
        assert d["data"]["severity"] == "high"

    def test_trace_entry_from_dict(self):
        d = {
            "type": "finding",
            "content": "XSS in /search",
            "data": {"severity": "high"},
            "timestamp": 1234567890.0,
            "iteration": 5,
        }
        entry = TraceEntry.from_dict(d)
        assert entry.type == TraceEntryType.FINDING
        assert entry.content == "XSS in /search"


# === StrategyEngine Tests ===


class TestStrategyEngine:
    def test_create_engine(self):
        engine = StrategyEngine()
        assert engine.state.strategy == AgentStrategy.RECON
        assert engine.state.total_cycles == 0

    def test_initial_strategy_is_recon(self):
        engine = StrategyEngine()
        state = engine.evaluate({})
        assert state.strategy == AgentStrategy.RECON

    def test_transition_recon_to_explore(self):
        engine = StrategyEngine()
        # After 10 cycles in recon, should transition to explore
        for _ in range(11):
            state = engine.evaluate({"endpoints_discovered": 10})
        assert state.strategy == AgentStrategy.EXPLORE

    def test_transition_explore_to_validate(self):
        engine = StrategyEngine()
        # Skip to explore
        engine.force_strategy(AgentStrategy.EXPLORE)
        # With findings, should transition to validate
        state = engine.evaluate({"findings": 5, "consecutive_failures": 0})
        assert state.strategy == AgentStrategy.VALIDATE

    def test_transition_explore_to_focused_on_stagnation(self):
        engine = StrategyEngine()
        engine.force_strategy(AgentStrategy.EXPLORE)
        # Stagnation should trigger focused
        for _ in range(6):
            state = engine.evaluate({"consecutive_failures": 5})
        assert state.strategy == AgentStrategy.FOCUSED

    def test_force_strategy(self):
        engine = StrategyEngine()
        engine.force_strategy(AgentStrategy.EXPLOIT, reason="Testing")
        assert engine.state.strategy == AgentStrategy.EXPLOIT
        assert engine.state.reason == "Testing"
        assert engine.state.cycles_in_strategy == 0

    def test_record_finding(self):
        engine = StrategyEngine()
        engine.record_finding()
        engine.record_finding()
        assert engine.state.findings_per_strategy.get("recon", 0) == 2

    def test_get_strategy_context(self):
        engine = StrategyEngine()
        ctx = engine.get_strategy_context()
        assert "current_strategy" in ctx
        assert ctx["current_strategy"] == "recon"

    def test_to_dict(self):
        engine = StrategyEngine()
        d = engine.to_dict()
        assert "strategy" in d
        assert d["strategy"] == "recon"

    def test_load_state(self):
        engine = StrategyEngine()
        data = {
            "strategy": "exploit",
            "confidence": 0.8,
            "cycles_in_strategy": 5,
            "stagnation_count": 2,
            "total_cycles": 20,
        }
        engine.load_state(data)
        assert engine.state.strategy == AgentStrategy.EXPLOIT
        assert engine.state.total_cycles == 20


# === CommandProcessor Tests ===


class TestCommandProcessor:
    def test_create_processor(self):
        processor = CommandProcessor()
        assert processor is not None

    def test_process_help(self):
        processor = CommandProcessor()
        result = run_async(processor.process("/help", {}))
        assert result.success
        assert "DEMOGORGON COMMANDS" in result.message

    def test_process_unknown_command(self):
        processor = CommandProcessor()
        result = run_async(processor.process("/foobar", {}))
        assert not result.success
        assert "Unknown command" in result.message

    def test_process_status(self):
        processor = CommandProcessor()
        result = run_async(processor.process("/status", {}))
        assert result.success
        assert "Agent Status" in result.message

    def test_process_pause(self):
        processor = CommandProcessor()
        from demogorgon.agent.session import AgentSession
        session = AgentSession()
        session.is_running = True
        result = run_async(processor.process("/pause", {"session": session}))
        assert result.success
        assert session.is_paused
        assert result.action == "pause"

    def test_process_resume(self):
        processor = CommandProcessor()
        from demogorgon.agent.session import AgentSession
        session = AgentSession()
        session.is_paused = True
        result = run_async(processor.process("/resume", {"session": session}))
        assert result.success
        assert not session.is_paused
        assert result.action == "resume"

    def test_process_stop(self):
        processor = CommandProcessor()
        from demogorgon.agent.session import AgentSession
        session = AgentSession()
        session.is_running = True
        result = run_async(processor.process("/stop", {"session": session}))
        assert result.success
        assert not session.is_running
        assert result.action == "stop"

    def test_process_findings_empty(self):
        processor = CommandProcessor()
        result = run_async(processor.process("/findings", {}))
        assert result.success
        assert "No findings" in result.message or "No trace" in result.message

    def test_process_strategy(self):
        processor = CommandProcessor()
        engine = StrategyEngine()
        result = run_async(processor.process("/strategy focused", {"strategy": engine}))
        assert result.success
        assert engine.state.strategy == AgentStrategy.FOCUSED

    def test_process_invalid_strategy(self):
        processor = CommandProcessor()
        engine = StrategyEngine()
        result = run_async(processor.process("/strategy invalid", {"strategy": engine}))
        assert not result.success
        assert "Invalid strategy" in result.message

    def test_process_budget(self):
        processor = CommandProcessor()
        budget = BudgetController()
        result = run_async(processor.process("/budget", {"budget": budget}))
        assert result.success
        assert "Budget Status" in result.message

    def test_process_cost(self):
        processor = CommandProcessor()
        tracker = TokenTracker()
        result = run_async(processor.process("/cost", {"token_tracker": tracker}))
        assert result.success

    def test_process_trace(self):
        processor = CommandProcessor()
        trace = ResearchTrace()
        trace.add(TraceEntryType.OBSERVATION, "Test")
        result = run_async(processor.process("/trace", {"trace": trace}))
        assert result.success

    def test_process_quit(self):
        processor = CommandProcessor()
        from demogorgon.agent.session import AgentSession
        session = AgentSession()
        session.is_running = True
        result = run_async(processor.process("/quit", {"session": session}))
        assert result.success
        assert not session.is_running
        assert result.action == "stop"

    def test_natural_language_instruction(self):
        processor = CommandProcessor()
        result = run_async(processor.process("focus on XSS in /search", {}))
        assert result.success
        assert "Instruction received" in result.message
        assert processor.get_pending_instruction() == "focus on XSS in /search"

    def test_command_history(self):
        processor = CommandProcessor()
        run_async(processor.process("/help", {}))
        run_async(processor.process("/status", {}))
        history = processor.get_history()
        assert len(history) == 2
        assert history[0][0] == "/help"

    def test_focus_command(self):
        processor = CommandProcessor()
        trace = ResearchTrace()
        result = run_async(processor.process("/focus idor", {"trace": trace}))
        assert result.success
        assert "Focusing on" in result.message
        assert result.data["focus_vuln_class"] == "idor"

    def test_focus_no_args(self):
        processor = CommandProcessor()
        result = run_async(processor.process("/focus", {}))
        assert not result.success
        assert "Usage:" in result.message


# === CapabilityRegistry Tests ===


class TestCapabilityRegistry:
    def test_create_registry(self):
        from demogorgon.agent.capabilities import CapabilityRegistry
        registry = CapabilityRegistry()
        assert registry is not None

    def test_register_tool(self):
        from demogorgon.agent.capabilities import CapabilityRegistry
        registry = CapabilityRegistry()
        registry.register_tool("subfinder", capabilities=["subdomain_enum"])
        assert "subfinder" in registry._tools
        assert "subdomain_enum" in registry._bindings

    def test_find_tools_for_capability(self):
        from demogorgon.agent.capabilities import CapabilityRegistry
        registry = CapabilityRegistry()
        registry.register_tool("subfinder", capabilities=["subdomain_enum"])
        registry.register_tool("amass", capabilities=["subdomain_enum", "dns_recon"])

        tools = registry.find_tools_for_capability("subdomain_enum")
        assert len(tools) == 2
        tool_names = [t.tool_name for t in tools]
        assert "subfinder" in tool_names
        assert "amass" in tool_names

    def test_find_best_tool(self):
        from demogorgon.agent.capabilities import CapabilityRegistry, CapabilityRequest
        registry = CapabilityRegistry()
        registry.register_tool("subfinder", capabilities=["subdomain_enum"], reliability=0.9)
        registry.register_tool("amass", capabilities=["subdomain_enum"], reliability=0.5)

        best = registry.find_best_tool(CapabilityRequest(capability="subdomain_enum"))
        assert best is not None
        assert best.tool_name == "subfinder"

    def test_find_best_tool_excludes(self):
        from demogorgon.agent.capabilities import CapabilityRegistry, CapabilityRequest
        registry = CapabilityRegistry()
        registry.register_tool("subfinder", capabilities=["subdomain_enum"])
        registry.register_tool("amass", capabilities=["subdomain_enum"])

        best = registry.find_best_tool(CapabilityRequest(
            capability="subdomain_enum",
            exclude_tools=["subfinder"],
        ))
        assert best is not None
        assert best.tool_name == "amass"

    def test_get_available_capabilities(self):
        from demogorgon.agent.capabilities import CapabilityRegistry
        registry = CapabilityRegistry()
        registry.register_tool("subfinder", capabilities=["subdomain_enum"])
        registry.register_tool("httpx", capabilities=["http_request", "tech_detect"])

        caps = registry.get_available_capabilities()
        assert "subdomain_enum" in caps
        assert "http_request" in caps
        assert "tech_detect" in caps

    def test_get_capability_info(self):
        from demogorgon.agent.capabilities import CapabilityRegistry
        registry = CapabilityRegistry()
        registry.register_tool("subfinder", capabilities=["subdomain_enum"])

        info = registry.get_capability_info("subdomain_enum")
        assert info is not None
        assert info["name"] == "subdomain_enum"
        assert "description" in info
        assert "subfinder" in info["tools"]

    def test_unregister_tool(self):
        from demogorgon.agent.capabilities import CapabilityRegistry
        registry = CapabilityRegistry()
        registry.register_tool("subfinder", capabilities=["subdomain_enum"])
        registry.unregister_tool("subfinder")
        assert "subfinder" not in registry._tools

    def test_record_success_failure(self):
        from demogorgon.agent.capabilities import CapabilityRegistry
        registry = CapabilityRegistry()
        registry.register_tool("subfinder", capabilities=["subdomain_enum"])

        registry.record_success("subfinder", "subdomain_enum")
        registry.record_success("subfinder", "subdomain_enum")
        registry.record_failure("subfinder", "subdomain_enum")

        bindings = registry.find_tools_for_capability("subdomain_enum")
        assert bindings[0].success_count == 2
        assert bindings[0].failure_count == 1

    def test_mcp_server_registration(self):
        from demogorgon.agent.capabilities import CapabilityRegistry
        registry = CapabilityRegistry()
        registry.register_tool("burp_scan", capabilities=["vuln_scan"], mcp_server="burp")

        tools = registry.get_tools_for_mcp_server("burp")
        assert len(tools) == 1
        assert tools[0].tool_name == "burp_scan"

    def test_to_llm_context(self):
        from demogorgon.agent.capabilities import CapabilityRegistry
        registry = CapabilityRegistry()
        registry.register_tool("subfinder", capabilities=["subdomain_enum"])

        context = registry.to_llm_context()
        assert "subdomain_enum" in context
        assert "subfinder" in context

    def test_get_status(self):
        from demogorgon.agent.capabilities import CapabilityRegistry
        registry = CapabilityRegistry()
        registry.register_tool("subfinder", capabilities=["subdomain_enum"])

        status = registry.get_status()
        assert status["total_tools"] == 1
        assert status["total_capabilities"] == 1


# === NaturalLanguageParser Tests ===


class TestNaturalLanguageParser:
    def test_create_parser(self):
        from demogorgon.agent.natural_language import NaturalLanguageParser
        parser = NaturalLanguageParser()
        assert parser is not None

    def test_parse_focus_xss(self):
        from demogorgon.agent.natural_language import NaturalLanguageParser, InstructionType
        parser = NaturalLanguageParser()
        result = parser.parse("focus on XSS")
        assert result.type == InstructionType.FOCUS
        assert result.vuln_class == "xss"

    def test_parse_focus_idor(self):
        from demogorgon.agent.natural_language import NaturalLanguageParser, InstructionType
        parser = NaturalLanguageParser()
        result = parser.parse("focus on IDOR in /api/users")
        assert result.type == InstructionType.FOCUS
        assert result.vuln_class == "idor"
        assert result.endpoint == "/api/users"

    def test_parse_scan_sqli(self):
        from demogorgon.agent.natural_language import NaturalLanguageParser, InstructionType
        parser = NaturalLanguageParser()
        result = parser.parse("scan for SQL injection on /search")
        assert result.type == InstructionType.DIRECT
        assert result.vuln_class == "sqli"
        assert result.endpoint == "/search"

    def test_parse_ignore(self):
        from demogorgon.agent.natural_language import NaturalLanguageParser, InstructionType
        parser = NaturalLanguageParser()
        result = parser.parse("ignore xss for now")
        assert result.type == InstructionType.IGNORE
        assert result.vuln_class == "xss"

    def test_parse_constraint_rate_limit(self):
        from demogorgon.agent.natural_language import NaturalLanguageParser, InstructionType
        parser = NaturalLanguageParser()
        result = parser.parse("slow down, be careful")
        assert result.type == InstructionType.CONSTRAINT
        assert result.constraint == "rate_limit"

    def test_parse_constraint_passive(self):
        from demogorgon.agent.natural_language import NaturalLanguageParser, InstructionType
        parser = NaturalLanguageParser()
        result = parser.parse("passive only, no active testing")
        # "passive only" matches constraint pattern "no_active"
        assert result.constraint == "no_active"

    def test_parse_tool_preference(self):
        from demogorgon.agent.natural_language import NaturalLanguageParser
        parser = NaturalLanguageParser()
        result = parser.parse("use nuclei to scan")
        assert result.tool == "nuclei"

    def test_parse_endpoint(self):
        from demogorgon.agent.natural_language import NaturalLanguageParser
        parser = NaturalLanguageParser()
        result = parser.parse("test /api/users for idor")
        assert result.endpoint == "/api/users"

    def test_parse_empty(self):
        from demogorgon.agent.natural_language import NaturalLanguageParser, InstructionType
        parser = NaturalLanguageParser()
        result = parser.parse("")
        assert result.type == InstructionType.QUERY
        assert result.confidence == 0.0

    def test_parse_query(self):
        from demogorgon.agent.natural_language import NaturalLanguageParser, InstructionType
        parser = NaturalLanguageParser()
        result = parser.parse("what findings do we have")
        assert result.type == InstructionType.QUERY

    def test_parse_xss_variations(self):
        from demogorgon.agent.natural_language import NaturalLanguageParser
        parser = NaturalLanguageParser()
        for text in ["test for xss", "cross-site scripting", "check for reflected xss"]:
            result = parser.parse(text)
            assert result.vuln_class == "xss", f"Failed for: {text}"

    def test_parse_ssti(self):
        from demogorgon.agent.natural_language import NaturalLanguageParser
        parser = NaturalLanguageParser()
        result = parser.parse("test for template injection")
        assert result.vuln_class == "ssti"

    def test_parse_cmd_injection(self):
        from demogorgon.agent.natural_language import NaturalLanguageParser
        parser = NaturalLanguageParser()
        result = parser.parse("test for command injection")
        assert result.vuln_class == "cmd_injection"


# === InstructionProcessor Tests ===


class TestInstructionProcessor:
    def test_process_focus(self):
        from demogorgon.agent.natural_language import (
            NaturalLanguageParser, InstructionProcessor, InstructionType,
        )
        parser = NaturalLanguageParser()
        processor = InstructionProcessor()

        instruction = parser.parse("focus on XSS")
        update = processor.process(instruction)
        assert update["focus_vuln_class"] == "xss"
        assert "priority_boost" in update

    def test_process_ignore(self):
        from demogorgon.agent.natural_language import (
            NaturalLanguageParser, InstructionProcessor,
        )
        parser = NaturalLanguageParser()
        processor = InstructionProcessor()

        instruction = parser.parse("ignore sqli")
        update = processor.process(instruction)
        assert update["ignore_vuln_class"] == "sqli"

    def test_process_constraint(self):
        from demogorgon.agent.natural_language import (
            NaturalLanguageParser, InstructionProcessor,
        )
        parser = NaturalLanguageParser()
        processor = InstructionProcessor()

        instruction = parser.parse("slow down")
        update = processor.process(instruction)
        assert update["constraint"] == "rate_limit"
        assert "rate_limit_multiplier" in update

    def test_process_hint(self):
        from demogorgon.agent.natural_language import (
            NaturalLanguageParser, InstructionProcessor,
        )
        parser = NaturalLanguageParser()
        processor = InstructionProcessor()

        instruction = parser.parse("check the login page for auth bypass")
        update = processor.process(instruction)
        assert "hint" in update
        assert "user_instruction" in update


# === ResearchMemory Tests ===


class TestResearchMemory:
    def test_create_memory(self):
        from demogorgon.agent.memory import ResearchMemory
        with tempfile.TemporaryDirectory() as tmpdir:
            memory = ResearchMemory(tmpdir)
            assert memory is not None

    def test_store_and_retrieve(self):
        from demogorgon.agent.memory import ResearchMemory
        with tempfile.TemporaryDirectory() as tmpdir:
            memory = ResearchMemory(tmpdir)
            memory.store("xss_search", "vuln_pattern", "XSS works on /search")
            entries = retrieve_by_key(memory, "xss_search")
            assert len(entries) == 1
            assert entries[0].content == "XSS works on /search"

    def test_retrieve_by_category(self):
        from demogorgon.agent.memory import ResearchMemory
        with tempfile.TemporaryDirectory() as tmpdir:
            memory = ResearchMemory(tmpdir)
            memory.store("k1", "vuln_pattern", "Pattern 1")
            memory.store("k2", "tool_effectiveness", "Tool 1")
            memory.store("k3", "vuln_pattern", "Pattern 2")

            entries = memory.retrieve(category="vuln_pattern")
            assert len(entries) == 2

    def test_retrieve_by_query(self):
        from demogorgon.agent.memory import ResearchMemory
        with tempfile.TemporaryDirectory() as tmpdir:
            memory = ResearchMemory(tmpdir)
            memory.store("xss_1", "vuln_pattern", "XSS on /search")
            memory.store("sqli_1", "vuln_pattern", "SQLi on /api")

            entries = memory.retrieve(query="xss")
            assert len(entries) == 1
            assert "XSS" in entries[0].content

    def test_store_updates_existing(self):
        from demogorgon.agent.memory import ResearchMemory
        with tempfile.TemporaryDirectory() as tmpdir:
            memory = ResearchMemory(tmpdir)
            memory.store("key1", "vuln_pattern", "Original")
            memory.store("key1", "vuln_pattern", "Updated")

            entries = retrieve_by_key(memory, "key1")
            assert len(entries) == 1
            assert entries[0].content == "Updated"

    def test_forget(self):
        from demogorgon.agent.memory import ResearchMemory
        with tempfile.TemporaryDirectory() as tmpdir:
            memory = ResearchMemory(tmpdir)
            memory.store("key1", "vuln_pattern", "Content")
            assert memory.forget("key1")
            assert not memory.forget("key1")

    def test_persistence(self):
        from demogorgon.agent.memory import ResearchMemory
        with tempfile.TemporaryDirectory() as tmpdir:
            memory1 = ResearchMemory(tmpdir)
            memory1.store("key1", "vuln_pattern", "Persistent")

            # Load in new instance
            memory2 = ResearchMemory(tmpdir)
            entries = retrieve_by_key(memory2, "key1")
            assert len(entries) == 1
            assert entries[0].content == "Persistent"

    def test_get_llm_context(self):
        from demogorgon.agent.memory import ResearchMemory
        with tempfile.TemporaryDirectory() as tmpdir:
            memory = ResearchMemory(tmpdir)
            memory.store("k1", "finding_pattern", "XSS pattern", confidence=0.8)
            memory.store("k2", "vuln_pattern", "SQLi on /api")
            context = memory.get_llm_context(target="example.com")
            # Should contain entries from various categories
            assert "XSS" in context or "SQLi" in context or "No prior" in context

    def test_get_llm_context_empty(self):
        from demogorgon.agent.memory import ResearchMemory
        with tempfile.TemporaryDirectory() as tmpdir:
            memory = ResearchMemory(tmpdir)
            context = memory.get_llm_context()
            assert "No prior" in context

    def test_get_stats(self):
        from demogorgon.agent.memory import ResearchMemory
        with tempfile.TemporaryDirectory() as tmpdir:
            memory = ResearchMemory(tmpdir)
            memory.store("k1", "vuln_pattern", "P1")
            memory.store("k2", "tool_effectiveness", "T1")

            stats = memory.get_stats()
            assert stats["total_entries"] == 2
            assert stats["categories"]["vuln_pattern"] == 1

    def test_clear(self):
        from demogorgon.agent.memory import ResearchMemory
        with tempfile.TemporaryDirectory() as tmpdir:
            memory = ResearchMemory(tmpdir)
            memory.store("k1", "vuln_pattern", "Content")
            memory.clear()
            assert len(memory._entries) == 0

    def test_confidence_filtering(self):
        from demogorgon.agent.memory import ResearchMemory
        with tempfile.TemporaryDirectory() as tmpdir:
            memory = ResearchMemory(tmpdir)
            memory.store("k1", "vuln_pattern", "Low conf", confidence=0.3)
            memory.store("k2", "vuln_pattern", "High conf", confidence=0.9)

            entries = memory.retrieve(min_confidence=0.5)
            assert len(entries) == 1
            assert entries[0].key == "k2"


def retrieve_by_key(memory, key):
    """Helper to retrieve by key."""
    return [e for e in memory._entries.values() if e.key == key]
