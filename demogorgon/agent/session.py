"""Agent Session — canonical session state for the interactive agent.

The AgentSession is the single source of truth for an agent run.
It owns the engagement, state, event bus, and coordinates all components.
It does NOT duplicate what Engagement/StateManager already provide.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Awaitable

from .events import EventBus, EventType
from .tokens import TokenTracker
from .budget import BudgetController, BudgetLimits
from .trace import ResearchTrace, TraceEntryType
from .strategies import StrategyEngine, AgentStrategy
from .commands import CommandProcessor

logger = logging.getLogger(__name__)


class SessionStatus(Enum):
    """Agent session status."""
    INITIALIZING = "initializing"
    READY = "ready"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPED = "stopped"
    ERROR = "error"
    COMPLETED = "completed"


@dataclass
class SessionConfig:
    """Configuration for an agent session."""
    target: str = ""
    program_text: str = ""
    workspace_dir: str = ""

    # LLM
    provider: str = ""
    model: str = ""
    api_key: str = ""
    base_url: str = ""

    # Budget
    max_cycles: int = 100
    max_cost_usd: float = 5.00
    max_requests: int = 500
    max_tokens: int = 500_000
    max_duration_seconds: float = 3600.0

    # Safety
    approval_level: str = "none"  # none, required, for_exploits
    rate_limit: float = 2.0

    # Research
    max_findings: int = 50
    checkpoint_interval: int = 10

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "provider": self.provider,
            "model": self.model,
            "max_cycles": self.max_cycles,
            "max_cost_usd": self.max_cost_usd,
            "max_requests": self.max_requests,
            "max_tokens": self.max_tokens,
            "approval_level": self.approval_level,
            "rate_limit": self.rate_limit,
        }


class AgentSession:
    """Canonical session state for the interactive agent.

    Owns the event bus, token tracker, budget, trace, strategy engine,
    and command processor. Coordinates with existing Engagement/StateManager
    without duplicating them.

    Usage:
        session = AgentSession(config=SessionConfig(target="https://example.com"))
        await session.initialize()
        await session.run()
    """

    def __init__(self, config: SessionConfig | None = None):
        self.config = config or SessionConfig()

        # Session identity
        import uuid
        self.session_id: str = str(uuid.uuid4())[:12]

        # Core state
        self.status = SessionStatus.INITIALIZING
        self.target = self.config.target
        self.is_running = False
        self.is_paused = False
        self.start_time = 0.0

        # Scope
        self.scope_assets: list[dict[str, Any]] = []
        self.out_of_scope: list[str] = []
        self.restrictions: list[str] = []

        # Workspace (must be set before subsystems that depend on it)
        self.workspace_dir = self.config.workspace_dir
        if not self.workspace_dir and self.target:
            safe_name = self.target.replace("https://", "").replace("http://", "").replace("/", "_")[:50]
            self.workspace_dir = os.path.join(os.getcwd(), "workspaces", safe_name)

        # Subsystems
        self.events = EventBus()
        self.token_tracker = TokenTracker()
        self.budget = BudgetController(BudgetLimits(
            max_cycles=self.config.max_cycles,
            max_cost_usd=self.config.max_cost_usd,
            max_requests=self.config.max_requests,
            max_tokens=self.config.max_tokens,
            max_findings=self.config.max_findings,
            max_duration_seconds=self.config.max_duration_seconds,
        ))
        self.trace = ResearchTrace(max_entries=200)
        self.strategy = StrategyEngine()
        self.commands = CommandProcessor()

        # Phase 11.1 — agent subsystems for ResearchLoop integration
        from .capabilities import CapabilityRegistry
        from .memory import ResearchMemory
        self.capability_registry = CapabilityRegistry()
        self.research_memory = ResearchMemory(workspace_dir=self.workspace_dir)
        self.application_model = None  # Set during initialize if needed

        # Findings / chains (accumulated during research)
        self.findings: list[dict[str, Any]] = []
        self.chains: list[dict[str, Any]] = []
        self.evidence_count: int = 0

        # Engagement reference (set during initialize)
        self._engagement = None
        self._state_manager = None

    async def initialize(self) -> None:
        """Initialize the session and all subsystems."""
        self.start_time = time.time()
        self.budget.start(self.start_time)

        # Create workspace
        if self.workspace_dir:
            os.makedirs(self.workspace_dir, exist_ok=True)

        # Register built-in tool capabilities
        self._register_builtin_tools()

        # Try to initialize MCP manager
        self._mcp_manager = None
        try:
            from .mcp import MCPManager, MCPServerConfig, DEFAULT_SERVERS
            self._mcp_manager = MCPManager()
            for name, config in DEFAULT_SERVERS.items():
                self._mcp_manager.add_server(name, config)
        except Exception:
            pass

        # Emit session start
        await self.events.emit(
            EventType.SESSION_START,
            {"target": self.target, "config": self.config.to_dict()},
            source="session",
        )

        self.status = SessionStatus.READY
        self.is_running = True

        logger.info(f"Agent session initialized: target={self.target}")

    def _register_builtin_tools(self) -> None:
        """Register built-in security tool capabilities."""
        import shutil
        tools = {
            "subfinder": ["subdomain_enum"],
            "httpx": ["http_request", "tech_detect"],
            "katana": ["url_discovery", "crawling"],
            "ffuf": ["dir_scan", "param_fuzz"],
            "nuclei": ["vuln_scan"],
            "naabu": ["port_scan"],
            "nmap": ["port_scan", "dns_recon"],
            "dnsx": ["dns_recon"],
            "gau": ["url_discovery"],
            "dalfo": ["url_discovery"],
        }
        for tool_name, capabilities in tools.items():
            if shutil.which(tool_name):
                self.capability_registry.register_tool(
                    tool_name,
                    capabilities=capabilities,
                    reliability=0.7,
                    speed=0.6,
                )

        # Register HTTP as always available
        self.capability_registry.register_tool(
            "http_executor",
            capabilities=["http_request", "http_method_test"],
            reliability=0.9,
            speed=0.8,
        )

        # Register browser as always available
        self.capability_registry.register_tool(
            "browser",
            capabilities=["browser_render", "browser_interact"],
            reliability=0.8,
            speed=0.5,
        )

    async def run(self) -> dict[str, Any]:
        """Run the agent's main loop.

        This is the core observe→reason→act→evaluate cycle.
        The loop continues until budget exhausted, user stops, or max iterations.
        """
        await self.events.emit(EventType.STATUS_CHANGE, {"status": "running"}, source="session")
        self.status = SessionStatus.RUNNING

        cycle = 0
        try:
            while self.is_running:
                # Check if paused
                if self.is_paused:
                    await self.events.emit(EventType.STATUS_CHANGE, {"status": "paused"}, source="session")
                    await asyncio.sleep(1.0)
                    continue

                cycle += 1
                self.budget.record_cycle()

                # Check budget
                should_stop, reason = self.budget.should_stop()
                if should_stop:
                    await self.events.emit(EventType.BUDGET_EXCEEDED, {"reason": reason}, source="session")
                    self.trace.add(TraceEntryType.BUDGET_CHECK, f"Budget exceeded: {reason}")
                    break

                # Execute one cycle
                await self._run_cycle(cycle)

                # Check for stagnation/loops
                is_loop, pattern = self.trace.check_for_loops()
                if is_loop:
                    await self.events.emit(
                        EventType.WARNING,
                        {"message": f"Loop detected: {pattern}"},
                        source="session",
                    )
                    self.strategy.state.stagnation_count += 1

                # Emit progress
                await self._emit_progress(cycle)

                # Auto-save every 5 cycles
                if cycle % 5 == 0:
                    self.auto_save()

        except KeyboardInterrupt:
            await self.events.emit(EventType.SESSION_END, {"reason": "user_interrupt"}, source="session")
        except Exception as e:
            self.status = SessionStatus.ERROR
            await self.events.emit(EventType.SESSION_ERROR, {"error": str(e)}, source="session")
            logger.error(f"Session error: {e}")
        finally:
            self.is_running = False
            self.status = SessionStatus.COMPLETED
            await self.events.emit(EventType.SESSION_END, {"cycles": cycle}, source="session")

        return self._build_summary()

    async def _run_cycle(self, cycle: int) -> None:
        """Execute a single research cycle.

        This is the core observe→reason→act→evaluate loop.
        It bridges to existing components (ResearchBrain, ActionGateway, etc.).
        """
        await self.events.emit(EventType.AGENT_THINKING, {"cycle": cycle}, source="session")

        # 1. Update strategy
        strategy_ctx = self._build_strategy_context()
        self.strategy.evaluate(strategy_ctx)

        # 2. Build context for LLM
        context = self._build_llm_context(cycle)

        # 3. Emit decision start
        await self.events.emit(
            EventType.DECISION_START,
            {"cycle": cycle, "strategy": self.strategy.state.strategy.value},
            source="session",
        )

        # 4. The actual LLM reasoning and tool execution happens here
        #    This is delegated to the existing ResearchLoop/ResearchBrain
        #    through the runner integration. The session just tracks state.

        # 5. Record trace
        self.trace.add(
            TraceEntryType.DECISION,
            f"Cycle {cycle}: strategy={self.strategy.state.strategy.value}",
            iteration=cycle,
        )

        # 6. Emit decision complete
        await self.events.emit(
            EventType.DECISION_COMPLETE,
            {"cycle": cycle},
            source="session",
        )

    def _build_strategy_context(self) -> dict[str, Any]:
        """Build context for strategy evaluation."""
        return {
            "endpoints_discovered": len(self.scope_assets),
            "findings": len(self.findings),
            "validated_findings": sum(1 for f in self.findings if f.get("validated")),
            "false_positives": sum(1 for f in self.findings if f.get("false_positive")),
            "evidence_count": self.evidence_count,
            "chains": len(self.chains),
            "consecutive_failures": self.strategy.state.stagnation_count,
            "tested_vuln_classes": [],
        }

    def _build_llm_context(self, cycle: int) -> dict[str, Any]:
        """Build context dict for LLM reasoning."""
        return {
            "target": self.target,
            "cycle": cycle,
            "strategy": self.strategy.state.strategy.value,
            "strategy_reason": self.strategy.state.reason,
            "findings": self.findings[-10:],
            "trace_summary": self.trace.get_llm_summary(max_entries=10),
            "budget": self.budget.get_usage_display(),
            "tokens": self.token_tracker.live_display,
        }

    async def _emit_progress(self, cycle: int) -> None:
        """Emit a progress update event."""
        await self.events.emit(
            EventType.PROGRESS_UPDATE,
            {
                "cycle": cycle,
                "strategy": self.strategy.state.strategy.value,
                "findings": len(self.findings),
                "budget": self.budget.get_usage_display(),
                "tokens": self.token_tracker.live_display,
            },
            source="session",
        )

    def _build_summary(self) -> dict[str, Any]:
        """Build session summary."""
        duration = time.time() - self.start_time if self.start_time else 0
        return {
            "target": self.target,
            "status": self.status.value,
            "duration": duration,
            "cycles": self.strategy.state.total_cycles,
            "findings": len(self.findings),
            "chains": len(self.chains),
            "evidence": self.evidence_count,
            "tokens": self.token_tracker.to_dict(),
            "budget": self.budget.to_dict(),
            "strategy": self.strategy.to_dict(),
            "workspace": self.workspace_dir,
        }

    async def pause(self) -> None:
        """Pause the session."""
        self.is_paused = True
        self.status = SessionStatus.PAUSED
        await self.events.emit(EventType.STATUS_CHANGE, {"status": "paused"}, source="session")

    async def resume(self) -> None:
        """Resume the session."""
        self.is_paused = False
        self.status = SessionStatus.RUNNING
        await self.events.emit(EventType.STATUS_CHANGE, {"status": "running"}, source="session")

    async def stop(self) -> None:
        """Stop the session."""
        self.is_running = False
        self.is_paused = False
        self.status = SessionStatus.STOPPED
        await self.events.emit(EventType.SESSION_END, {"reason": "user_stop"}, source="session")

    def record_finding(self, finding: dict[str, Any]) -> None:
        """Record a finding."""
        self.findings.append(finding)
        self.budget.record_finding()
        self.strategy.record_finding()
        self.trace.add(
            TraceEntryType.FINDING,
            finding.get("title", "Untitled finding"),
            data=finding,
        )

    def record_evidence(self, count: int = 1) -> None:
        """Record evidence collected."""
        self.evidence_count += count
        self.strategy.record_evidence()

    def record_llm_call(self, provider: str, model: str, prompt_tokens: int,
                        completion_tokens: int, latency_ms: float = 0.0) -> None:
        """Record an LLM call's token usage."""
        usage = self.token_tracker.record_call(
            provider=provider,
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            latency_ms=latency_ms,
        )
        self.budget.record_cost(usage.cost_usd)
        self.budget.record_tokens(usage.total_tokens)
        self.budget.record_request()

    def get_state(self) -> dict[str, Any]:
        """Get the full session state for command processing."""
        return {
            "session": self,
            "budget": self.budget,
            "trace": self.trace,
            "strategy": self.strategy,
            "token_tracker": self.token_tracker,
            "findings": self.findings,
            "chains": self.chains,
        }

    def save_state(self) -> str:
        """Save session state to disk for crash recovery."""
        if not self.workspace_dir:
            return ""

        os.makedirs(self.workspace_dir, exist_ok=True)
        state_path = os.path.join(self.workspace_dir, "agent_state.json")
        import json
        state = {
            "session_id": self.session_id,
            "target": self.target,
            "status": self.status.value,
            "start_time": self.start_time,
            "is_running": self.is_running,
            "is_paused": self.is_paused,
            "findings": self.findings,
            "chains": self.chains,
            "evidence_count": self.evidence_count,
            "strategy": self.strategy.to_dict(),
            "budget": self.budget.to_dict(),
            "tokens": self.token_tracker.to_dict(),
            "config": self.config.to_dict(),
            "scope_assets": self.scope_assets,
            "out_of_scope": self.out_of_scope,
            "restrictions": self.restrictions,
        }
        Path(state_path).write_text(json.dumps(state, indent=2))

        # Save trace
        trace_path = os.path.join(self.workspace_dir, "agent_trace.json")
        self.trace.save(trace_path)

        # Save findings separately for easy access
        if self.findings:
            findings_path = os.path.join(self.workspace_dir, "findings.json")
            Path(findings_path).write_text(json.dumps(self.findings, indent=2))

        return state_path

    @classmethod
    def load_state(cls, workspace_dir: str) -> AgentSession:
        """Load session state from disk for crash recovery."""
        import json
        state_path = os.path.join(workspace_dir, "agent_state.json")
        if not os.path.exists(state_path):
            raise FileNotFoundError(f"No saved state at {state_path}")

        data = json.loads(Path(state_path).read_text())
        config = SessionConfig(**data.get("config", {}))
        session = cls(config=config)
        session.session_id = data.get("session_id", session.session_id)
        session.workspace_dir = workspace_dir
        session.target = data.get("target", "")
        session.status = SessionStatus(data.get("status", "ready"))
        session.start_time = data.get("start_time", 0)
        session.is_running = data.get("is_running", False)
        session.is_paused = data.get("is_paused", False)
        session.findings = data.get("findings", [])
        session.chains = data.get("chains", [])
        session.evidence_count = data.get("evidence_count", 0)
        session.scope_assets = data.get("scope_assets", [])
        session.out_of_scope = data.get("out_of_scope", [])
        session.restrictions = data.get("restrictions", [])

        if "strategy" in data:
            session.strategy.load_state(data["strategy"])

        # Load trace
        trace_path = os.path.join(workspace_dir, "agent_trace.json")
        if os.path.exists(trace_path):
            session.trace = ResearchTrace.load(trace_path)

        return session

    @staticmethod
    def list_saved_sessions(workspaces_dir: str = "") -> list[dict[str, Any]]:
        """List all saved sessions from workspaces directory."""
        import json
        base = workspaces_dir or os.path.join(os.getcwd(), "workspaces")
        if not os.path.exists(base):
            return []

        sessions = []
        for name in os.listdir(base):
            state_path = os.path.join(base, name, "agent_state.json")
            if os.path.exists(state_path):
                try:
                    data = json.loads(Path(state_path).read_text())
                    sessions.append({
                        "session_id": data.get("session_id", ""),
                        "target": data.get("target", name),
                        "status": data.get("status", "unknown"),
                        "findings": len(data.get("findings", [])),
                        "evidence": data.get("evidence_count", 0),
                        "workspace": os.path.join(base, name),
                    })
                except Exception:
                    pass

        return sessions

    def auto_save(self) -> None:
        """Auto-save state (called periodically during research)."""
        try:
            self.save_state()
        except Exception as e:
            logger.warning(f"Auto-save failed: {e}")
