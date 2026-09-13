"""Terminal UI — live agent display with Rich Live.

Uses Rich Live for in-place updates. The terminal shows:
- Persistent header panel (target, model, phase, status)
- Live status bar (strategy, tokens, budget)
- Event stream (scrolling, newest at bottom)
- Tool execution progress
- Findings as they appear

Events update the display in-place without scrolling new lines.
"""

from __future__ import annotations

import asyncio
import collections
import sys
import time
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich.layout import Layout
from rich.align import Align
from rich.columns import Columns

from .events import EventBus, EventType, AgentEvent
from .tokens import TokenTracker
from .budget import BudgetController
from .trace import ResearchTrace, TraceEntryType
from .strategies import StrategyEngine
from .commands import CommandProcessor

console = Console()

# Max events to show in the live feed
MAX_LIVE_EVENTS = 30


class TerminalUI:
    """Live terminal UI with Rich Live for in-place updates.

    Architecture:
    - EventBus handlers update internal state
    - A background task refreshes the Live display every 0.5s
    - The Live display shows header + status bar + event feed + findings
    - Significant events (findings, errors) also print immediately
    """

    def __init__(
        self,
        event_bus: EventBus,
        token_tracker: TokenTracker,
        budget: BudgetController,
        trace: ResearchTrace,
        strategy: StrategyEngine,
        commands: CommandProcessor,
        session: Any = None,
    ):
        self.event_bus = event_bus
        self.token_tracker = token_tracker
        self.budget = budget
        self.trace = trace
        self.strategy = strategy
        self.commands = commands
        self.session = session

        self._running = False
        self._event_task = None
        self._live: Live | None = None

        # Live state
        self._events: collections.deque = collections.deque(maxlen=MAX_LIVE_EVENTS)
        self._status = "initializing"
        self._cycle = 0
        self._tool_active = ""
        self._last_thinking = ""

        # Register event handlers
        self._register_handlers()

    def _register_handlers(self):
        """Register event handlers for UI rendering."""
        self.event_bus.on(EventType.SESSION_START, self._on_session_start)
        self.event_bus.on(EventType.SESSION_END, self._on_session_end)
        self.event_bus.on(EventType.STATUS_CHANGE, self._on_status_change)
        self.event_bus.on(EventType.PROGRESS_UPDATE, self._on_progress)
        self.event_bus.on(EventType.STRATEGY_CHANGE, self._on_strategy_change)
        self.event_bus.on(EventType.DECISION_START, self._on_decision_start)
        self.event_bus.on(EventType.DECISION_COMPLETE, self._on_decision_complete)
        self.event_bus.on(EventType.TOOL_EXECUTE, self._on_tool_execute)
        self.event_bus.on(EventType.TOOL_RESULT, self._on_tool_result)
        self.event_bus.on(EventType.TOOL_ERROR, self._on_tool_error)
        self.event_bus.on(EventType.FINDING, self._on_finding)
        self.event_bus.on(EventType.FINDING_VALIDATED, self._on_finding_validated)
        self.event_bus.on(EventType.EVIDENCE_COLLECTED, self._on_evidence)
        self.event_bus.on(EventType.SAFETY_BLOCK, self._on_safety_block)
        self.event_bus.on(EventType.HITL_REQUEST, self._on_hitl_request)
        self.event_bus.on(EventType.BUDGET_WARNING, self._on_budget_warning)
        self.event_bus.on(EventType.BUDGET_EXCEEDED, self._on_budget_exceeded)
        self.event_bus.on(EventType.LLM_REQUEST, self._on_llm_request)
        self.event_bus.on(EventType.LLM_RESPONSE, self._on_llm_response)
        self.event_bus.on(EventType.LLM_ERROR, self._on_llm_error)
        self.event_bus.on(EventType.AGENT_THINKING, self._on_thinking)
        self.event_bus.on(EventType.ERROR, self._on_error)
        self.event_bus.on(EventType.WARNING, self._on_warning)

    def _add_event(self, icon: str, text: str, style: str = ""):
        """Add an event to the live feed."""
        ts = time.strftime("%H:%M:%S")
        self._events.append((ts, icon, text, style))

    async def start(self):
        """Start the UI with Rich Live display."""
        self._running = True
        self._live = Live(
            self._build_layout(),
            console=console,
            refresh_per_second=2,
            transient=False,
        )
        self._live.start()
        self._event_task = asyncio.create_task(self._refresh_loop())

    async def stop(self):
        """Stop the UI."""
        self._running = False
        if self._event_task:
            self._event_task.cancel()
        if self._live:
            self._live.stop()
            self._live = None

    async def _refresh_loop(self):
        """Periodically refresh the Live display."""
        while self._running:
            await asyncio.sleep(0.5)
            if self._live:
                self._live.update(self._build_layout())

    def _build_layout(self) -> Panel:
        """Build the complete live layout."""
        # Header panel
        header = self._build_header()

        # Status bar
        status_bar = self._build_status_bar()

        # Event feed
        event_feed = self._build_event_feed()

        # Combine into a single panel
        parts = [header, status_bar, "", event_feed]

        return Panel(
            "\n".join(parts),
            title="[bold cyan]DEMOGOORGON[/bold cyan]",
            border_style="cyan",
            subtitle=f"[dim]{self._status}[/dim]",
            padding=(0, 1),
        )

    def _build_header(self) -> str:
        """Build the header section."""
        if not self.session:
            return "[dim]No session[/dim]"

        target = self.session.target or "—"
        provider = self.session.config.provider or "?"
        model = self.session.config.model or "?"
        strategy = self.strategy.state.strategy.value.upper() if self.strategy else "?"
        status = "RUNNING" if self.session.is_running and not self.session.is_paused else "PAUSED" if self.session.is_paused else "STOPPED"

        return (
            f"  [bold]Target:[/bold] {target}  |  "
            f"[bold]Provider:[/bold] {provider}  |  "
            f"[bold]Model:[/bold] {model}\n"
            f"  [bold]Phase:[/bold] [cyan]{strategy}[/cyan]  |  "
            f"[bold]Status:[/bold] {status}  |  "
            f"[bold]Cycle:[/bold] {self._cycle}"
        )

    def _build_status_bar(self) -> str:
        """Build the status bar section."""
        parts = []

        if self.strategy:
            s = self.strategy.state
            parts.append(f"[cyan]{s.strategy.value.upper()}[/cyan] ({s.cycles_in_strategy}c)")

        if self.token_tracker:
            parts.append(self.token_tracker.live_display)

        if self.budget:
            parts.append(self.budget.get_usage_display())

        if self._tool_active:
            parts.append(f"[magenta]▶ {self._tool_active}[/magenta]")

        bar = " │ ".join(parts)
        return f"  {bar}"

    def _build_event_feed(self) -> str:
        """Build the event feed section."""
        if not self._events:
            return "  [dim]Waiting for research to begin...[/dim]"

        lines = []
        for ts, icon, text, style in self._events:
            style_prefix = f"[{style}]" if style else ""
            style_suffix = f"[/{style}]" if style else ""
            lines.append(f"  [dim]{ts}[/dim] {icon} {style_prefix}{text}{style_suffix}")

        return "\n".join(lines)

    def _build_findings_summary(self) -> str:
        """Build a compact findings summary."""
        findings = self.trace.get_by_type(TraceEntryType.FINDING, limit=5)
        if not findings:
            return ""

        lines = ["  [bold green]Findings:[/bold green]"]
        for f in findings:
            severity = f.data.get("severity", "?")
            sev_color = {"critical": "red", "high": "red", "medium": "yellow", "low": "cyan"}.get(severity, "white")
            lines.append(f"    [{sev_color}]●[/{sev_color}] {f.content[:60]}")
        return "\n".join(lines)

    # ── Event Handlers ────────────────────────────────────────

    async def _on_session_start(self, event: AgentEvent):
        target = event.data.get("target", "unknown")
        self._status = "running"
        self._add_event("✓", f"Session started — target: {target}", "green")
        # Print banner once (before Live takes over)
        self.print_banner()

    async def _on_session_end(self, event: AgentEvent):
        reason = event.data.get("reason", "unknown")
        self._status = f"stopped ({reason})"
        self._add_event("■", f"Session ended — {reason}", "yellow")

    async def _on_status_change(self, event: AgentEvent):
        status = event.data.get("status", "unknown")
        self._status = status

    async def _on_progress(self, event: AgentEvent):
        self._cycle = event.data.get("cycle", self._cycle)
        findings = event.data.get("findings", 0)
        self._add_event("→", f"Cycle {self._cycle} | Findings: {findings}", "dim")

    async def _on_strategy_change(self, event: AgentEvent):
        old = event.data.get("from", "?")
        new = event.data.get("to", "?")
        reason = event.data.get("reason", "")
        self._add_event("◆", f"Strategy: {old} → {new} ({reason})", "cyan")

    async def _on_decision_start(self, event: AgentEvent):
        self._add_event("◦", "Deciding next action...", "dim")

    async def _on_decision_complete(self, event: AgentEvent):
        action = event.data.get("action", "")
        target = event.data.get("target", "")
        if action:
            self._add_event("→", f"{action} {target[:50]}", "bold")

    async def _on_tool_execute(self, event: AgentEvent):
        tool = event.data.get("tool", "unknown")
        target = event.data.get("target", "")
        self._tool_active = tool
        self._add_event("▶", f"{tool} → {target[:60]}", "magenta")

    async def _on_tool_result(self, event: AgentEvent):
        tool = event.data.get("tool", "unknown")
        success = event.data.get("success", False)
        icon = "✓" if success else "✗"
        style = "green" if success else "red"
        self._add_event(icon, f"{tool} complete", style)
        self._tool_active = ""

    async def _on_tool_error(self, event: AgentEvent):
        tool = event.data.get("tool", "unknown")
        error = event.data.get("error", "unknown")
        self._add_event("✗", f"{tool} failed: {error[:50]}", "red")
        self._tool_active = ""

    async def _on_finding(self, event: AgentEvent):
        title = event.data.get("title", "Untitled")
        severity = event.data.get("severity", "unknown")
        sev_style = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan"}.get(severity, "white")
        self._add_event("🎯", f"FINDING: {title} ({severity})", sev_style)
        # Also print immediately for visibility
        console.print(f"\n  [bold green]🎯 FINDING:[/bold green] [{sev_style}]{title}[/{sev_style}] ({severity})\n")

    async def _on_finding_validated(self, event: AgentEvent):
        title = event.data.get("title", "Untitled")
        self._add_event("✓", f"Validated: {title}", "green")

    async def _on_evidence(self, event: AgentEvent):
        desc = event.data.get("description", "evidence")
        self._add_event("◆", f"Evidence: {desc[:50]}", "blue")

    async def _on_safety_block(self, event: AgentEvent):
        reason = event.data.get("reason", "unknown")
        self._add_event("⛔", f"SAFETY BLOCK: {reason}", "red")
        console.print(f"    [red]⛔ SAFETY BLOCK:[/red] {reason}")

    async def _on_hitl_request(self, event: AgentEvent):
        question = event.data.get("question", "Approval needed")
        self._add_event("⚠", f"HITL: {question}", "yellow")
        console.print(f"\n  [bold yellow]HITL:[/bold yellow] {question}")

    async def _on_budget_warning(self, event: AgentEvent):
        warnings = event.data.get("warnings", [])
        for w in warnings:
            self._add_event("⚠", f"Budget: {w}", "yellow")

    async def _on_budget_exceeded(self, event: AgentEvent):
        reason = event.data.get("reason", "unknown")
        self._add_event("⛔", f"BUDGET EXCEEDED: {reason}", "red")
        console.print(f"\n  [red]⛔ BUDGET EXCEEDED:[/red] {reason}\n")

    async def _on_llm_request(self, event: AgentEvent):
        model = event.data.get("model", "")
        self._add_event("→", f"LLM ({model})...", "dim")

    async def _on_llm_response(self, event: AgentEvent):
        latency = event.data.get("latency_ms", 0)
        tokens = event.data.get("tokens", 0)
        self._add_event("✓", f"LLM → {latency:.0f}ms {tokens}tok", "green")

    async def _on_llm_error(self, event: AgentEvent):
        error = event.data.get("error", "unknown")
        self._add_event("✗", f"LLM error: {error[:50]}", "red")

    async def _on_thinking(self, event: AgentEvent):
        cycle = event.data.get("cycle", 0)
        self._cycle = cycle
        self._last_thinking = f"Cycle {cycle}"
        self._add_event("◦", f"Cycle {cycle} — thinking...", "cyan")

    async def _on_error(self, event: AgentEvent):
        error = event.data.get("error", "unknown")
        self._add_event("✗", f"ERROR: {error}", "red")
        console.print(f"\n[red]ERROR:[/red] {error}\n")

    async def _on_warning(self, event: AgentEvent):
        message = event.data.get("message", "unknown")
        self._add_event("⚠", message, "yellow")

    # ── Display Methods (called outside Live context) ─────────

    def print_banner(self):
        """Print the agent banner."""
        banner = """
╔══════════════════════════════════════════════╗
║              DEMOGORGON                      ║
║     Interactive Security Research Agent      ║
╚══════════════════════════════════════════════╝"""
        console.print(banner, style="bold cyan")

    def print_help(self):
        """Print command help."""
        console.print(self.commands.commands.get("help", "No help available."))

    def render_status_line(self) -> str:
        """Render a single status line (for non-Live contexts)."""
        parts = []
        if self.strategy:
            s = self.strategy.state
            parts.append(f"[bold cyan]{s.strategy.value.upper()}[/bold cyan]")
            parts.append(f"({s.cycles_in_strategy}c)")
        if self.token_tracker:
            parts.append(self.token_tracker.live_display)
        if self.budget:
            parts.append(self.budget.get_usage_display())
        return " | ".join(parts)

    def render_findings_table(self) -> Panel:
        """Render current findings as a Rich panel."""
        findings = self.trace.get_by_type(TraceEntryType.FINDING, limit=10)
        if not findings:
            return Panel("[dim]No findings yet[/dim]", title="Findings", border_style="green")

        table = Table(show_header=True, border_style="green", expand=True)
        table.add_column("#", style="dim", width=3)
        table.add_column("Finding", style="bold")
        table.add_column("Severity", width=8)
        table.add_column("Endpoint")

        for i, f in enumerate(findings, 1):
            severity = f.data.get("severity", "unknown")
            sev_style = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan"}.get(severity, "")
            table.add_row(
                str(i),
                f.content[:60],
                f"[{sev_style}]{severity}[/{sev_style}]" if sev_style else severity,
                f.data.get("endpoint", "")[:30],
            )

        return Panel(table, title=f"Findings ({len(findings)})", border_style="green")

    def render_trace_panel(self, n: int = 8) -> Panel:
        """Render recent trace entries."""
        entries = self.trace.get_recent(n)
        if not entries:
            return Panel("[dim]No trace entries[/dim]", title="Recent Activity", border_style="blue")

        lines = []
        for e in entries:
            marker = {
                TraceEntryType.OBSERVATION: "[dim][OBS][/dim]",
                TraceEntryType.DECISION: "[cyan][DEC][/cyan]",
                TraceEntryType.ACTION: "[yellow][ACT][/yellow]",
                TraceEntryType.TOOL_CALL: "[magenta][TL][/magenta]",
                TraceEntryType.TOOL_RESULT: "[green][RES][/green]",
                TraceEntryType.EVIDENCE: "[blue][EVD][/blue]",
                TraceEntryType.FINDING: "[bold red][FND][/bold red]",
                TraceEntryType.ERROR: "[red][ERR][/red]",
                TraceEntryType.USER_INSTRUCTION: "[bold][USR][/bold]",
                TraceEntryType.SAFETY_BLOCK: "[red][SAF][/red]",
            }.get(e.type, "[dim][???][/dim]")
            lines.append(f"  {marker} {e.content[:70]}")

        return Panel("\n".join(lines), title="Recent Activity", border_style="blue")
