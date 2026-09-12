"""Terminal UI — live agent display with Rich.

Decoupled UI that subscribes to the EventBus and renders the agent's
state in real time. Shows:
- Current strategy and reasoning
- Tool execution results
- Findings as they're discovered
- Live token/cost ticker
- Command input prompt
"""

from __future__ import annotations

import asyncio
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

from .events import EventBus, EventType, AgentEvent
from .tokens import TokenTracker
from .budget import BudgetController
from .trace import ResearchTrace, TraceEntryType
from .strategies import StrategyEngine
from .commands import CommandProcessor

console = Console()


class TerminalUI:
    """Live terminal UI for the agent session.

    Subscribes to EventBus events and renders them in real time.
    Uses Rich Live for in-place updates when possible.
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
        self._input_task = None
        self._event_task = None

        # Live status state
        self._last_status_line = ""
        self._last_phase = ""
        self._event_count = 0
        self._tool_active = ""

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

    async def start(self):
        """Start the UI (event listener)."""
        self._running = True
        self._event_task = asyncio.create_task(self._event_loop())

    async def stop(self):
        """Stop the UI."""
        self._running = False
        if self._event_task:
            self._event_task.cancel()

    async def _event_loop(self):
        """Main event loop — periodic status refresh."""
        while self._running:
            await asyncio.sleep(2.0)
            # Periodic status line update
            if self.session and self.session.is_running and not self.session.is_paused:
                status = self.render_status_line()
                if status != self._last_status_line:
                    self._last_status_line = status

    def render_status_line(self) -> str:
        """Render a single status line for the terminal."""
        parts = []

        # Strategy
        if self.strategy:
            s = self.strategy.state
            parts.append(f"[bold cyan]{s.strategy.value.upper()}[/bold cyan]")
            parts.append(f"({s.cycles_in_strategy}c)")

        # Tokens
        if self.token_tracker:
            parts.append(self.token_tracker.live_display)

        # Budget
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
            sev_style = {
                "critical": "bold red",
                "high": "red",
                "medium": "yellow",
                "low": "cyan",
            }.get(severity, "")

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

    def render_session_header(self) -> Panel:
        """Render the session header panel."""
        if not self.session:
            return Panel("[dim]No session[/dim]", border_style="cyan")

        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Key", style="bold")
        table.add_column("Value")

        strategy = self.strategy.state.strategy.value.upper() if self.strategy else "?"
        status = "RUNNING" if self.session.is_running and not self.session.is_paused else "PAUSED" if self.session.is_paused else "STOPPED"

        table.add_row("Target", self.session.target or "—")
        table.add_row("Model", f"{self.session.config.provider}/{self.session.config.model}")
        table.add_row("Phase", strategy)
        table.add_row("Status", status)

        return Panel(table, title="DEMOGOORGON", border_style="cyan", subtitle=self.render_status_line())

    # Event handlers

    async def _on_session_start(self, event: AgentEvent):
        target = event.data.get("target", "unknown")
        console.print(f"\n[bold green]Agent started[/bold green] — Target: {target}\n")

    async def _on_session_end(self, event: AgentEvent):
        reason = event.data.get("reason", "unknown")
        console.print(f"\n[bold yellow]Agent stopped[/bold yellow] — Reason: {reason}\n")

    async def _on_status_change(self, event: AgentEvent):
        status = event.data.get("status", "unknown")
        console.print(f"[dim]Status: {status}[/dim]")

    async def _on_progress(self, event: AgentEvent):
        cycle = event.data.get("cycle", 0)
        strategy = event.data.get("strategy", "unknown")
        findings = event.data.get("findings", 0)
        tokens = event.data.get("tokens", "")

        # Single-line progress update
        console.print(
            f"  [dim]Cycle {cycle}[/dim] | "
            f"[cyan]{strategy}[/cyan] | "
            f"Findings: {findings} | "
            f"{tokens}"
        )

    async def _on_strategy_change(self, event: AgentEvent):
        old = event.data.get("from", "unknown")
        new = event.data.get("to", "unknown")
        reason = event.data.get("reason", "")
        console.print(f"  [bold cyan]Strategy: {old} → {new}[/bold cyan] ({reason})")

    async def _on_decision_start(self, event: AgentEvent):
        console.print("  [dim]Deciding next action...[/dim]", end="")

    async def _on_decision_complete(self, event: AgentEvent):
        action = event.data.get("action", "")
        target = event.data.get("target", "")
        if action:
            console.print(f" → [bold]{action}[/bold] {target[:50]}")

    async def _on_tool_execute(self, event: AgentEvent):
        tool = event.data.get("tool", "unknown")
        target = event.data.get("target", "")
        self._tool_active = tool
        console.print(f"    [magenta]▶ {tool}[/magenta] {target[:60]}")

    async def _on_tool_result(self, event: AgentEvent):
        tool = event.data.get("tool", "unknown")
        success = event.data.get("success", False)
        icon = "[green]✓[/green]" if success else "[red]✗[/red]"
        console.print(f"    {icon} {tool} complete")
        self._tool_active = ""

    async def _on_tool_error(self, event: AgentEvent):
        tool = event.data.get("tool", "unknown")
        error = event.data.get("error", "unknown")
        console.print(f"    [red]✗ {tool} failed: {error[:60]}[/red]")
        self._tool_active = ""

    async def _on_finding(self, event: AgentEvent):
        title = event.data.get("title", "Untitled")
        severity = event.data.get("severity", "unknown")
        sev_style = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "cyan",
        }.get(severity, "")
        style = f"[{sev_style}]" if sev_style else ""
        close = f"[/{sev_style}]" if sev_style else ""
        console.print(f"\n  [bold green]🎯 FINDING:[/bold green] {style}{title}{close} ({severity})\n")

    async def _on_finding_validated(self, event: AgentEvent):
        title = event.data.get("title", "Untitled")
        console.print(f"  [green]✓ Validated:[/green] {title}")

    async def _on_evidence(self, event: AgentEvent):
        desc = event.data.get("description", "evidence")
        console.print(f"    [blue]Evidence:[/blue] {desc[:60]}")

    async def _on_safety_block(self, event: AgentEvent):
        reason = event.data.get("reason", "unknown")
        console.print(f"    [red]⛔ SAFETY BLOCK:[/red] {reason}")

    async def _on_hitl_request(self, event: AgentEvent):
        question = event.data.get("question", "Approval needed")
        console.print(f"\n  [bold yellow]HITL:[/bold yellow] {question}")

    async def _on_budget_warning(self, event: AgentEvent):
        warnings = event.data.get("warnings", [])
        for w in warnings:
            console.print(f"  [yellow]⚠ Budget: {w}[/yellow]")

    async def _on_budget_exceeded(self, event: AgentEvent):
        reason = event.data.get("reason", "unknown")
        console.print(f"\n  [red]⛔ BUDGET EXCEEDED:[/red] {reason}\n")

    async def _on_llm_request(self, event: AgentEvent):
        model = event.data.get("model", "")
        console.print(f"  [dim]→ LLM ({model})...[/dim]", end="")

    async def _on_llm_response(self, event: AgentEvent):
        latency = event.data.get("latency_ms", 0)
        tokens = event.data.get("tokens", 0)
        console.print(f" [green]✓[/green] {latency:.0f}ms {tokens}tok")

    async def _on_llm_error(self, event: AgentEvent):
        error = event.data.get("error", "unknown")
        console.print(f" [red]✗ {error[:60]}[/red]")

    async def _on_thinking(self, event: AgentEvent):
        cycle = event.data.get("cycle", 0)
        console.print(f"\n[bold cyan]Cycle {cycle}[/bold cyan] — Thinking...", end="")

    async def _on_error(self, event: AgentEvent):
        error = event.data.get("error", "unknown")
        console.print(f"\n[red]ERROR:[/red] {error}\n")

    async def _on_warning(self, event: AgentEvent):
        message = event.data.get("message", "unknown")
        console.print(f"  [yellow]⚠ {message}[/yellow]")

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
