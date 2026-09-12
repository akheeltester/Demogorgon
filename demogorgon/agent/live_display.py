"""Live Display — Rich Live terminal display during research.

Provides real-time updates during the research loop:
- Current action and strategy
- Tool execution progress
- Findings as they're discovered
- Live token/cost ticker
- Budget status
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live

from .events import EventBus, EventType, AgentEvent
from .tokens import TokenTracker
from .budget import BudgetController
from .trace import ResearchTrace, TraceEntryType
from .strategies import StrategyEngine

console = Console()


class LiveDisplay:
    """Rich Live display for real-time agent monitoring.

    Usage:
        display = LiveDisplay(event_bus, token_tracker, budget, trace, strategy)
        await display.start()
        # ... agent runs ...
        await display.stop()
    """

    def __init__(
        self,
        event_bus: EventBus,
        token_tracker: TokenTracker,
        budget: BudgetController,
        trace: ResearchTrace,
        strategy: StrategyEngine,
    ):
        self.event_bus = event_bus
        self.token_tracker = token_tracker
        self.budget = budget
        self.trace = trace
        self.strategy = strategy

        self._live: Live | None = None
        self._running = False
        self._current_action = ""
        self._current_tool = ""
        self._last_finding = ""
        self._thinking = False
        self._cycle = 0
        self._start_time = 0.0

        # Register event handlers
        self._register_handlers()

    def _register_handlers(self):
        """Register event handlers for live updates."""
        self.event_bus.on(EventType.AGENT_THINKING, self._on_thinking)
        self.event_bus.on(EventType.DECISION_START, self._on_decision_start)
        self.event_bus.on(EventType.DECISION_COMPLETE, self._on_decision_complete)
        self.event_bus.on(EventType.TOOL_EXECUTE, self._on_tool_execute)
        self.event_bus.on(EventType.TOOL_RESULT, self._on_tool_result)
        self.event_bus.on(EventType.FINDING, self._on_finding)
        self.event_bus.on(EventType.PROGRESS_UPDATE, self._on_progress)

    async def start(self):
        """Start the live display."""
        self._running = True
        self._start_time = time.time()
        self._live = Live(
            self._build_layout(),
            console=console,
            refresh_per_second=2,
            screen=False,
        )
        self._live.start()

    async def stop(self):
        """Stop the live display."""
        self._running = False
        if self._live:
            self._live.stop()
            self._live = None

    def update(self):
        """Force a display update."""
        if self._live:
            self._live.update(self._build_layout())

    def _build_layout(self) -> Layout:
        """Build the live display layout."""
        layout = Layout()

        # Split into header, body, footer
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3),
        )

        # Header: strategy + cycle + tokens
        layout["header"].update(self._build_header())

        # Body: split into left (status) and right (findings)
        layout["body"].split_row(
            Layout(name="status", ratio=2),
            Layout(name="findings", ratio=1),
        )

        layout["status"].update(self._build_status_panel())
        layout["findings"].update(self._build_findings_panel())

        # Footer: budget
        layout["footer"].update(self._build_footer())

        return layout

    def _build_header(self) -> Panel:
        """Build the header panel."""
        strategy = self.strategy.state.strategy.value.upper()
        cycle = self.cycle
        tokens = self.token_tracker.live_display

        text = Text()
        text.append(f" DEMOGORGON ", style="bold cyan")
        text.append(" | ", style="dim")
        text.append(f"Strategy: {strategy}", style="bold")
        text.append(" | ", style="dim")
        text.append(f"Cycle: {cycle}", style="bold")
        text.append(" | ", style="dim")
        text.append(tokens, style="green")

        return Panel(text, style="cyan")

    def _build_status_panel(self) -> Panel:
        """Build the status panel."""
        lines = []

        # Current action
        if self._current_action:
            lines.append(f"[bold]Action:[/bold] {self._current_action}")

        # Current tool
        if self._current_tool:
            lines.append(f"[bold]Tool:[/bold] {self._current_tool}")

        # Thinking indicator
        if self._thinking:
            lines.append("[bold cyan]Thinking...[/bold cyan]")

        # Strategy info
        s = self.strategy.state
        lines.append(f"[dim]Strategy: {s.strategy.value} ({s.cycles_in_strategy} cycles)[/dim]")
        lines.append(f"[dim]Reason: {s.reason}[/dim]")

        # Last trace entries
        recent = self.trace.get_recent(5)
        if recent:
            lines.append("")
            lines.append("[bold]Recent:[/bold]")
            for entry in recent:
                marker = {
                    TraceEntryType.OBSERVATION: "[dim][OBS][/dim]",
                    TraceEntryType.DECISION: "[cyan][DEC][/cyan]",
                    TraceEntryType.ACTION: "[yellow][ACT][/yellow]",
                    TraceEntryType.TOOL_CALL: "[magenta][TL][/magenta]",
                    TraceEntryType.TOOL_RESULT: "[green][RES][/green]",
                    TraceEntryType.FINDING: "[bold red][FND][/bold red]",
                    TraceEntryType.ERROR: "[red][ERR][/red]",
                }.get(entry.type, "[dim][???][/dim]")
                lines.append(f"  {marker} {entry.content[:60]}")

        return Panel(
            "\n".join(lines) or "[dim]Waiting...[/dim]",
            title="Status",
            border_style="blue",
        )

    def _build_findings_panel(self) -> Panel:
        """Build the findings panel."""
        findings = self.trace.get_by_type(TraceEntryType.FINDING, limit=8)

        if not findings:
            return Panel(
                "[dim]No findings yet[/dim]",
                title="Findings",
                border_style="green",
            )

        table = Table(show_header=True, expand=True, box=None)
        table.add_column("#", style="dim", width=2)
        table.add_column("Finding", style="bold")
        table.add_column("Sev", width=5)

        for i, f in enumerate(findings, 1):
            severity = f.data.get("severity", "?")
            sev_style = {
                "critical": "bold red",
                "high": "red",
                "medium": "yellow",
                "low": "cyan",
            }.get(severity, "dim")

            table.add_row(
                str(i),
                f.content[:35],
                f"[{sev_style}]{severity[0].upper()}[/{sev_style}]",
            )

        return Panel(table, title=f"Findings ({len(findings)})", border_style="green")

    def _build_footer(self) -> Panel:
        """Build the footer panel with budget."""
        budget_display = self.budget.get_usage_display()
        duration = time.time() - self._start_time if self._start_time else 0

        text = Text()
        text.append(f" {budget_display} ", style="bold")
        text.append(" | ", style="dim")
        text.append(f"Duration: {duration:.0f}s", style="dim")

        return Panel(text, style="yellow")

    # Event handlers

    async def _on_thinking(self, event: AgentEvent):
        self._thinking = True
        self._cycle = event.data.get("cycle", self._cycle)
        self.update()

    async def _on_decision_start(self, event: AgentEvent):
        self._thinking = False
        self._current_action = event.data.get("action", "")
        self.update()

    async def _on_decision_complete(self, event: AgentEvent):
        self._thinking = False
        self.update()

    async def _on_tool_execute(self, event: AgentEvent):
        self._current_tool = event.data.get("tool", "")
        self._current_action = event.data.get("action", "")
        self.update()

    async def _on_tool_result(self, event: AgentEvent):
        self._current_tool = ""
        self.update()

    async def _on_finding(self, event: AgentEvent):
        self._last_finding = event.data.get("title", "")
        self.update()

    async def _on_progress(self, event: AgentEvent):
        self._cycle = event.data.get("cycle", self._cycle)
        self.update()
