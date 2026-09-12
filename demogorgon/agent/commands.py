"""Command Processor — user commands in the agent terminal.

Processes /-prefixed commands typed by the user in the agent terminal.
Commands control the agent without breaking the autonomous loop.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class CommandType(Enum):
    """Agent command types."""
    HELP = "help"
    STATUS = "status"
    FINDINGS = "findings"
    PAUSE = "pause"
    RESUME = "resume"
    STOP = "stop"
    STRATEGY = "strategy"
    BUDGET = "budget"
    TRACE = "trace"
    REPORT = "report"
    CHAINS = "chains"
    EVIDENCE = "evidence"
    TARGETS = "targets"
    FOCUS = "focus"
    HISTORY = "history"
    COST = "cost"
    TIMEOUT = "timeout"
    LOG = "log"
    SKIP = "skip"
    OVERRIDE = "override"
    EXPLORE = "explore"
    VALIDATE = "validate"
    EXPLOIT = "exploit"
    CHAIN = "chain"
    QUIT = "quit"


@dataclass
class CommandResult:
    """Result of processing a command."""
    success: bool
    message: str
    data: dict[str, Any] | None = None
    action: str = ""  # what the agent should do next: "continue", "pause", "stop", "resume"

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "message": self.message,
            "data": self.data,
            "action": self.action,
        }


COMMAND_HELP = """
╔══════════════════════════════════════════════════════════════╗
║                    DEMOGORGON COMMANDS                       ║
╠══════════════════════════════════════════════════════════════╣
║ /help          Show this help message                        ║
║ /status        Show agent status and stats                   ║
║ /findings      List current findings                         ║
║ /chains        List attack chains                            ║
║ /evidence      Show evidence collected                       ║
║ /targets       Show discovered targets                       ║
║ /pause         Pause the agent loop                          ║
║ /resume        Resume the agent loop                         ║
║ /stop          Stop the agent completely                     ║
║ /strategy <s>  Force strategy (recon|explore|focused|        ║
║                validate|exploit|chain)                       ║
║ /focus <class> Focus on a specific vuln class                ║
║ /budget        Show budget usage                             ║
║ /cost          Show token/cost breakdown                     ║
║ /trace         Show recent decision trace                    ║
║ /history       Show full command history                     ║
║ /report        Generate findings report                      ║
║ /skip          Skip current action                           ║
║ /override      Override safety (requires auth)               ║
║ /log [n]       Show last N log entries                       ║
║ /quit          Exit the agent                                ║
╚══════════════════════════════════════════════════════════════╝
"""


class CommandProcessor:
    """Processes user commands in the agent terminal.

    Usage:
        processor = CommandProcessor()
        result = await processor.process("/status", agent_state)
        print(result.message)
    """

    def __init__(self):
        self._history: list[tuple[str, CommandResult, float]] = []
        self._pending_instruction: str | None = None

    async def process(self, command_str: str, state: dict[str, Any]) -> CommandResult:
        """Process a command string.

        state should contain:
            - session: AgentSession
            - budget: BudgetController
            - trace: ResearchTrace
            - strategy: StrategyEngine
            - token_tracker: TokenTracker
        """
        command_str = command_str.strip()
        if not command_str.startswith("/"):
            # Treat as natural language instruction
            return await self._handle_instruction(command_str, state)

        parts = command_str.split(maxsplit=1)
        cmd = parts[0].lower().lstrip("/")
        args = parts[1] if len(parts) > 1 else ""

        # Map command to handler
        handlers = {
            "help": self._cmd_help,
            "status": self._cmd_status,
            "findings": self._cmd_findings,
            "chains": self._cmd_chains,
            "evidence": self._cmd_evidence,
            "targets": self._cmd_targets,
            "pause": self._cmd_pause,
            "resume": self._cmd_resume,
            "stop": self._cmd_stop,
            "strategy": self._cmd_strategy,
            "focus": self._cmd_focus,
            "budget": self._cmd_budget,
            "cost": self._cmd_cost,
            "trace": self._cmd_trace,
            "history": self._cmd_history,
            "report": self._cmd_report,
            "skip": self._cmd_skip,
            "override": self._cmd_override,
            "log": self._cmd_log,
            "quit": self._cmd_quit,
            # Strategy shortcuts
            "explore": lambda a, s: self._cmd_strategy("explore", s),
            "validate": lambda a, s: self._cmd_strategy("validate", s),
            "exploit": lambda a, s: self._cmd_strategy("exploit", s),
            "chain": lambda a, s: self._cmd_strategy("chain", s),
        }

        handler = handlers.get(cmd)
        if handler:
            result = await handler(args, state)
        else:
            result = CommandResult(
                success=False,
                message=f"Unknown command: /{cmd}. Type /help for available commands.",
            )

        # Record in history
        self._history.append((command_str, result, time.time()))

        return result

    async def _handle_instruction(self, text: str, state: dict[str, Any]) -> CommandResult:
        """Handle a natural language instruction from the user."""
        self._pending_instruction = text
        return CommandResult(
            success=True,
            message=f"Instruction received: \"{text}\"",
            data={"instruction": text},
            action="continue",
        )

    def get_pending_instruction(self) -> str | None:
        """Get and clear any pending user instruction."""
        inst = self._pending_instruction
        self._pending_instruction = None
        return inst

    async def _cmd_help(self, args: str, state: dict[str, Any]) -> CommandResult:
        return CommandResult(success=True, message=COMMAND_HELP)

    async def _cmd_status(self, args: str, state: dict[str, Any]) -> CommandResult:
        session = state.get("session")
        budget = state.get("budget")
        strategy = state.get("strategy")
        tokens = state.get("token_tracker")

        lines = ["Agent Status:"]
        if session:
            lines.append(f"  Target: {session.target or 'Not set'}")
            lines.append(f"  Running: {session.is_running}")
            lines.append(f"  Paused: {session.is_paused}")
        if strategy:
            s = strategy.state
            lines.append(f"  Strategy: {s.strategy.value} ({s.cycles_in_strategy} cycles)")
            lines.append(f"  Reason: {s.reason}")
        if budget:
            lines.append(f"  Budget: {budget.get_usage_display()}")
        if tokens:
            lines.append(f"  {tokens.live_display}")

        return CommandResult(success=True, message="\n".join(lines))

    async def _cmd_findings(self, args: str, state: dict[str, Any]) -> CommandResult:
        trace = state.get("trace")
        if not trace:
            return CommandResult(success=True, message="No trace available.")

        from .trace import TraceEntryType
        findings = trace.get_by_type(TraceEntryType.FINDING, limit=20)
        if not findings:
            return CommandResult(success=True, message="No findings yet.")

        lines = [f"Findings ({len(findings)}):"]
        for i, f in enumerate(findings, 1):
            lines.append(f"  {i}. {f.content[:80]}")
            if f.data.get("severity"):
                lines.append(f"     Severity: {f.data['severity']}")
            if f.data.get("endpoint"):
                lines.append(f"     Endpoint: {f.data['endpoint']}")

        return CommandResult(success=True, message="\n".join(lines))

    async def _cmd_chains(self, args: str, state: dict[str, Any]) -> CommandResult:
        session = state.get("session")
        if not session:
            return CommandResult(success=True, message="No session active.")

        chains = state.get("chains", [])
        if not chains:
            return CommandResult(success=True, message="No attack chains found.")

        lines = [f"Attack Chains ({len(chains)}):"]
        for i, chain in enumerate(chains, 1):
            if isinstance(chain, dict):
                lines.append(f"  {i}. {chain.get('name', 'Unnamed')}")
            else:
                lines.append(f"  {i}. {str(chain)[:80]}")

        return CommandResult(success=True, message="\n".join(lines))

    async def _cmd_evidence(self, args: str, state: dict[str, Any]) -> CommandResult:
        trace = state.get("trace")
        if not trace:
            return CommandResult(success=True, message="No trace available.")

        from .trace import TraceEntryType
        evidence = trace.get_by_type(TraceEntryType.EVIDENCE, limit=10)
        if not evidence:
            return CommandResult(success=True, message="No evidence collected yet.")

        lines = [f"Evidence ({len(evidence)}):"]
        for i, e in enumerate(evidence, 1):
            lines.append(f"  {i}. {e.content[:100]}")

        return CommandResult(success=True, message="\n".join(lines))

    async def _cmd_targets(self, args: str, state: dict[str, Any]) -> CommandResult:
        session = state.get("session")
        if not session:
            return CommandResult(success=True, message="No session active.")

        return CommandResult(
            success=True,
            message=f"Target: {session.target}\nScope: {len(session.scope_assets)} assets",
        )

    async def _cmd_pause(self, args: str, state: dict[str, Any]) -> CommandResult:
        session = state.get("session")
        if session:
            session.is_paused = True
        return CommandResult(
            success=True,
            message="Agent paused. Type /resume to continue.",
            action="pause",
        )

    async def _cmd_resume(self, args: str, state: dict[str, Any]) -> CommandResult:
        session = state.get("session")
        if session:
            session.is_paused = False
        return CommandResult(
            success=True,
            message="Agent resuming...",
            action="resume",
        )

    async def _cmd_stop(self, args: str, state: dict[str, Any]) -> CommandResult:
        session = state.get("session")
        if session:
            session.is_running = False
            session.is_paused = False
        return CommandResult(
            success=True,
            message="Agent stopping...",
            action="stop",
        )

    async def _cmd_strategy(self, args: str, state: dict[str, Any]) -> CommandResult:
        strategy = state.get("strategy")
        if not strategy:
            return CommandResult(success=False, message="No strategy engine available.")

        from .strategies import AgentStrategy
        try:
            new_strategy = AgentStrategy(args.strip())
        except ValueError:
            valid = [s.value for s in AgentStrategy]
            return CommandResult(
                success=False,
                message=f"Invalid strategy: {args}. Valid: {', '.join(valid)}",
            )

        strategy.force_strategy(new_strategy, reason="User override")
        return CommandResult(
            success=True,
            message=f"Strategy changed to: {new_strategy.value}",
        )

    async def _cmd_focus(self, args: str, state: dict[str, Any]) -> CommandResult:
        if not args.strip():
            return CommandResult(
                success=False,
                message="Usage: /focus <vuln_class> (e.g., /focus idor, /focus xss)",
            )

        vuln_class = args.strip().lower()
        trace = state.get("trace")
        if trace:
            from .trace import TraceEntryType
            trace.add(
                TraceEntryType.USER_INSTRUCTION,
                f"Focus on vulnerability class: {vuln_class}",
            )

        return CommandResult(
            success=True,
            message=f"Focusing on vulnerability class: {vuln_class}",
            data={"focus_vuln_class": vuln_class},
        )

    async def _cmd_budget(self, args: str, state: dict[str, Any]) -> CommandResult:
        budget = state.get("budget")
        if not budget:
            return CommandResult(success=True, message="No budget controller available.")

        status = budget.check()
        lines = ["Budget Status:"]
        lines.append(f"  {budget.get_usage_display()}")

        if status.warnings:
            lines.append("\nWarnings:")
            for w in status.warnings:
                lines.append(f"  ⚠ {w}")

        if status.exceeded:
            lines.append("\nExceeded:")
            for e in status.exceeded:
                lines.append(f"  ✗ {e}")

        return CommandResult(success=True, message="\n".join(lines))

    async def _cmd_cost(self, args: str, state: dict[str, Any]) -> CommandResult:
        tokens = state.get("token_tracker")
        if not tokens:
            return CommandResult(success=True, message="No token tracker available.")

        by_provider = tokens.get_by_provider()
        lines = [tokens.totals_display]

        if by_provider:
            lines.append("\nBy Provider:")
            for provider, stats in by_provider.items():
                lines.append(
                    f"  {provider}: {stats['calls']} calls, "
                    f"{stats['tokens']:,} tokens, ${stats['cost']:.4f}"
                )

        return CommandResult(success=True, message="\n".join(lines))

    async def _cmd_trace(self, args: str, state: dict[str, Any]) -> CommandResult:
        trace = state.get("trace")
        if not trace:
            return CommandResult(success=True, message="No trace available.")

        n = 15
        if args.strip().isdigit():
            n = int(args.strip())

        summary = trace.get_llm_summary(max_entries=n)
        return CommandResult(
            success=True,
            message=f"Recent Trace ({len(trace)} total):\n{summary}",
        )

    async def _cmd_history(self, args: str, state: dict[str, Any]) -> CommandResult:
        if not self._history:
            return CommandResult(success=True, message="No command history.")

        lines = ["Command History:"]
        for cmd, result, ts in self._history[-20:]:
            time_str = time.strftime("%H:%M:%S", time.localtime(ts))
            status = "✓" if result.success else "✗"
            lines.append(f"  {time_str} {status} {cmd}")

        return CommandResult(success=True, message="\n".join(lines))

    async def _cmd_report(self, args: str, state: dict[str, Any]) -> CommandResult:
        return CommandResult(
            success=True,
            message="Generating report...",
            action="continue",
            data={"generate_report": True},
        )

    async def _cmd_skip(self, args: str, state: dict[str, Any]) -> CommandResult:
        return CommandResult(
            success=True,
            message="Skipping current action.",
            action="skip",
        )

    async def _cmd_override(self, args: str, state: dict[str, Any]) -> CommandResult:
        return CommandResult(
            success=False,
            message="Safety override requires explicit authorization. Use /override --confirm.",
        )

    async def _cmd_log(self, args: str, state: dict[str, Any]) -> CommandResult:
        n = 10
        if args.strip().isdigit():
            n = int(args.strip())

        trace = state.get("trace")
        if trace:
            entries = trace.get_recent(n)
            lines = [f"Last {len(entries)} entries:"]
            for e in entries:
                ts = time.strftime("%H:%M:%S", time.localtime(e.timestamp))
                lines.append(f"  {ts} [{e.type.value}] {e.content[:80]}")
            return CommandResult(success=True, message="\n".join(lines))

        return CommandResult(success=True, message="No log entries.")

    async def _cmd_quit(self, args: str, state: dict[str, Any]) -> CommandResult:
        session = state.get("session")
        if session:
            session.is_running = False
            session.is_paused = False
        return CommandResult(
            success=True,
            message="Quitting agent...",
            action="stop",
        )

    def get_history(self) -> list[tuple[str, CommandResult, float]]:
        return list(self._history)
